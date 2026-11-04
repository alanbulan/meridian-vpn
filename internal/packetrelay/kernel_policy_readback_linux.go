//go:build linux

package packetrelay

import (
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// KernelPolicyRecord retains the complete fixed header and attributes of one
// address, route or policy-rule message. Unknown attributes are preserved, not
// approved. Consumers must interpret or reject them before making policy claims.
// Data excludes the netlink envelope and is owned by the returned observation.
type KernelPolicyRecord struct {
	Type uint16
	Data []byte
}

// KernelPolicyObservation is a sequential read of IPv4/IPv6 addresses, routes
// (all tables) and routing rules in one independently identified namespace.
// It is NOT an atomic snapshot, DNS/firewall/dispatcher inspection, ownership,
// readiness or absence proof. Kernel dump interruption and partial data fail.
type KernelPolicyObservation struct {
	Namespace KernelNamespaceIdentity
	Records   []KernelPolicyRecord
}

// ObserveKernelPolicy performs only fixed RTM_GETADDR/GETROUTE/GETRULE dumps.
// expected must come from independent namespace provenance; this function does
// not discover the host namespace or confer authority on caller-supplied IDs.
// It never enters a namespace, changes networking or runs a command. Socket polling uses a two-second deadline; in-flight namespace inspection
// syscalls are not interruptible. Received data is capped at 1 MiB and 4096
// records (plus a fixed 64 KiB receive buffer and bounded parser temporaries). No normal
// application path invokes this API until host authority is implemented.
func ObserveKernelPolicy(ctx context.Context, expected KernelNamespaceIdentity) (KernelPolicyObservation, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return observeKernelPolicyWith(ctx, expected, realKernelLinkOps())
}

type kernelDumpSpec struct {
	kind   uint16
	family byte
}

func observeKernelPolicyWith(ctx context.Context, expected KernelNamespaceIdentity, ops kernelLinkOps) (KernelPolicyObservation, error) {
	var specs []kernelDumpSpec
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		for _, kind := range []uint16{unix.RTM_GETADDR, unix.RTM_GETROUTE, unix.RTM_GETRULE} {
			specs = append(specs, kernelDumpSpec{kind, family})
		}
	}
	return observeKernelRecordsWith(ctx, expected, ops, specs)
}

// Shared bounded transport accepts only these read-only request shapes.
func observeKernelRecordsWith(ctx context.Context, expected KernelNamespaceIdentity, ops kernelLinkOps, specs []kernelDumpSpec) (out KernelPolicyObservation, resultErr error) {
	if len(specs) == 0 || len(specs) > 6 {
		return out, errTUNKernelObservation
	}
	for _, spec := range specs {
		if spec.kind == unix.RTM_GETLINK {
			if spec.family != unix.AF_UNSPEC {
				return out, errTUNKernelObservation
			}
		} else if (spec.kind != unix.RTM_GETADDR && spec.kind != unix.RTM_GETROUTE && spec.kind != unix.RTM_GETRULE) || (spec.family != unix.AF_INET && spec.family != unix.AF_INET6) {
			return out, errTUNKernelObservation
		}
	}
	var closers []func() error
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			if err := closers[i](); err != nil {
				resultErr = errors.Join(resultErr, ErrCleanup, err)
			}
		}
		if resultErr != nil {
			out = KernelPolicyObservation{}
		}
	}()
	if ctx == nil || expected.Inode == 0 {
		return out, errTUNKernelObservation
	}
	deadline := ops.now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !ops.now().Before(deadline) {
			return context.DeadlineExceeded
		}
		return nil
	}
	observeNS := func() error {
		if err := check(); err != nil {
			return err
		}
		id, closeNS, err := ops.namespace()
		if closeNS != nil {
			closers = append(closers, closeNS)
		}
		if err != nil || id != expected {
			return errors.Join(errTUNKernelObservation, err)
		}
		return check()
	}
	if err := observeNS(); err != nil {
		return out, err
	}
	fd, err := ops.socket()
	if err != nil {
		return out, err
	}
	closers = append(closers, func() error { return ops.close(fd) })
	if err = observeNS(); err != nil {
		return out, err
	}
	if err = ops.bind(fd); err != nil {
		return out, err
	}
	port, err := ops.port(fd)
	if err != nil || port == 0 {
		return out, errors.Join(errTUNKernelObservation, err)
	}
	wait := func(events int16) error {
		if err := check(); err != nil {
			return err
		}
		revents, err := ops.poll(fd, events, 10)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if revents & ^events != 0 {
			return errTUNKernelObservation
		}
		return check()
	}
	buf := make([]byte, 65536)
	total := 0
	seq := uint32(0)
	for _, spec := range specs {
		kind, family := spec.kind, spec.family
		seq++
		request := kernelPolicyRequest(kind, family, seq, port)
		for {
			if err = check(); err != nil {
				return out, err
			}
			err = ops.send(fd, request)
			if err == nil {
				break
			}
			if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
				return out, err
			}
			if err = wait(unix.POLLOUT); err != nil {
				return out, err
			}
		}
		for {
			if err = check(); err != nil {
				return out, err
			}
			n, flags, from, e := ops.recv(fd, buf)
			if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EINTR) {
				if err = wait(unix.POLLIN); err != nil {
					return out, err
				}
				continue
			}
			if e != nil {
				return out, e
			}
			source, ok := from.(*unix.SockaddrNetlink)
			if !ok || source.Family != unix.AF_NETLINK || source.Pid != 0 || source.Groups != 0 || flags != 0 || n <= 0 || n > len(buf) {
				return out, errTUNKernelObservation
			}
			total += n
			if total > 1<<20 {
				return out, errTUNKernelObservation
			}
			records, done, e := parseKernelPolicyReply(buf[:n], kind, family, seq, port)
			if e != nil || len(out.Records)+len(records) > 4096 {
				return out, errors.Join(errTUNKernelObservation, e)
			}
			out.Records = append(out.Records, records...)
			if done {
				break
			}
		}
	}
	if err = observeNS(); err != nil {
		return out, err
	}
	out.Namespace = expected
	return out, check()
}

func kernelPolicyRequest(kind uint16, family byte, seq, port uint32) []byte {
	size := 12
	if kind == unix.RTM_GETADDR {
		size = 8
	} else if kind == unix.RTM_GETLINK {
		size = 16
	}
	b := make([]byte, 16+size)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], kind)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(b[8:], seq)
	binary.NativeEndian.PutUint32(b[12:], port)
	b[16] = family
	return b
}

func parseKernelPolicyReply(b []byte, request uint16, family byte, seq, port uint32) ([]KernelPolicyRecord, bool, error) {
	var records []KernelPolicyRecord
	done := false
	size := 12
	if request == unix.RTM_GETADDR {
		size = 8
	} else if request == unix.RTM_GETLINK {
		size = 16
	}
	if request != unix.RTM_GETADDR && request != unix.RTM_GETROUTE && request != unix.RTM_GETRULE && request != unix.RTM_GETLINK {
		return nil, false, errTUNKernelObservation
	}
	for len(b) > 0 {
		if done || len(b) < 16 {
			return nil, false, errTUNKernelObservation
		}
		n := int(binary.NativeEndian.Uint32(b))
		if n < 16 || n > len(b) || kernelAlign(n) > len(b) {
			return nil, false, errTUNKernelObservation
		}
		kind, flags := binary.NativeEndian.Uint16(b[4:]), binary.NativeEndian.Uint16(b[6:])
		if binary.NativeEndian.Uint32(b[8:]) != seq || binary.NativeEndian.Uint32(b[12:]) != port || flags != unix.NLM_F_MULTI {
			return nil, false, errTUNKernelObservation
		}
		data := b[16:n]
		if kind == unix.NLMSG_DONE {
			if len(data) != 4 || binary.NativeEndian.Uint32(data) != 0 {
				return nil, false, errTUNKernelObservation
			}
			done = true
		} else {
			if kind != request-2 || len(data) < size || data[0] != family {
				return nil, false, errTUNKernelObservation
			}
			if _, err := kernelAttributes(data[size:], 0); err != nil {
				return nil, false, err
			}
			records = append(records, KernelPolicyRecord{Type: kind, Data: append([]byte(nil), data...)})
		}
		b = b[kernelAlign(n):]
	}
	return records, done, nil
}
