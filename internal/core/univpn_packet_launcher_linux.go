//go:build linux

package core

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"mygo-vpn/internal/packetrelay"
)

// UniVPNPacketProvider is a trusted deployment dependency, not caller input.
// AcquirePacket transfers exclusive ownership of both returned endpoints even on
// error. Native must be one end of an unnamed connected nonblocking AF_UNIX
// SOCK_SEQPACKET pair; original must be CLOEXEC. Relay owns the exact opposite
// endpoint of that same pair, never a host TUN. The unnamed address check cannot
// prove pairing; the trusted provider must guarantee this association. The relay
// descriptor and every other retained broker descriptor MUST also be CLOEXEC;
// an opaque PacketIO cannot be inspected here. A concrete provider must enforce
// this prerequisite so only the four explicitly assigned descriptors are inherited.
// Provider must
// retain no copies or active users. Unreturned resources must be cleaned before
// returning; uncertain cleanup must return CleanupError. It must honor ctx.
// No host TUN descriptor may ever be returned as native or inherited by the child.
type UniVPNPacketProvider interface {
	AcquirePacket(context.Context, string) (native *os.File, relay packetrelay.PacketIO, err error)
}

type uniVPNPacketNative struct {
	file  *os.File
	owner packetrelay.PacketIO
}
type uniVPNPacketDuplicate func(*os.File) (uniVPNPacketNative, error)

// Duplicate before inspect, under RawConn lifetime protection. No socket is
// created or connected and no descriptor configuration is changed here.
func duplicateUniVPNPacket(f *os.File) (uniVPNPacketNative, error) {
	if f == nil {
		return uniVPNPacketNative{}, errors.New("missing native packet endpoint")
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return uniVPNPacketNative{}, err
	}
	fd := -1
	var opErr error
	err = raw.Control(func(original uintptr) {
		flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, original, syscall.F_GETFD, 0)
		if e != 0 {
			opErr = e
			return
		}
		if flags&syscall.FD_CLOEXEC == 0 {
			opErr = errors.New("original packet endpoint must be CLOEXEC")
			return
		}
		n, _, e := syscall.Syscall(syscall.SYS_FCNTL, original, syscall.F_DUPFD_CLOEXEC, 3)
		if e != 0 {
			opErr = e
		} else {
			fd = int(n)
		}
	})
	if err = errors.Join(err, opErr); err != nil {
		if fd >= 0 {
			if syscall.Close(fd) != nil {
				err = errors.Join(err, &CleanupError{})
			}
		}
		return uniVPNPacketNative{}, err
	}
	dup := os.NewFile(uintptr(fd), "meridian-native-packet")
	owner, err := packetrelay.NewDatagramPackets(dup)
	if err != nil {
		if dup.Close() != nil {
			err = errors.Join(err, &CleanupError{})
		}
		return uniVPNPacketNative{}, err
	}
	return uniVPNPacketNative{dup, owner}, nil
}

func closeUniVPNPacket(endpoint packetrelay.PacketIO) error {
	if nilInterface(endpoint) {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- endpoint.Close() }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return &CleanupError{}
		}
		return nil
	case <-timer.C:
		return &CleanupError{}
	}
}

func acquireUniVPNPacket(ctx context.Context, provider UniVPNPacketProvider, sessionID string, duplicate uniVPNPacketDuplicate) (native uniVPNPacketNative, relay packetrelay.PacketIO, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	original, relay, err := provider.AcquirePacket(ctx, sessionID)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		if original == nil || nilInterface(relay) {
			err = errors.New("two owned packet endpoints required")
		} else {
			native, err = duplicate(original)
		}
	}
	if original != nil {
		if original.Close() != nil {
			err = errors.Join(err, &CleanupError{})
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && (native.file == nil || nilInterface(native.owner)) {
		err = errors.New("invalid native packet duplicate")
	}
	if err != nil {
		err = errors.Join(err, closeUniVPNPacket(native.owner), closeUniVPNPacket(relay))
		return uniVPNPacketNative{}, nil, err
	}
	return
}

func wireUniVPNPacket(cmd *exec.Cmd, native *os.File) error {
	if native == nil || len(cmd.ExtraFiles) != 3 || len(cmd.Args) < 3 || cmd.Args[len(cmd.Args)-2] != "--" {
		return errors.New("packet channel requires session and TCP descriptors")
	}
	nativeFD, err := uniVPNPacketDescriptor(native)
	if err != nil {
		return err
	}
	seen := map[uintptr]bool{nativeFD: true}
	for _, f := range cmd.ExtraFiles {
		fd, err := uniVPNPacketDescriptor(f)
		if err != nil || seen[fd] {
			return errors.New("packet descriptor collision or unavailable")
		}
		seen[fd] = true
	}
	required := map[string]int{"--meridian-session-fd=3": 0, "--meridian-control-fd=4": 0, "--meridian-data-fd=5": 0}
	for _, a := range cmd.Args[:len(cmd.Args)-2] {
		if _, ok := required[a]; ok {
			required[a]++
		}
		if strings.HasPrefix(a, "--meridian-packet-fd=") {
			return errors.New("packet descriptor already supplied")
		}
	}
	for _, count := range required {
		if count != 1 {
			return errors.New("missing fixed descriptor argument")
		}
	}
	n := len(cmd.Args) - 2
	args := append([]string(nil), cmd.Args[:n]...)
	args = append(args, "--meridian-packet-fd=6")
	cmd.Args = append(args, cmd.Args[n:]...)
	cmd.ExtraFiles = append(cmd.ExtraFiles, native)
	return nil
}

func closeUniVPNPacketLaunch(native uniVPNPacketNative, relay packetrelay.PacketIO, p *uniVPNExecProcess, stop func() error, launchErr error) error {
	closeErr := closeUniVPNPacket(native.owner)
	if p == nil {
		return errors.Join(launchErr, closeErr, closeUniVPNPacket(relay))
	}
	if closeErr != nil {
		p.launchCleanupErr = errors.Join(p.launchCleanupErr, closeErr)
		_ = stop()
	}
	return launchErr
}

// Inspect without File.Fd, which may change blocking behavior for some file
// origins. Callers own these files and must not close them concurrently with
// command wiring; the descriptor number is not retained as cleanup authority.
func uniVPNPacketDescriptor(f *os.File) (uintptr, error) {
	if f == nil {
		return 0, errors.New("missing packet launch descriptor")
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd uintptr
	err = raw.Control(func(value uintptr) { fd = value })
	return fd, err
}
