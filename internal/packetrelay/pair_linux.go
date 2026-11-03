//go:build linux

package packetrelay

import (
	"context"
	"errors"
	"os"
	"syscall"
)

var errPacketPair = errors.New("local packet pair acquisition failed")

// OpenPacketPair creates one anonymous, connected AF_UNIX SOCK_SEQPACKET pair.
// Both NONBLOCK and CLOEXEC are set atomically by the one socketpair syscall.
// It does not bind/connect a pathname, contact an IP peer, configure networking,
// open a TUN, or launch a process. No fallback, adoption or retry is performed.
//
// On success, the caller owns the native file and the exact opposite concrete
// DatagramPackets endpoint. Pairing follows from their original acquisition,
// not merely matching unnamed addresses. The native file may be transferred to
// the launcher; the relay endpoint must stay in the broker. The caller must not
// copy/share descriptors or alter their flags after transfer.
//
// Any failure after acquisition closes both owned handles once and returns nil
// endpoints. ErrCleanup reports uncertain closes; those numeric FDs must never
// be retried. Context is checked around syscalls but cannot interrupt them. It
// covers acquisition only; cancellation after success does not own the handles.
func OpenPacketPair(ctx context.Context) (*os.File, *DatagramPackets, error) {
	return openPacketPair(ctx, packetPairOps{
		pair: syscall.Socketpair,
		validateNative: func(f *os.File) error {
			_, err := validateDatagramFile(f)
			return err
		},
		wrapRelay:  NewDatagramPackets,
		closeFile:  (*os.File).Close,
		closeRelay: (*DatagramPackets).Close,
	})
}

// Per-call injection exists only for package tests. Production always supplies
// the exact syscall and concrete validators above; there is no public fd input.
type packetPairOps struct {
	pair           func(int, int, int) ([2]int, error)
	validateNative func(*os.File) error
	wrapRelay      func(*os.File) (*DatagramPackets, error)
	closeFile      func(*os.File) error
	closeRelay     func(*DatagramPackets) error
}

func openPacketPair(ctx context.Context, ops packetPairOps) (native *os.File, relay *DatagramPackets, resultErr error) {
	if ctx == nil || ops.pair == nil || ops.validateNative == nil || ops.wrapRelay == nil || ops.closeFile == nil || ops.closeRelay == nil {
		return nil, nil, errPacketPair
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, errors.Join(errPacketPair, err)
	}
	fds, err := ops.pair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		// Go's syscall.Socketpair returns [0,0] on failure. Those are not
		// acquired descriptors. Never interpret them as resources to close.
		return nil, nil, errors.Join(errPacketPair, err)
	}
	var files [2]*os.File
	for i, fd := range fds {
		if fd >= 0 && (i == 0 || fd != fds[0]) {
			files[i] = os.NewFile(uintptr(fd), "meridian-owned-packet-pair")
		}
	}
	// Files own the successful syscall's descriptors before any validation or
	// cancellation check. There is no raw close after this ownership transfer.
	var peer *DatagramPackets
	defer func() {
		if resultErr == nil {
			return
		}
		var closeErr error
		if files[0] != nil {
			closeErr = errors.Join(closeErr, ops.closeFile(files[0]))
		}
		if peer != nil {
			closeErr = errors.Join(closeErr, ops.closeRelay(peer))
		} else if files[1] != nil {
			closeErr = errors.Join(closeErr, ops.closeFile(files[1]))
		}
		if closeErr != nil {
			resultErr = errors.Join(resultErr, ErrCleanup, closeErr)
		}
		native, relay = nil, nil
	}()
	if files[0] == nil || files[1] == nil || ctx.Err() != nil {
		return nil, nil, errors.Join(errPacketPair, ctx.Err())
	}
	if err = ops.validateNative(files[0]); err != nil || ctx.Err() != nil {
		return nil, nil, errors.Join(errPacketPair, err, ctx.Err())
	}
	peer, err = ops.wrapRelay(files[1])
	if err != nil || peer == nil || ctx.Err() != nil {
		return nil, nil, errors.Join(errPacketPair, err, ctx.Err())
	}
	return files[0], peer, nil
}
