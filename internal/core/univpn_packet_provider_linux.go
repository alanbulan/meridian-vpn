//go:build linux

package core

import (
	"context"
	"errors"
	"os"
	"syscall"

	"mygo-vpn/internal/packetrelay"
)

// UniVPNLocalPacketProvider supplies the launcher's private packet channel.
// Each acquisition creates a fresh unnamed socketpair in one kernel operation,
// so the returned descriptors are opposite ends of the same connection. Both
// endpoints are nonblocking and CLOEXEC from creation, including during a
// concurrent exec. No listener, filesystem socket, host TUN or network route is
// created. The provider retains no descriptors and can be reused across launches.
//
// This provides only the local worker/relay channel. It does not establish host
// authority, worker containment, gateway connectivity or readiness. A trusted
// deployment must still supply those independent launcher/controller dependencies.
type UniVPNLocalPacketProvider struct{}

var _ UniVPNPacketProvider = UniVPNLocalPacketProvider{}

func (UniVPNLocalPacketProvider) AcquirePacket(ctx context.Context, sessionID string) (*os.File, packetrelay.PacketIO, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// Accept only the launcher's freshly generated session nonce, never a path
	// or address. The nonce is not used as a public socket name.
	if len(sessionID) != 32 {
		return nil, nil, errors.New("invalid packet session identity")
	}
	for _, c := range sessionID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, nil, errors.New("invalid packet session identity")
		}
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	native := os.NewFile(uintptr(fds[0]), "meridian-native-packet")
	relayFile := os.NewFile(uintptr(fds[1]), "meridian-relay-packet")
	// NewDatagramPackets retains caller ownership on failure. Before successful
	// transfer, close both handles exactly once; do not retry a failed close on
	// a descriptor number that the kernel may already have reused.
	fail := func(cause error) (*os.File, packetrelay.PacketIO, error) {
		closeErr := errors.Join(native.Close(), relayFile.Close())
		if closeErr != nil {
			cause = errors.Join(cause, closeErr, &CleanupError{})
		}
		return nil, nil, cause
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	relay, err := packetrelay.NewDatagramPackets(relayFile)
	if err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		closeErr := errors.Join(native.Close(), relay.Close())
		if closeErr != nil {
			err = errors.Join(err, closeErr, &CleanupError{})
		}
		return nil, nil, err
	}
	return native, relay, nil
}
