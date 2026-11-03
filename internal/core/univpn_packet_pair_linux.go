//go:build linux

package core

import (
	"context"
	"errors"
	"os"
	"sync"

	"mygo-vpn/internal/packetrelay"
)

var errUniVPNPacketPair = errors.New("packet pair provider unavailable or already consumed")

// UniVPNPacketPairProvider creates one private local socketpair for one launch.
// It retains no endpoint, duplicate, goroutine or cancellation hook after return.
// Session is a shape-checked launch label, not authority, a lookup or reconnect
// key. It does not establish native/NM/TUN identity or implement HostBinding.
// Do not copy. Use a new provider for each separately authorized generation.
// This provider is not enabled in the normal application.
type UniVPNPacketPairProvider struct {
	self *UniVPNPacketPairProvider
	mu sync.Mutex
	attempted bool
	err error
}

var _ UniVPNPacketProvider = (*UniVPNPacketPairProvider)(nil)

// NewUniVPNPacketPairProvider creates no resource and performs no I/O.
func NewUniVPNPacketPairProvider() *UniVPNPacketPairProvider {
	p := &UniVPNPacketPairProvider{}
	p.self = p
	return p
}

// AcquirePacket consumes the only attempt before validating inputs. A canceled
// or failed attempt cannot be retried. Failure returns nil endpoints after local
// cleanup; CleanupError is retained on future calls when cleanup is uncertain.
// On success both endpoints transfer exclusively to the caller. Context covers
// acquisition only, not the subsequent lifetime of the returned pair.
func (p *UniVPNPacketPairProvider) AcquirePacket(ctx context.Context, session string) (*os.File, packetrelay.PacketIO, error) {
	return p.acquire(ctx, session, packetrelay.OpenPacketPair)
}

// Only private tests can replace acquisition; the public entry is concrete.
func (p *UniVPNPacketPairProvider) acquire(ctx context.Context, session string, open func(context.Context) (*os.File, *packetrelay.DatagramPackets, error)) (*os.File, packetrelay.PacketIO, error) {
	if p == nil || p.self != p { return nil, nil, errUniVPNPacketPair }
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attempted { return nil, nil, errors.Join(errUniVPNPacketPair, p.err) }
	p.attempted = true
	if ctx == nil || !validUniVPNPacketSession(session) || open == nil {
		p.err = errUniVPNPacketPair
		return nil, nil, p.err
	}
	if err := ctx.Err(); err != nil {
		p.err = errors.Join(errUniVPNPacketPair, err)
		return nil, nil, p.err
	}
	native, peer, err := open(ctx)
	if err == nil && (native == nil || peer == nil) { err = errUniVPNPacketPair }
	err = errors.Join(err, ctx.Err())
	if err != nil {
		// OpenPacketPair already cleans its own failures. Still retain and
		// close any successful return if cancellation won just afterwards.
		var closeErr error
		if native != nil { closeErr = errors.Join(closeErr, native.Close()) }
		if peer != nil { closeErr = errors.Join(closeErr, peer.Close()) }
		if closeErr != nil || errors.Is(err, packetrelay.ErrCleanup) {
			err = errors.Join(err, closeErr, &CleanupError{})
		}
		p.err = err
		return nil, nil, err
	}
	return native, peer, nil
}

func validUniVPNPacketSession(s string) bool {
	if len(s) != 32 { return false }
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return false }
	}
	return true
}
