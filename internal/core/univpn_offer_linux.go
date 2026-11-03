//go:build linux

package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync"

	"mygo-vpn/internal/packetrelay"
)

// UniVPNOffer is authenticated tunnel metadata, never host ownership evidence.
type UniVPNOffer struct {
	Session           string
	Addresses, Routes []netip.Prefix
	DNS               []netip.Addr
	Endpoint          netip.Addr
}

func cloneUniVPNOffer(o UniVPNOffer) UniVPNOffer {
	o.Addresses = append([]netip.Prefix(nil), o.Addresses...)
	o.Routes = append([]netip.Prefix(nil), o.Routes...)
	o.DNS = append([]netip.Addr(nil), o.DNS...)
	return o
}

type uniVPNOfferChannel struct {
	mu          sync.Mutex
	ready, done chan struct{}
	offer       *UniVPNOffer
	terminal    bool
	err         error
}

func newUniVPNOfferChannel() *uniVPNOfferChannel {
	return &uniVPNOfferChannel{ready: make(chan struct{}), done: make(chan struct{})}
}
func decodeUniVPNOffer(data []byte, session string) (*UniVPNOffer, bool, error) {
	bad := errors.New("invalid native v2 offer")
	if len(session) != 32 {
		return nil, false, bad
	}
	for _, c := range session {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, false, bad
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, false, bad
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		if e != nil || !ok || fields[k] != nil {
			return nil, false, bad
		}
		switch k {
		case "version", "event", "session", "addresses", "routes", "dns", "endpoint":
		default:
			return nil, false, bad
		}
		var r json.RawMessage
		if d.Decode(&r) != nil || bytes.Equal(r, []byte("null")) {
			return nil, false, bad
		}
		fields[k] = r
	}
	if _, e = d.Token(); e != nil {
		return nil, false, bad
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, false, bad
	}
	var wire struct {
		Version           int    `json:"version"`
		Event             string `json:"event"`
		Session           string `json:"session"`
		Addresses, Routes []netip.Prefix
		DNS               []netip.Addr
		Endpoint          netip.Addr
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || wire.Version != 2 || wire.Session != session {
		return nil, false, bad
	}
	if wire.Event == "relay-closed" {
		if len(fields) != 3 {
			return nil, false, bad
		}
		return nil, true, nil
	}
	if wire.Event != "offer" || len(fields) != 7 {
		return nil, false, bad
	}
	for _, k := range []string{"version", "event", "session", "addresses", "routes", "dns", "endpoint"} {
		if fields[k] == nil {
			return nil, false, bad
		}
	}
	if len(wire.Addresses) != 1 || len(wire.Routes) > 128 || len(wire.DNS) > 3 || !wire.Endpoint.Is4() || !validUniVPNIP(wire.Endpoint) {
		return nil, false, bad
	}
	seen := map[netip.Prefix]bool{}
	for _, a := range wire.Addresses {
		if !a.IsValid() || !a.Addr().Is4() || !validUniVPNIP(a.Addr()) {
			return nil, false, bad
		}
	}
	for _, r := range wire.Routes {
		if !r.IsValid() || !r.Addr().Is4() || r != r.Masked() || r.Bits() == 0 || seen[r] {
			return nil, false, bad
		}
		seen[r] = true
	}
	dns := map[netip.Addr]bool{}
	for _, a := range wire.DNS {
		if !a.Is4() || !validUniVPNIP(a) || dns[a] {
			return nil, false, bad
		}
		dns[a] = true
	}
	return &UniVPNOffer{session, wire.Addresses, wire.Routes, wire.DNS, wire.Endpoint}, false, nil
}
func (s *uniVPNOfferChannel) read(r io.Reader, session string, invalid func()) {
	defer close(s.done)
	ready := false
	fail := func() {
		s.mu.Lock()
		s.err = errors.New("invalid or incomplete native v2 channel")
		s.mu.Unlock()
		if !ready {
			close(s.ready)
			ready = true
		}
		invalid()
	}
	b := bufio.NewReaderSize(r, uniVPNNativeRecordLimit+1)
	terminal := false
	for {
		line, e := b.ReadSlice('\n')
		if e == io.EOF && len(line) == 0 {
			if !terminal {
				fail()
			}
			return
		}
		if e != nil || len(line) > uniVPNNativeRecordLimit {
			fail()
			return
		}
		o, end, e := decodeUniVPNOffer(line, session)
		if e != nil || terminal || (!end && ready) {
			fail()
			return
		}
		s.mu.Lock()
		if end {
			s.terminal = true
			terminal = true
		} else {
			s.offer = o
		}
		s.mu.Unlock()
		if !ready {
			close(s.ready)
			ready = true
		}
		if end {
			invalid()
		} // terminal metadata must end any active session
	}
}

// UniVPNOfferSource must bind metadata and the exclusive packet endpoint to the
// exact launched process. ProveClosed includes whole-tree containment and channel
// completion, NOT host network absence. WaitOffer transfers endpoint ownership.
type UniVPNOfferSource interface {
	WaitOffer(context.Context, UniVPNNativeProcess) (UniVPNOffer, packetrelay.PacketIO, error)
	ProveClosed(context.Context, UniVPNNativeProcess) error
	CheckLive(context.Context, UniVPNNativeProcess) error
}
type UniVPNNativeOfferSource struct{}

func (UniVPNNativeOfferSource) WaitOffer(ctx context.Context, process UniVPNNativeProcess) (UniVPNOffer, packetrelay.PacketIO, error) {
	p, ok := process.(*uniVPNExecProcess)
	if !ok || p == nil || p.offer == nil {
		return UniVPNOffer{}, nil, errors.New("process-bound v2 channel unavailable")
	}
	select {
	case <-ctx.Done():
		return UniVPNOffer{}, nil, ctx.Err()
	case <-p.offer.ready:
	}
	p.offer.mu.Lock()
	defer p.offer.mu.Unlock()
	if p.offer.err != nil || p.offer.terminal || p.offer.offer == nil {
		return UniVPNOffer{}, nil, errors.New("native offer unavailable")
	}
	p.packetMu.Lock()
	defer p.packetMu.Unlock()
	if ctx.Err() != nil {
		return UniVPNOffer{}, nil, ctx.Err()
	}
	select {
	case <-p.exited:
		return UniVPNOffer{}, nil, errors.New("native process exited")
	default:
	}
	if nilInterface(p.packet) || p.offer.offer.Session != p.sessionID {
		return UniVPNOffer{}, nil, errors.New("native packet endpoint unavailable")
	}
	endpoint := p.packet
	p.packet = nil
	return cloneUniVPNOffer(*p.offer.offer), endpoint, nil
}

// CheckLive rechecks process-bound offer state after host readback. It is not a
// network probe and never treats terminal metadata as a successful session.
func (UniVPNNativeOfferSource) CheckLive(ctx context.Context, process UniVPNNativeProcess) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, ok := process.(*uniVPNExecProcess)
	if !ok || p == nil || p.offer == nil {
		return errors.New("native offer unavailable")
	}
	select {
	case <-p.exited:
		return errors.New("native exited")
	default:
	}
	p.offer.mu.Lock()
	defer p.offer.mu.Unlock()
	if p.offer.err != nil || p.offer.terminal || p.offer.offer == nil || p.offer.offer.Session != p.sessionID {
		return errors.New("native offer no longer live")
	}
	return nil
}
func (UniVPNNativeOfferSource) ProveClosed(ctx context.Context, process UniVPNNativeProcess) error {
	p, ok := process.(*uniVPNExecProcess)
	if !ok || p == nil || p.offer == nil || p.contained == nil {
		return &CleanupError{}
	}
	select {
	case <-ctx.Done():
		return &CleanupError{}
	case <-p.contained:
	}
	if p.containmentErr != nil || p.launchCleanupErr != nil {
		return &CleanupError{}
	}
	select {
	case <-ctx.Done():
		return &CleanupError{}
	case <-p.offer.done:
	}
	p.offer.mu.Lock()
	defer p.offer.mu.Unlock()
	if p.offer.err != nil || !p.offer.terminal {
		return &CleanupError{}
	}
	return nil
}
