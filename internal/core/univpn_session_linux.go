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
)

const uniVPNNativeRecordLimit = 32768

// UniVPNNativeSessionSource consumes the private inherited pipe created by
// UniVPNExecLauncher.NativeSessionChannel. Neither caller input, environment,
// stdout nor a script can supply this channel. Readiness still requires the
// network controller's policy and kernel readback. This source does not supply
// process containment or an exclusive network namespace lease.
//
// Absence is checked again even after the controller's cleanup, including when
// the controller rejected a native configuration. Incomplete acquisition or a
// corrupt stream cannot establish cleanup and quarantines the backend.
type UniVPNNativeSessionSource struct{ ops UniVPNNetworkOps }

// UniVPNUncreatedSessionProof is the read-only kernel proof used only alongside
// the pinned native program's explicit no-network attestation and containment.
// It is not a substitute for full interface/route/resolver cleanup after a TUN
// was acquired. Providers that do not implement it retain conservative failure.
type UniVPNUncreatedSessionProof interface {
	ProveUncreatedSession(context.Context, string) error
}

func NewUniVPNNativeSessionSource(ops UniVPNNetworkOps) (*UniVPNNativeSessionSource, error) {
	if nilInterface(ops) {
		return nil, errors.New("native session absence operations required")
	}
	return &UniVPNNativeSessionSource{ops: ops}, nil
}
func (s *UniVPNNativeSessionSource) WaitNetworkConfig(ctx context.Context, process UniVPNNativeProcess) (UniVPNNetworkConfig, error) {
	p, ok := process.(*uniVPNExecProcess)
	if !ok || p == nil || p.session == nil {
		return UniVPNNetworkConfig{}, errors.New("native process-bound channel unavailable")
	}
	select {
	case <-ctx.Done():
		return UniVPNNetworkConfig{}, ctx.Err()
	case <-p.session.ready:
	}
	p.session.mu.Lock()
	defer p.session.mu.Unlock()
	if p.session.err != nil {
		return UniVPNNetworkConfig{}, p.session.err
	}
	if p.session.config == nil {
		return UniVPNNetworkConfig{}, errors.New("native configuration unavailable")
	}
	return cloneUniVPNNativeConfig(*p.session.config), nil
}
func (s *UniVPNNativeSessionSource) ProveNetworkGone(ctx context.Context, process UniVPNNativeProcess) error {
	p, ok := process.(*uniVPNExecProcess)
	if !ok || p == nil || p.session == nil || p.contained == nil {
		return &CleanupError{}
	}
	select {
	case <-ctx.Done():
		return &CleanupError{}
	case <-p.contained:
	}
	if p.containmentErr != nil {
		return &CleanupError{}
	}
	select {
	case <-ctx.Done():
		return &CleanupError{}
	case <-p.session.done:
	}
	p.session.mu.Lock()
	if p.session.err == nil && p.session.noNetwork {
		alias := p.session.alias
		p.session.mu.Unlock()
		proof, ok := s.ops.(UniVPNUncreatedSessionProof)
		if !ok || proof.ProveUncreatedSession(ctx, alias) != nil {
			return &CleanupError{}
		}
		return nil
	}
	if p.session.err != nil || p.session.config == nil {
		p.session.mu.Unlock()
		return &CleanupError{}
	}
	c := cloneUniVPNNativeConfig(*p.session.config)
	p.session.mu.Unlock()
	if err := s.ops.ProveAbsent(ctx, c); err != nil {
		return &CleanupError{}
	}
	return nil
}
func cloneUniVPNNativeConfig(c UniVPNNetworkConfig) UniVPNNetworkConfig {
	c.Addresses = append([]netip.Prefix(nil), c.Addresses...)
	c.Routes = append([]netip.Prefix(nil), c.Routes...)
	c.DNS = append([]netip.Addr(nil), c.DNS...)
	return c
}

type uniVPNNativeRecord struct {
	Version   int            `json:"version"`
	Event     string         `json:"event"`
	Session   string         `json:"session"`
	Interface string         `json:"interface,omitempty"`
	Index     int            `json:"index,omitempty"`
	Alias     string         `json:"alias,omitempty"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	Routes    []netip.Prefix `json:"routes,omitempty"`
	DNS       []netip.Addr   `json:"dns,omitempty"`
	Endpoint  netip.Addr     `json:"endpoint,omitempty"`
}
type uniVPNNativeChannel struct {
	mu          sync.Mutex
	ready, done chan struct{}
	config      *UniVPNNetworkConfig
	noNetwork   bool
	alias       string
	err         error
}

func newUniVPNNativeChannel() *uniVPNNativeChannel {
	return &uniVPNNativeChannel{ready: make(chan struct{}), done: make(chan struct{})}
}

// Reject duplicate keys rather than accepting encoding/json's last-value wins.
// All nested protocol values are scalar arrays, so nested objects are rejected.
func decodeUniVPNNativeRecord(data []byte) (uniVPNNativeRecord, error) {
	var out uniVPNNativeRecord
	d := json.NewDecoder(bytes.NewReader(data))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return out, errors.New("invalid native record")
	}
	seen := map[string]bool{}
	for d.More() {
		t, e = d.Token()
		key, ok := t.(string)
		if e != nil || !ok || seen[key] {
			return out, errors.New("duplicate native record field")
		}
		switch key {
		case "version", "event", "session", "interface", "index", "alias", "addresses", "routes", "dns", "endpoint":
		default:
			return out, errors.New("unknown native record field")
		}
		seen[key] = true
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return out, errors.New("invalid native field")
		}
	}
	if _, e = d.Token(); e != nil {
		return out, errors.New("invalid native record end")
	}
	if _, e = d.Token(); e != io.EOF {
		return out, errors.New("trailing native record data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e = d.Decode(&out); e != nil {
		return out, errors.New("invalid native record fields")
	}
	if (out.Event == "closed" || out.Event == "no-network") && len(seen) != 3 {
		return out, errors.New("unexpected terminal fields")
	}
	return out, nil
}
func (s *uniVPNNativeChannel) read(r io.Reader, session string, invalid func()) {
	defer close(s.done)
	ready := false
	fail := func() {
		s.mu.Lock()
		s.err = errors.New("invalid or incomplete native session channel")
		s.mu.Unlock()
		if !ready {
			close(s.ready)
			ready = true
		}
		invalid()
	}
	b := bufio.NewReaderSize(r, uniVPNNativeRecordLimit+1)
	closed := false
	for {
		line, e := b.ReadSlice('\n')
		if e == io.EOF && len(line) == 0 {
			if !ready {
				fail()
			}
			return
		}
		if e != nil || len(line) > uniVPNNativeRecordLimit {
			fail()
			return
		}
		rec, e := decodeUniVPNNativeRecord(line)
		if e != nil || rec.Version != 1 || rec.Session != session || closed {
			fail()
			return
		}
		switch rec.Event {
		case "config":
			if ready || !safeUniVPNLink(rec.Interface) || rec.Index <= 0 || rec.Alias != "meridian-"+session || len(rec.Addresses) == 0 || len(rec.Addresses) > 8 || len(rec.Routes) > 128 || len(rec.DNS) > 8 || !validUniVPNIP(rec.Endpoint) {
				fail()
				return
			}
			for _, p := range rec.Addresses {
				if !p.IsValid() || !validUniVPNIP(p.Addr()) {
					fail()
					return
				}
			}
			for _, p := range rec.Routes {
				if !p.IsValid() || !validUniVPNIP(p.Addr()) || p != p.Masked() || p.Bits() == 0 {
					fail()
					return
				}
			}
			for _, a := range rec.DNS {
				if !validUniVPNIP(a) {
					fail()
					return
				}
			}
			c := UniVPNNetworkConfig{Interface: rec.Interface, Index: rec.Index, Alias: rec.Alias, Addresses: rec.Addresses, Routes: rec.Routes, DNS: rec.DNS, Endpoint: rec.Endpoint}
			s.mu.Lock()
			s.config = &c
			s.mu.Unlock()
			close(s.ready)
			ready = true
		case "no-network":
			if ready || rec.Interface != "" || rec.Index != 0 || rec.Alias != "" || len(rec.Addresses) != 0 || len(rec.Routes) != 0 || len(rec.DNS) != 0 || rec.Endpoint.IsValid() {
				fail()
				return
			}
			s.mu.Lock()
			s.noNetwork = true
			s.alias = "meridian-" + session
			s.mu.Unlock()
			close(s.ready)
			ready = true
			closed = true
		case "closed":
			if !ready || rec.Interface != "" || rec.Index != 0 || rec.Alias != "" || len(rec.Addresses) != 0 || len(rec.Routes) != 0 || len(rec.DNS) != 0 || rec.Endpoint.IsValid() {
				fail()
				return
			}
			closed = true
		default:
			fail()
			return
		}
	}
}
