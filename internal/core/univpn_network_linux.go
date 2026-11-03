//go:build linux

package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
)

// UniVPNNetworkConfig may only come from the authenticated, process-bound hook
// channel. In particular, Alias must be a fresh broker-generated ownership marker,
// NOT a value supplied by the gateway or desktop client. The hook must mark only
// the fresh TUN created by this native process before delivering this record.
type UniVPNNetworkConfig struct {
	Interface         string
	Index             int
	Alias             string
	Addresses, Routes []netip.Prefix
	DNS               []netip.Addr
	Endpoint          netip.Addr
}
type UniVPNNetworkSessionSource interface {
	WaitNetworkConfig(context.Context, UniVPNNativeProcess) (UniVPNNetworkConfig, error)
	// ProveNetworkGone must also cover partial hook acquisition and rejected config.
	ProveNetworkGone(context.Context, UniVPNNativeProcess) error
}

// Policy is administrator configuration, copied by the constructor. All pushed
// values must exactly match an allowlist entry: a broad allowed network does NOT
// authorize arbitrary more-specific routes (which could capture local services).
type UniVPNNetworkPolicy struct {
	DNSDomains        []string
	Routes, Addresses []netip.Prefix
	DNS, Endpoints    []netip.Addr
}
type UniVPNLinkState struct {
	DNSDomains           []string
	DNSDefaultRoute      bool
	DNSDefaultRouteKnown bool
	Exists               bool
	Index                int
	Alias, Kind          string
	Up                   bool
	Addresses            []netip.Prefix
	DNS                  []netip.Addr
	Routes               []netip.Prefix
}
type UniVPNEscapeRoute struct {
	Owner    UniVPNNetworkConfig
	Metric   uint32
	Endpoint netip.Addr
	Gateway  netip.Addr
	Device   string
}

// UniVPNNetworkOps is the injectable privileged boundary. Snapshot must return
// actual kernel/resolver state, not cached intent. EscapeExists must query all
// exact host routes and reject conflicting/non-owned routes, never replace them.
type UniVPNNetworkOps interface {
	Snapshot(context.Context, string) (UniVPNLinkState, error)
	Escape(context.Context, netip.Addr) (UniVPNEscapeRoute, error)
	EscapeExists(context.Context, UniVPNEscapeRoute) (bool, error)
	AddEscape(context.Context, UniVPNEscapeRoute) error
	DeleteEscape(context.Context, UniVPNEscapeRoute) error
	AddAddress(context.Context, UniVPNNetworkConfig, netip.Prefix) error
	AddRoute(context.Context, UniVPNNetworkConfig, netip.Prefix) error
	SetDNS(context.Context, UniVPNNetworkConfig, []netip.Addr) error
	SetUp(context.Context, UniVPNNetworkConfig) error
	RevertDNS(context.Context, UniVPNNetworkConfig) error
	DeleteLink(context.Context, UniVPNNetworkConfig) error
	// ProveAbsent queries link, routes AND resolver state, including stale records.
	ProveAbsent(context.Context, UniVPNNetworkConfig) error
}

type UniVPNLinuxNetworkController struct {
	source          UniVPNNetworkSessionSource
	ops             UniVPNNetworkOps
	policy          UniVPNNetworkPolicy
	mu              sync.Mutex
	process         UniVPNNativeProcess
	config          *UniVPNNetworkConfig
	escape          *UniVPNEscapeRoute
	escapeConfirmed bool
	dirty           bool
}

func NewUniVPNLinuxNetworkController(source UniVPNNetworkSessionSource, ops UniVPNNetworkOps, policy UniVPNNetworkPolicy) (*UniVPNLinuxNetworkController, error) {
	if nilInterface(source) || nilInterface(ops) {
		return nil, errors.New("trusted hook source and kernel operations required")
	}
	policy.DNSDomains = append([]string(nil), policy.DNSDomains...)
	if err := validateUniVPNDomains(policy.DNSDomains); err != nil {
		return nil, err
	}
	policy.Routes = append([]netip.Prefix(nil), policy.Routes...)
	policy.Addresses = append([]netip.Prefix(nil), policy.Addresses...)
	policy.DNS = append([]netip.Addr(nil), policy.DNS...)
	policy.Endpoints = append([]netip.Addr(nil), policy.Endpoints...)
	if len(policy.Addresses) == 0 || len(policy.Endpoints) == 0 {
		return nil, errors.New("explicit address and endpoint policy required")
	}
	for _, p := range append(append([]netip.Prefix(nil), policy.Routes...), policy.Addresses...) {
		if !p.IsValid() || p.Addr().Is4In6() {
			return nil, errors.New("invalid policy prefix")
		}
	}
	for _, a := range append(append([]netip.Addr(nil), policy.DNS...), policy.Endpoints...) {
		if !validUniVPNIP(a) {
			return nil, errors.New("invalid policy address")
		}
	}
	return &UniVPNLinuxNetworkController{source: source, ops: ops, policy: policy}, nil
}
func validUniVPNIP(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback()
}
func uniVPNContains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
func safeUniVPNLink(s string) bool {
	if len(s) == 0 || len(s) > 15 || s[0] == '-' {
		return false
	}
	allDigits := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigits = false
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return s != "lo" && !allDigits
}
func (n *UniVPNLinuxNetworkController) validate(c UniVPNNetworkConfig) error {
	if !safeUniVPNLink(c.Interface) || c.Index <= 0 || len(c.Alias) < 24 || len(c.Alias) > 96 {
		return errors.New("invalid owned TUN identity")
	}
	for _, r := range c.Alias {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return errors.New("invalid ownership marker")
		}
	}
	if !uniVPNContains(n.policy.Endpoints, c.Endpoint) || !validUniVPNIP(c.Endpoint) {
		return errors.New("unapproved endpoint")
	}
	if len(c.Addresses) == 0 || len(c.Addresses) > 8 || len(c.Routes) > 128 || len(c.DNS) > 8 {
		return errors.New("network configuration exceeds bounds")
	}
	seen := map[netip.Prefix]bool{}
	for _, p := range c.Addresses {
		if !p.IsValid() || !validUniVPNIP(p.Addr()) || !uniVPNContains(n.policy.Addresses, p) || seen[p] {
			return errors.New("unapproved or duplicate interface address")
		}
		seen[p] = true
	}
	seen = map[netip.Prefix]bool{}
	for _, p := range c.Routes {
		if !p.IsValid() || p.Bits() == 0 || p != p.Masked() || !uniVPNContains(n.policy.Routes, p) || seen[p] {
			return errors.New("unapproved or duplicate route")
		}
		seen[p] = true
	}
	if len(c.DNS) > 0 && len(n.policy.DNSDomains) == 0 {
		return errors.New("explicit DNS routing domains required")
	}
	seenDNS := map[netip.Addr]bool{}
	for _, a := range c.DNS {
		if !validUniVPNIP(a) || !uniVPNContains(n.policy.DNS, a) || seenDNS[a] {
			return errors.New("unapproved or duplicate DNS")
		}
		reachable := false
		for _, r := range c.Routes {
			if r.Contains(a) {
				reachable = true
			}
		}
		for _, p := range c.Addresses {
			if p.Masked().Contains(a) {
				reachable = true
			}
		}
		if !reachable {
			return errors.New("DNS address has no approved tunnel route")
		}
		seenDNS[a] = true
	}
	return nil
}
func ownedUniVPNLink(s UniVPNLinkState, c UniVPNNetworkConfig) bool {
	return s.Exists && s.Index == c.Index && s.Alias == c.Alias && s.Kind == "tun"
}
func sameUniVPNSet[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[T]bool, len(a))
	for _, x := range a {
		if seen[x] {
			return false
		}
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
		delete(seen, x)
	}
	return len(seen) == 0
}

func (n *UniVPNLinuxNetworkController) WaitReady(ctx context.Context, p UniVPNNativeProcess) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.process != nil || n.dirty {
		return errors.New("network controller busy or quarantined")
	}
	if nilInterface(p) || !reflect.TypeOf(p).Comparable() {
		return errors.New("invalid process identity")
	}
	// Retain identity even when hook acquisition fails: Cleanup still requires
	// the source to prove partial hook/native-owned state is gone.
	n.process = p
	c, err := n.source.WaitNetworkConfig(ctx, p)
	if err != nil {
		return err
	}
	if err = n.validate(c); err != nil {
		return err
	}
	c.Addresses = append([]netip.Prefix(nil), c.Addresses...)
	c.Routes = append([]netip.Prefix(nil), c.Routes...)
	c.DNS = append([]netip.Addr(nil), c.DNS...)
	s, err := n.ops.Snapshot(ctx, c.Interface)
	if err != nil {
		return err
	}
	if !ownedUniVPNLink(s, c) || len(s.Addresses) > 0 || len(s.Routes) > 0 || len(s.DNS) > 0 || len(s.DNSDomains) > 0 || s.DNSDefaultRoute {
		return errors.New("TUN is not fresh and exclusively session-owned")
	}
	n.config = &c
	n.dirty = true
	if err = ctx.Err(); err != nil {
		return err
	}
	escape, err := n.ops.Escape(ctx, c.Endpoint)
	if err != nil {
		return err
	}
	if escape.Endpoint != c.Endpoint || !safeUniVPNLink(escape.Device) || escape.Device == c.Interface || (escape.Gateway.IsValid() && !validUniVPNIP(escape.Gateway)) {
		return errors.New("unsafe endpoint escape route")
	}
	escape.Owner = c
	escape.Metric = uniVPNNetworkMetric(c.Alias)
	exists, err := n.ops.EscapeExists(ctx, escape)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("endpoint escape route already exists")
	}
	// Journal before attempted writes: a failed command may already have applied.
	n.escape = &escape
	if err = n.ops.AddEscape(ctx, escape); err != nil {
		return err
	}
	n.escapeConfirmed = true
	for _, a := range c.Addresses {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = n.ops.AddAddress(ctx, c, a); err != nil {
			return err
		}
	}
	for _, r := range c.Routes {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = n.ops.AddRoute(ctx, c, r); err != nil {
			return err
		}
	}
	if len(c.DNS) > 0 {
		if err = n.ops.SetDNS(ctx, c, c.DNS); err != nil {
			return err
		}
	}
	if err = n.ops.SetUp(ctx, c); err != nil {
		return err
	}
	s, err = n.ops.Snapshot(ctx, c.Interface)
	if err != nil {
		return err
	}
	if !ownedUniVPNLink(s, c) || !s.Up || !sameUniVPNSet(s.Addresses, c.Addresses) || !sameUniVPNSet(s.Routes, c.Routes) || !sameUniVPNSet(s.DNS, c.DNS) || (len(c.DNS) > 0 && (!sameUniVPNSet(s.DNSDomains, n.policy.DNSDomains) || !s.DNSDefaultRouteKnown || s.DNSDefaultRoute)) {
		return errors.New("kernel/resolver readiness mismatch")
	}
	exists, err = n.ops.EscapeExists(ctx, escape)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("endpoint escape route missing")
	}
	return ctx.Err()
}
func (n *UniVPNLinuxNetworkController) Cleanup(ctx context.Context, p UniVPNNativeProcess) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.process == nil {
		return nil
	}
	if nilInterface(p) || !reflect.TypeOf(p).Comparable() || n.process != p {
		return errors.New("wrong cleanup process")
	}
	var failures []error
	if n.config != nil {
		c := *n.config
		s, err := n.ops.Snapshot(ctx, c.Interface)
		if err != nil {
			failures = append(failures, err)
		} else if s.Exists {
			if !ownedUniVPNLink(s, c) {
				return errors.New("TUN ownership changed; refusing cleanup")
			}
			if err = n.ops.RevertDNS(ctx, c); err != nil {
				failures = append(failures, err)
			}
			if err = n.ops.DeleteLink(ctx, c); err != nil {
				failures = append(failures, err)
			}
		}
		if err = n.ops.ProveAbsent(ctx, c); err != nil {
			failures = append(failures, err)
		}
	}
	if n.escape != nil {
		exists, err := n.ops.EscapeExists(ctx, *n.escape)
		if err != nil {
			failures = append(failures, err)
		} else if exists && !n.escapeConfirmed {
			failures = append(failures, errors.New("escape creation uncertain; refusing deletion"))
		} else if exists {
			if err = n.ops.DeleteEscape(ctx, *n.escape); err != nil {
				failures = append(failures, err)
			}
		}
		exists, err = n.ops.EscapeExists(ctx, *n.escape)
		if err != nil {
			failures = append(failures, err)
		} else if exists {
			failures = append(failures, errors.New("escape route remains"))
		}
	}
	if err := n.source.ProveNetworkGone(ctx, p); err != nil {
		failures = append(failures, err)
	}
	if err := ctx.Err(); err != nil {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		n.dirty = true
		return fmt.Errorf("network cleanup not proven: %w", errors.Join(failures...))
	}
	n.process = nil
	n.config = nil
	n.escape = nil
	n.escapeConfirmed = false
	n.dirty = false
	return nil
}

func uniVPNNetworkMetric(alias string) uint32 {
	h := sha256.Sum256([]byte(alias))
	return 0x40000000 | (binary.BigEndian.Uint32(h[:4]) & 0x3fffffff)
}
func validateUniVPNDomains(domains []string) error {
	if len(domains) > 32 {
		return errors.New("too many DNS domains")
	}
	seen := map[string]bool{}
	for _, d := range domains {
		if len(d) < 2 || len(d) > 254 || d[0] != '~' || seen[d] {
			return errors.New("unique route-only DNS domains required")
		}
		seen[d] = true
		for _, c := range d[1:] {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return errors.New("invalid DNS domain")
			}
		}
	}
	return nil
}
