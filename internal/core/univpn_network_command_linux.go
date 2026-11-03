//go:build linux

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// UniVPNNetworkCommandRunner must execute argv directly, never through a shell.
// Output is bounded and errors must not include gateway-supplied output.
type UniVPNNetworkCommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type UniVPNRootCommandRunner struct{}
type uniVPNBoundedOutput struct{ bytes.Buffer }

func (b *uniVPNBoundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, errors.New("network command output limit")
	}
	return b.Buffer.Write(p)
}
func (UniVPNRootCommandRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute trusted command path required")
	}
	if err := trustedUniVPNPath(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 {
		return nil, errors.New("untrusted network executable")
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	var out uniVPNBoundedOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, errors.New("network command failed")
	}
	return out.Bytes(), nil
}

// UniVPNCommandNetworkOps uses iproute2 JSON and systemd-resolved's C-locale
// numeric DNS listing. Unknown output fails closed. No global resolv.conf edits.
// Paths and route-only DNS domains are fixed administrator configuration.
// Constructor performs NO host command; all commands are at the injectable Run
// boundary. This implementation has only mock coverage, not live kernel QA.
// UniVPNNetworkLease is supplied by reviewed deployment isolation. It verifies
// a previously acquired, namespace/session-bound exclusive lease, held through
// cleanup; it must prohibit competing CAP_NET_ADMIN writers, not merely lock
// other broker goroutines. There is intentionally no permissive default.
type UniVPNNetworkLease interface {
	AssertHeld(context.Context, UniVPNNetworkConfig) error
}
type UniVPNCommandNetworkOps struct {
	lease        UniVPNNetworkLease
	runner       UniVPNNetworkCommandRunner
	ip, resolver string
	domains      []string
}

func NewUniVPNCommandNetworkOps(r UniVPNNetworkCommandRunner, lease UniVPNNetworkLease, ip, resolver string, domains []string) (*UniVPNCommandNetworkOps, error) {
	if nilInterface(lease) || nilInterface(r) || !filepath.IsAbs(ip) || !filepath.IsAbs(resolver) {
		return nil, errors.New("explicit command runner and paths required")
	}
	if err := validateUniVPNDomains(domains); err != nil {
		return nil, err
	}
	return &UniVPNCommandNetworkOps{lease: lease, runner: r, ip: ip, resolver: resolver, domains: append([]string(nil), domains...)}, nil
}
func (o *UniVPNCommandNetworkOps) ipRun(ctx context.Context, args ...string) ([]byte, error) {
	return o.runner.Run(ctx, o.ip, args...)
}
func (o *UniVPNCommandNetworkOps) dnsRun(ctx context.Context, args ...string) ([]byte, error) {
	return o.runner.Run(ctx, o.resolver, args...)
}
func (o *UniVPNCommandNetworkOps) command(ctx context.Context, args ...string) error {
	_, e := o.ipRun(ctx, args...)
	return e
}

type uniVPNIPLink struct {
	Index int      `json:"ifindex"`
	Name  string   `json:"ifname"`
	Alias string   `json:"ifalias"`
	Flags []string `json:"flags"`
	Info  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	Addresses []struct {
		Local  string `json:"local"`
		Length int    `json:"prefixlen"`
		Scope  string `json:"scope"`
	} `json:"addr_info"`
}
type uniVPNIPRoute struct {
	Dst      string          `json:"dst"`
	Gateway  string          `json:"gateway"`
	Dev      string          `json:"dev"`
	Protocol json.RawMessage `json:"protocol"`
	Metric   int             `json:"metric"`
	Type     string          `json:"type"`
	Table    json.RawMessage `json:"table"`
}

func uniVPNRouteProtocol(r uniVPNIPRoute) string { return strings.Trim(string(r.Protocol), "\"") }
func (o *UniVPNCommandNetworkOps) links(ctx context.Context) ([]uniVPNIPLink, error) {
	b, e := o.ipRun(ctx, "-json", "-details", "address", "show")
	if e != nil {
		return nil, e
	}
	return uniVPNDecodeLinks(b)
}
func (o *UniVPNCommandNetworkOps) routes(ctx context.Context) ([]uniVPNIPRoute, error) {
	var all []uniVPNIPRoute
	for _, family := range []string{"-4", "-6"} {
		b, e := o.ipRun(ctx, family, "-json", "route", "show", "table", "all")
		if e != nil {
			return nil, e
		}
		v, e := uniVPNDecodeRoutes(b)
		if e != nil {
			return nil, e
		}
		all = append(all, v...)
	}
	return all, nil
}

type uniVPNResolvedDNS struct {
	index   int
	name    string
	servers []netip.Addr
}

func (o *UniVPNCommandNetworkOps) resolverDNS(ctx context.Context) ([]uniVPNResolvedDNS, error) {
	b, e := o.dnsRun(ctx, "dns")
	if e != nil {
		return nil, e
	}
	var records []uniVPNResolvedDNS
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		head, tail, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("unknown resolver output")
		}
		r := uniVPNResolvedDNS{}
		if head != "Global" {
			parts := strings.Fields(head)
			if len(parts) != 3 || parts[0] != "Link" || !strings.HasPrefix(parts[2], "(") || !strings.HasSuffix(parts[2], ")") {
				return nil, errors.New("unknown resolver link")
			}
			r.index, e = strconv.Atoi(parts[1])
			if e != nil || r.index <= 0 {
				return nil, errors.New("invalid resolver index")
			}
			r.name = strings.TrimSuffix(strings.TrimPrefix(parts[2], "("), ")")
		}
		for _, v := range strings.Fields(tail) {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, errors.New("unknown resolver address")
			}
			r.servers = append(r.servers, a)
		}
		records = append(records, r)
	}
	return records, nil
}
func uniVPNMainTable(r uniVPNIPRoute) bool {
	t := strings.Trim(string(r.Table), "\"")
	return t == "" || t == "main" || t == "254"
}
func (o *UniVPNCommandNetworkOps) Snapshot(ctx context.Context, name string) (UniVPNLinkState, error) {
	var s UniVPNLinkState
	links, e := o.links(ctx)
	if e != nil {
		return s, e
	}
	for _, l := range links {
		if l.Name != name {
			continue
		}
		if s.Exists {
			return s, errors.New("duplicate interface")
		}
		s.Exists = true
		s.Index = l.Index
		s.Alias = l.Alias
		s.Kind = l.Info.Kind
		s.Up = uniVPNContains(l.Flags, "UP")
		for _, a := range l.Addresses {
			p, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", a.Local, a.Length))
			if err != nil {
				return s, err
			}
			if p.Addr().Is6() && p.Addr().IsLinkLocalUnicast() {
				continue
			}
			s.Addresses = append(s.Addresses, p)
		}
	}
	routes, e := o.routes(ctx)
	if e != nil {
		return s, e
	}
	for _, r := range routes {
		if r.Dev != name || uniVPNRouteProtocol(r) == "kernel" {
			continue
		}
		if uniVPNRouteProtocol(r) != "186" || !uniVPNMainTable(r) || (r.Type != "" && r.Type != "unicast") || uint32(r.Metric) != uniVPNNetworkMetric(s.Alias) {
			return s, errors.New("unexpected route ownership or attributes")
		}
		p, e := netip.ParsePrefix(r.Dst)
		if r.Dst == "default" {
			return s, errors.New("unbounded route in owned TUN")
		}
		if e != nil {
			a, err := netip.ParseAddr(r.Dst)
			if err != nil {
				return s, e
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		s.Routes = append(s.Routes, p)
	}
	dns, e := o.resolverDNS(ctx)
	if e != nil {
		return s, e
	}
	for _, r := range dns {
		if r.name == name {
			if r.index != s.Index && s.Exists {
				return s, errors.New("resolver interface index mismatch")
			}
			s.DNS = append(s.DNS, r.servers...)
		}
	}
	domains, e := o.resolverValues(ctx, "domain")
	if e != nil {
		return s, e
	}
	defaults, e := o.resolverValues(ctx, "default-route")
	if e != nil {
		return s, e
	}
	for _, r := range domains {
		if r.name == name {
			if s.Exists && r.index != s.Index {
				return s, errors.New("resolver domain index mismatch")
			}
			s.DNSDomains = append(s.DNSDomains, r.values...)
		}
	}
	for _, r := range defaults {
		if r.name == name {
			if s.Exists && r.index != s.Index {
				return s, errors.New("resolver default index mismatch")
			}
			if len(r.values) != 1 || (r.values[0] != "yes" && r.values[0] != "no") {
				return s, errors.New("unknown resolver default route")
			}
			if s.DNSDefaultRouteKnown {
				return s, errors.New("duplicate resolver default route record")
			}
			s.DNSDefaultRouteKnown = true
			s.DNSDefaultRoute = r.values[0] == "yes"
		}
	}
	return s, nil
}
func (o *UniVPNCommandNetworkOps) Escape(ctx context.Context, a netip.Addr) (UniVPNEscapeRoute, error) {
	r := UniVPNEscapeRoute{Endpoint: a}
	family := "-6"
	if a.Is4() {
		family = "-4"
	}
	b, e := o.ipRun(ctx, family, "-json", "route", "get", a.String())
	if e != nil {
		return r, e
	}
	routes, e := uniVPNDecodeRoutes(b)
	if e != nil {
		return r, e
	}
	if len(routes) != 1 || routes[0].Dev == "" || routes[0].Type != "" && routes[0].Type != "unicast" {
		return r, errors.New("ambiguous endpoint route")
	}
	r.Device = routes[0].Dev
	if routes[0].Gateway != "" {
		r.Gateway, e = netip.ParseAddr(routes[0].Gateway)
	}
	return r, e
}
func (o *UniVPNCommandNetworkOps) EscapeExists(ctx context.Context, escape UniVPNEscapeRoute) (bool, error) {
	routes, e := o.routes(ctx)
	if e != nil {
		return false, e
	}
	host := netip.PrefixFrom(escape.Endpoint, escape.Endpoint.BitLen()).String()
	found := false
	for _, r := range routes {
		if r.Dst != host && r.Dst != escape.Endpoint.String() {
			continue
		}
		gateway := ""
		if escape.Gateway.IsValid() {
			gateway = escape.Gateway.String()
		}
		if found || r.Dev != escape.Device || r.Gateway != gateway || uniVPNRouteProtocol(r) != "186" || uint32(r.Metric) != escape.Metric || !uniVPNMainTable(r) {
			return false, errors.New("conflicting endpoint host route")
		}
		found = true
	}
	return found, nil
}
func (o *UniVPNCommandNetworkOps) escapeArgs(verb string, r UniVPNEscapeRoute) []string {
	family := "-6"
	if r.Endpoint.Is4() {
		family = "-4"
	}
	a := []string{family, "route", verb, netip.PrefixFrom(r.Endpoint, r.Endpoint.BitLen()).String()}
	if r.Gateway.IsValid() {
		a = append(a, "via", r.Gateway.String())
	}
	return append(a, "dev", r.Device, "table", "main", "proto", "186", "metric", strconv.FormatUint(uint64(r.Metric), 10))
}
func (o *UniVPNCommandNetworkOps) AddEscape(ctx context.Context, r UniVPNEscapeRoute) error {
	if err := o.guard(ctx, r.Owner); err != nil {
		return err
	}
	return o.command(ctx, o.escapeArgs("add", r)...)
}
func (o *UniVPNCommandNetworkOps) DeleteEscape(ctx context.Context, r UniVPNEscapeRoute) error {
	if err := o.lease.AssertHeld(ctx, r.Owner); err != nil {
		return err
	}
	exists, err := o.EscapeExists(ctx, r)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return o.command(ctx, o.escapeArgs("del", r)...)
}
func (o *UniVPNCommandNetworkOps) AddAddress(ctx context.Context, c UniVPNNetworkConfig, p netip.Prefix) error {
	if err := o.guard(ctx, c); err != nil {
		return err
	}

	return o.command(ctx, "address", "add", p.String(), "dev", c.Interface)
}
func (o *UniVPNCommandNetworkOps) AddRoute(ctx context.Context, c UniVPNNetworkConfig, p netip.Prefix) error {
	if err := o.guard(ctx, c); err != nil {
		return err
	}

	return o.command(ctx, "route", "add", p.String(), "dev", c.Interface, "table", "main", "proto", "186", "metric", strconv.FormatUint(uint64(uniVPNNetworkMetric(c.Alias)), 10))
}
func (o *UniVPNCommandNetworkOps) SetUp(ctx context.Context, c UniVPNNetworkConfig) error {
	if err := o.guard(ctx, c); err != nil {
		return err
	}

	return o.command(ctx, "link", "set", "dev", c.Interface, "up")
}
func (o *UniVPNCommandNetworkOps) SetDNS(ctx context.Context, c UniVPNNetworkConfig, servers []netip.Addr) error {
	if err := o.guard(ctx, c); err != nil {
		return err
	}

	if len(o.domains) == 0 {
		return errors.New("DNS route-only domains require administrator policy")
	}
	a := []string{"dns", c.Interface}
	for _, s := range servers {
		a = append(a, s.String())
	}
	if _, e := o.dnsRun(ctx, a...); e != nil {
		return e
	}
	if _, e := o.dnsRun(ctx, append([]string{"domain", c.Interface}, o.domains...)...); e != nil {
		return e
	}
	_, e := o.dnsRun(ctx, "default-route", c.Interface, "no")
	return e
}
func (o *UniVPNCommandNetworkOps) RevertDNS(ctx context.Context, c UniVPNNetworkConfig) error {
	if err := o.guard(ctx, c); err != nil {
		return err
	}

	_, e := o.dnsRun(ctx, "revert", c.Interface)
	return e
}
func (o *UniVPNCommandNetworkOps) DeleteLink(ctx context.Context, c UniVPNNetworkConfig) error {
	if err := o.guard(ctx, c); err != nil {
		return err
	}

	return o.command(ctx, "link", "delete", "dev", c.Interface)
}
func (o *UniVPNCommandNetworkOps) ProveAbsent(ctx context.Context, c UniVPNNetworkConfig) error {
	links, e := o.links(ctx)
	if e != nil {
		return e
	}
	for _, l := range links {
		if l.Index == c.Index || l.Name == c.Interface || l.Alias == c.Alias {
			return errors.New("owned interface absence not proven")
		}
	}
	routes, e := o.routes(ctx)
	if e != nil {
		return e
	}
	for _, r := range routes {
		if r.Dev == c.Interface {
			return errors.New("interface route remains")
		}
	}
	dns, e := o.resolverDNS(ctx)
	if e != nil {
		return e
	}
	for _, r := range dns {
		if (r.index == c.Index || r.name == c.Interface) && len(r.servers) > 0 {
			return errors.New("interface DNS remains")
		}
	}
	for _, command := range []string{"domain", "default-route"} {
		records, e := o.resolverValues(ctx, command)
		if e != nil {
			return e
		}
		for _, r := range records {
			if r.index == c.Index || r.name == c.Interface {
				if command == "domain" && len(r.values) > 0 {
					return errors.New("interface DNS domain remains")
				}
				if command == "default-route" && (len(r.values) != 1 || r.values[0] != "no") {
					return errors.New("interface DNS default route remains")
				}
			}
		}
	}
	return nil
}

// Identity checks require an exclusive administrator-enforced network namespace
// lease. Subprocess ip operations cannot make check-and-mutate atomic against
// another CAP_NET_ADMIN actor; deployment must not permit competing writers.
func (o *UniVPNCommandNetworkOps) guard(ctx context.Context, c UniVPNNetworkConfig) error {
	if err := o.lease.AssertHeld(ctx, c); err != nil {
		return err
	}
	links, e := o.links(ctx)
	if e != nil {
		return e
	}
	for _, l := range links {
		if l.Name == c.Interface && l.Index == c.Index && l.Alias == c.Alias && l.Info.Kind == "tun" {
			return nil
		}
	}
	return errors.New("owned TUN identity changed")
}

type uniVPNResolvedValues struct {
	index  int
	name   string
	values []string
}

func (o *UniVPNCommandNetworkOps) resolverValues(ctx context.Context, command string) ([]uniVPNResolvedValues, error) {
	b, e := o.dnsRun(ctx, command)
	if e != nil {
		return nil, e
	}
	var records []uniVPNResolvedValues
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		head, tail, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("unknown resolver output")
		}
		r := uniVPNResolvedValues{}
		if head != "Global" {
			parts := strings.Fields(head)
			if len(parts) != 3 || parts[0] != "Link" || !strings.HasPrefix(parts[2], "(") || !strings.HasSuffix(parts[2], ")") {
				return nil, errors.New("unknown resolver link")
			}
			r.index, e = strconv.Atoi(parts[1])
			if e != nil || r.index <= 0 {
				return nil, errors.New("invalid resolver index")
			}
			r.name = strings.TrimSuffix(strings.TrimPrefix(parts[2], "("), ")")
		}
		r.values = strings.Fields(tail)
		records = append(records, r)
	}
	return records, nil
}

// ProveUncreatedSession is only valid with the native no-network attestation:
// no TUN acquisition succeeded, no config reached the controller, and all native
// descendants are gone. Therefore there can be no session route/resolver writes.
// Still query the kernel rather than accepting the attestation alone.
func (o *UniVPNCommandNetworkOps) ProveUncreatedSession(ctx context.Context, alias string) error {
	if len(alias) != len("meridian-")+32 || !strings.HasPrefix(alias, "meridian-") {
		return errors.New("invalid native session alias")
	}
	for _, r := range strings.TrimPrefix(alias, "meridian-") {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return errors.New("invalid native session alias")
		}
	}
	links, err := o.links(ctx)
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.Alias == alias {
			return errors.New("unexpected native session interface")
		}
	}
	return nil
}
