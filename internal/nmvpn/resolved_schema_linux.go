//go:build linux

package nmvpn

import (
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"
)

const resolvedMaxEntries = 256
const resolvedMaxLinks = 256

// This is a closed projection of these properties, not the whole resolver API.
// Missing DNSEx/fallback fields, unfamiliar modes and unsupported wire schemas
// fail; there is no legacy downgrade. Statistics, learned server capabilities,
// current-server selection, positive trust anchors and host files are not
// inferred from this projection. Nonempty delegates are separately rejected.
// https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html
var resolvedManagerFields = []string{
	"DNS", "DNSEx", "FallbackDNS", "FallbackDNSEx", "Domains", "LLMNR",
	"MulticastDNS", "DNSOverTLS", "DNSSEC", "DNSSECSupported",
	"DNSSECNegativeTrustAnchors", "DNSStubListener", "ResolvConfMode",
}

var resolvedLinkFields = []string{
	"DNS", "DNSEx", "Domains", "DefaultRoute", "LLMNR", "MulticastDNS",
	"DNSOverTLS", "DNSSEC", "DNSSECSupported", "DNSSECNegativeTrustAnchors", "ScopesMask",
}

// ResolvedDNSServer preserves the extended property, including its raw port
// (zero means systemd's default) and TLS server name. The legacy property's
// index/address projection must agree exactly before it is accepted.
type ResolvedDNSServer struct {
	LinkIndex  int32
	Address    netip.Addr
	Port       uint16
	ServerName string
}

type ResolvedDomain struct {
	LinkIndex int32
	Name      string
	RouteOnly bool
}

type ResolvedModes struct {
	LLMNR, MulticastDNS, DNSOverTLS, DNSSEC string
	DNSSECSupported                         bool
	NegativeTrustAnchors                    []string
}

type ResolvedManagerSnapshot struct {
	DNS, FallbackDNS                []ResolvedDNSServer
	Domains                         []ResolvedDomain
	Modes                           ResolvedModes
	DNSStubListener, ResolvConfMode string
}

type ResolvedLinkSnapshot struct {
	Index int32
	// Name is from the sampled kernel namespace, not from resolved's API.
	Name         string
	Path         dbus.ObjectPath
	DNS          []ResolvedDNSServer
	Domains      []ResolvedDomain
	Modes        ResolvedModes
	DefaultRoute bool
	ScopesMask   uint64
}

func resolvedPropertyListed(name string, fields []string) bool {
	for _, field := range fields {
		if name == field {
			return true
		}
	}
	return false
}

func resolvedExactProperties(p map[string]dbus.Variant, fields []string) bool {
	if len(p) != len(fields) {
		return false
	}
	for _, name := range fields {
		if _, ok := p[name]; !ok {
			return false
		}
	}
	return true
}

// The privately assembled property set must contain exactly the reviewed schema.
// Production populates it with individual Get results, never wire dictionaries.
// Known telemetry is strictly
// typed but excluded from policy equality; resolver activity alone must not look
// like a configuration change. No unknown added property is silently ignored.
func resolvedPolicyProperties(all map[string]dbus.Variant, manager bool) (map[string]dbus.Variant, error) {
	fields, extra := resolvedLinkFields, 2
	if manager {
		fields, extra = resolvedManagerFields, 6
	}
	if len(all) != len(fields)+extra {
		return nil, errResolvedObservation
	}
	out := make(map[string]dbus.Variant, len(fields))
	for _, field := range fields {
		v, ok := all[field]
		if !ok {
			return nil, errResolvedObservation
		}
		out[field] = v
	}
	if !resolvedCurrentPair(all["CurrentDNSServer"], all["CurrentDNSServerEx"], manager) {
		return nil, errResolvedObservation
	}
	if manager {
		name, ok := all["LLMNRHostname"].Value().(string)
		if !ok || all["LLMNRHostname"].Signature().String() != "s" || !resolvedDomainName(name, false) {
			return nil, errResolvedObservation
		}
		for _, field := range []struct {
			name, signature string
			width           int
		}{
			{"TransactionStatistics", "(tt)", 2}, {"CacheStatistics", "(ttt)", 3}, {"DNSSECStatistics", "(tttt)", 4},
		} {
			v := all[field.name]
			values, ok := v.Value().([]any)
			if !ok || v.Signature().String() != field.signature || len(values) != field.width {
				return nil, errResolvedObservation
			}
			for _, value := range values {
				if _, ok := value.(uint64); !ok {
					return nil, errResolvedObservation
				}
			}
		}
	}
	return out, nil
}

func resolvedCurrentPair(old, extended dbus.Variant, manager bool) bool {
	oldSig, newSig, width, offset := "(iay)", "(iayqs)", 2, 0
	if manager {
		oldSig, newSig, width, offset = "(iiay)", "(iiayqs)", 3, 1
	}
	legacy, ok := old.Value().([]any)
	current, exOK := extended.Value().([]any)
	if !ok || !exOK || old.Signature().String() != oldSig || extended.Signature().String() != newSig || len(legacy) != width || len(current) != width+2 || !reflect.DeepEqual(legacy, current[:width]) {
		return false
	}
	if family, ok := current[offset].(int32); ok && family == syscall.AF_UNSPEC {
		address, a := current[offset+1].([]byte)
		port, p := current[offset+2].(uint16)
		name, n := current[offset+3].(string)
		return a && len(address) == 0 && p && port == 0 && n && name == "" && (!manager || current[0] == int32(0))
	}
	// Use the same strict DNS row validator for an actual selected server.
	_, err := resolvedDNSPair(
		dbus.MakeVariantWithSignature([][]any{legacy}, dbus.ParseSignatureMust("a"+oldSig)),
		dbus.MakeVariantWithSignature([][]any{current}, dbus.ParseSignatureMust("a"+newSig)), 1, manager)
	return err == nil
}

func resolvedLinkPath(index int32) dbus.ObjectPath {
	return dbus.ObjectPath(string(resolvedPath) + "/link/_" + strconv.FormatInt(int64(index), 10))
}

func resolvedValidLinkPath(path dbus.ObjectPath) bool {
	const prefix = "/org/freedesktop/resolve1/link/_"
	if !strings.HasPrefix(string(path), prefix) || len(path) > len(prefix)+10 {
		return false
	}
	index, err := strconv.ParseInt(string(path)[len(prefix):], 10, 32)
	return err == nil && index > 0 && path == resolvedLinkPath(int32(index))
}

func parseResolvedManager(p map[string]dbus.Variant) (ResolvedManagerSnapshot, error) {
	var out ResolvedManagerSnapshot
	if !resolvedExactProperties(p, resolvedManagerFields) {
		return out, errResolvedObservation
	}
	var err error
	if out.DNS, err = resolvedDNSPair(p["DNS"], p["DNSEx"], 0, true); err != nil {
		return ResolvedManagerSnapshot{}, err
	}
	if out.FallbackDNS, err = resolvedDNSPair(p["FallbackDNS"], p["FallbackDNSEx"], 0, true); err != nil {
		return ResolvedManagerSnapshot{}, err
	}
	if out.Domains, err = resolvedDomains(p["Domains"], 0, true); err != nil {
		return ResolvedManagerSnapshot{}, err
	}
	if out.Modes, err = resolvedModes(p); err != nil {
		return ResolvedManagerSnapshot{}, err
	}
	if out.DNSStubListener, err = resolvedMode(p["DNSStubListener"], "yes", "no", "udp", "tcp"); err != nil {
		return ResolvedManagerSnapshot{}, err
	}
	if out.ResolvConfMode, err = resolvedMode(p["ResolvConfMode"], "uplink", "stub", "static", "foreign", "missing"); err != nil {
		return ResolvedManagerSnapshot{}, err
	}
	return out, nil
}

func parseResolvedLink(p map[string]dbus.Variant, index int32, path dbus.ObjectPath) (ResolvedLinkSnapshot, error) {
	var out ResolvedLinkSnapshot
	if index <= 0 || path != resolvedLinkPath(index) || !resolvedExactProperties(p, resolvedLinkFields) {
		return out, errResolvedObservation
	}
	var err error
	if out.DNS, err = resolvedDNSPair(p["DNS"], p["DNSEx"], index, false); err != nil {
		return ResolvedLinkSnapshot{}, err
	}
	if out.Domains, err = resolvedDomains(p["Domains"], index, false); err != nil {
		return ResolvedLinkSnapshot{}, err
	}
	if out.Modes, err = resolvedModes(p); err != nil {
		return ResolvedLinkSnapshot{}, err
	}
	var ok bool
	if out.DefaultRoute, ok = p["DefaultRoute"].Value().(bool); !ok || p["DefaultRoute"].Signature().String() != "b" {
		return ResolvedLinkSnapshot{}, errResolvedObservation
	}
	if out.ScopesMask, ok = p["ScopesMask"].Value().(uint64); !ok || p["ScopesMask"].Signature().String() != "t" || out.ScopesMask & ^uint64(31) != 0 {
		return ResolvedLinkSnapshot{}, errResolvedObservation
	}
	out.Index, out.Path = index, path
	return out, nil
}

func resolvedMode(v dbus.Variant, allowed ...string) (string, error) {
	s, ok := v.Value().(string)
	if !ok || v.Signature().String() != "s" {
		return "", errResolvedObservation
	}
	for _, mode := range allowed {
		if s == mode {
			return s, nil
		}
	}
	return "", errResolvedObservation
}

func resolvedModes(p map[string]dbus.Variant) (ResolvedModes, error) {
	var out ResolvedModes
	var err error
	if out.LLMNR, err = resolvedMode(p["LLMNR"], "yes", "no", "resolve"); err != nil {
		return ResolvedModes{}, err
	}
	if out.MulticastDNS, err = resolvedMode(p["MulticastDNS"], "yes", "no", "resolve"); err != nil {
		return ResolvedModes{}, err
	}
	if out.DNSOverTLS, err = resolvedMode(p["DNSOverTLS"], "yes", "no", "opportunistic"); err != nil {
		return ResolvedModes{}, err
	}
	if out.DNSSEC, err = resolvedMode(p["DNSSEC"], "yes", "no", "allow-downgrade"); err != nil {
		return ResolvedModes{}, err
	}
	var ok bool
	if out.DNSSECSupported, ok = p["DNSSECSupported"].Value().(bool); !ok || p["DNSSECSupported"].Signature().String() != "b" {
		return ResolvedModes{}, errResolvedObservation
	}
	anchors, ok := p["DNSSECNegativeTrustAnchors"].Value().([]string)
	if !ok || p["DNSSECNegativeTrustAnchors"].Signature().String() != "as" || len(anchors) > resolvedMaxEntries {
		return ResolvedModes{}, errResolvedObservation
	}
	seen := make(map[string]bool, len(anchors))
	for _, anchor := range anchors {
		if !resolvedDomainName(anchor, true) || seen[strings.ToLower(anchor)] {
			return ResolvedModes{}, errResolvedObservation
		}
		seen[strings.ToLower(anchor)] = true
		out.NegativeTrustAnchors = append(out.NegativeTrustAnchors, anchor)
	}
	// NTAs are a set; search-domain and DNS preference order is not sorted.
	sort.Strings(out.NegativeTrustAnchors)
	return out, nil
}

func resolvedTuples(v dbus.Variant, signature string, width int) ([][]any, error) {
	rows, ok := v.Value().([][]any) // godbus's decoded D-Bus struct representation
	if !ok || v.Signature().String() != signature || len(rows) > resolvedMaxEntries {
		return nil, errResolvedObservation
	}
	for _, row := range rows {
		if len(row) != width {
			return nil, errResolvedObservation
		}
	}
	return rows, nil
}

func resolvedDNSPair(legacy, extended dbus.Variant, index int32, manager bool) ([]ResolvedDNSServer, error) {
	oldSignature, newSignature, oldWidth, newWidth := "a(iay)", "a(iayqs)", 2, 4
	if manager {
		oldSignature, newSignature, oldWidth, newWidth = "a(iiay)", "a(iiayqs)", 3, 5
	}
	oldRows, err := resolvedTuples(legacy, oldSignature, oldWidth)
	if err != nil {
		return nil, err
	}
	newRows, err := resolvedTuples(extended, newSignature, newWidth)
	if err != nil || len(oldRows) != len(newRows) {
		return nil, errResolvedObservation
	}
	out := make([]ResolvedDNSServer, 0, len(newRows))
	seen := make(map[ResolvedDNSServer]bool, len(newRows))
	for i, row := range newRows {
		// Compare the typed legacy prefix before decoding. This forbids both
		// lossy casts and a different ordering between DNS and DNSEx.
		if !reflect.DeepEqual(oldRows[i], row[:oldWidth]) {
			return nil, errResolvedObservation
		}
		offset := 0
		if manager {
			var ok bool
			index, ok = row[0].(int32)
			if !ok || index < 0 {
				return nil, errResolvedObservation
			}
			offset = 1
		}
		family, familyOK := row[offset].(int32)
		bytes, bytesOK := row[offset+1].([]byte)
		port, portOK := row[offset+2].(uint16)
		name, nameOK := row[offset+3].(string)
		if !familyOK || !bytesOK || !portOK || !nameOK || (name != "" && !resolvedDomainName(name, false)) {
			return nil, errResolvedObservation
		}
		if (family != syscall.AF_INET || len(bytes) != 4) && (family != syscall.AF_INET6 || len(bytes) != 16) {
			return nil, errResolvedObservation
		}
		address, ok := netip.AddrFromSlice(bytes)
		if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || (address.Is6() && address.IsLinkLocalUnicast() && index == 0) {
			return nil, errResolvedObservation
		}
		server := ResolvedDNSServer{LinkIndex: index, Address: address, Port: port, ServerName: name}
		if seen[server] {
			return nil, errResolvedObservation
		}
		seen[server] = true
		out = append(out, server)
	}
	return out, nil
}

func resolvedDomains(v dbus.Variant, index int32, manager bool) ([]ResolvedDomain, error) {
	signature, width := "a(sb)", 2
	if manager {
		signature, width = "a(isb)", 3
	}
	rows, err := resolvedTuples(v, signature, width)
	if err != nil {
		return nil, err
	}
	out := make([]ResolvedDomain, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		offset := 0
		if manager {
			var ok bool
			index, ok = row[0].(int32)
			if !ok || index < 0 {
				return nil, errResolvedObservation
			}
			offset = 1
		}
		name, nameOK := row[offset].(string)
		routeOnly, routeOK := row[offset+1].(bool)
		if !nameOK || !routeOK || !resolvedDomainName(name, true) || (name == "." && !routeOnly) {
			return nil, errResolvedObservation
		}
		key := strconv.FormatInt(int64(index), 10) + ":" + strings.ToLower(name)
		if seen[key] {
			return nil, errResolvedObservation
		}
		seen[key] = true
		out = append(out, ResolvedDomain{LinkIndex: index, Name: name, RouteOnly: routeOnly})
	}
	return out, nil
}

// Only plain ASCII DNS names are supported. Escaped/IDN/binary labels require
// a separately reviewed schema; they are never silently trimmed or normalized.
func resolvedDomainName(name string, root bool) bool {
	if root && name == "." {
		return true
	}
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
