package macosvpn

import (
	"bytes"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const maxDNSReadbackBytes = 256 << 10

var ErrDNSReadback = errors.New("系统解析器读回不可用或格式不受支持")

// DNSResolverRecord describes scutil's consolidated resolver configuration,
// independently of the selected service dictionary. It does not prove the
// resolver actually used for any query, encrypted DNS or per-app DNS behavior.
type DNSResolverRecord struct {
	Scope                                               string
	Domain                                              string
	SearchDomains                                       []string
	Nameservers                                         []netip.Addr
	InterfaceIndex                                      uint32
	InterfaceName                                       string
	Order, Port, Timeout, ServiceIdentifier, ReachFlags uint32
	Flags                                               []string
	Options                                             string
}
type DNSReadback struct {
	Resolvers            []DNSResolverRecord
	QueryRoutingVerified bool // Always false: configuration is not query provenance.
}

var dnsIndex = regexp.MustCompile(`^(nameserver|search domain)\[([0-9]+)\]$`)
var dnsInterface = regexp.MustCompile(`^([1-9][0-9]{0,9}) \(([A-Za-z0-9_.?-]{1,15})\)$`)
var dnsReach = regexp.MustCompile(`^0x([0-9a-fA-F]{8})( \([A-Za-z, ]+\))?$`)

func dnsDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
func dnsUint(s string) (uint32, error) {
	n, e := strconv.ParseUint(s, 10, 32)
	if e != nil {
		return 0, ErrDNSReadback
	}
	return uint32(n), nil
}

// parseDNSReadback accepts a bounded documented scutil --dns subset. Unknown,
// duplicate, malformed or unrecognized fields fail closed, never silently drop.
func parseDNSReadback(data []byte) (DNSReadback, error) {
	var out DNSReadback
	fail := func() (DNSReadback, error) { return DNSReadback{}, ErrDNSReadback }
	if len(data) == 0 || len(data) > maxDNSReadbackBytes || bytes.IndexByte(data, 0) >= 0 {
		return fail()
	}
	for _, b := range data {
		if (b < 32 && b != '\n' && b != '\r' && b != '\t') || b > 126 {
			return fail()
		}
	}
	scope := ""
	section := 0
	number := 0
	var current *DNSResolverRecord
	seen := map[string]bool{}
	complete := func() bool {
		if current == nil {
			return true
		}
		if !seen["flags"] || !seen["reach"] {
			return false
		}
		scoped := slices.Contains(current.Flags, "Scoped")
		service := slices.Contains(current.Flags, "Service-specific")
		if scoped != (current.Scope == "scoped") || service != (current.Scope == "service-specific") {
			return false
		}
		return (!scoped || current.InterfaceIndex != 0) && (!service || current.ServiceIdentifier != 0)
	}
	for _, raw := range strings.Split(string(data), "\n") {
		if len(raw) > 2048 {
			return fail()
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		next := 0
		switch line {
		case "DNS configuration":
			next = 1
		case "DNS configuration (for scoped queries)":
			next = 2
		case "DNS configuration (for service-specific queries)":
			next = 3
		}
		if next != 0 {
			if !complete() {
				return fail()
			}
			if next <= section || (section == 0 && next != 1) {
				return fail()
			}
			section = next
			scope = []string{"", "default", "scoped", "service-specific"}[next]
			number = 0
			current = nil
			continue
		}
		if strings.HasPrefix(line, "resolver #") {
			if !complete() {
				return fail()
			}
			n, e := strconv.Atoi(strings.TrimPrefix(line, "resolver #"))
			if e != nil || n != number+1 || scope == "" || len(out.Resolvers) >= 128 {
				return fail()
			}
			number = n
			out.Resolvers = append(out.Resolvers, DNSResolverRecord{Scope: scope})
			current = &out.Resolvers[len(out.Resolvers)-1]
			seen = map[string]bool{}
			continue
		}
		if current == nil {
			return fail()
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return fail()
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if seen[key] {
			return fail()
		}
		seen[key] = true
		if match := dnsIndex.FindStringSubmatch(key); match != nil {
			n, e := strconv.Atoi(match[2])
			if e != nil || n >= 16 {
				return fail()
			}
			if match[1] == "nameserver" {
				ip, e := netip.ParseAddr(value)
				if e != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || n != len(current.Nameservers) {
					return fail()
				}
				current.Nameservers = append(current.Nameservers, ip)
			} else {
				if !dnsDomain(value) || n != len(current.SearchDomains) {
					return fail()
				}
				current.SearchDomains = append(current.SearchDomains, strings.ToLower(value))
			}
			continue
		}
		switch key {
		case "domain":
			if !dnsDomain(value) {
				return fail()
			}
			current.Domain = strings.ToLower(value)
		case "if_index":
			m := dnsInterface.FindStringSubmatch(value)
			if m == nil {
				return fail()
			}
			n, e := dnsUint(m[1])
			if e != nil {
				return fail()
			}
			current.InterfaceIndex = n
			current.InterfaceName = m[2]
		case "flags":
			if value != "" {
				for _, flag := range strings.Split(value, ", ") {
					switch flag {
					case "Scoped", "Service-specific", "Supplemental", "Request A records", "Request AAAA records":
					default:
						return fail()
					}
					for _, old := range current.Flags {
						if old == flag {
							return fail()
						}
					}
					current.Flags = append(current.Flags, flag)
				}
			}
		case "reach":
			m := dnsReach.FindStringSubmatch(value)
			if m == nil {
				return fail()
			}
			n, e := strconv.ParseUint(m[1], 16, 32)
			if e != nil {
				return fail()
			}
			current.ReachFlags = uint32(n)
		case "order", "port", "timeout", "service_identifier":
			n, e := dnsUint(value)
			if e != nil {
				return fail()
			}
			switch key {
			case "order":
				current.Order = n
			case "port":
				if n == 0 || n > 65535 {
					return fail()
				}
				current.Port = n
			case "timeout":
				current.Timeout = n
			case "service_identifier":
				current.ServiceIdentifier = n
			}
		case "options":
			if value != "mdns" {
				return fail()
			}
			current.Options = value
		default:
			return fail()
		}
	}
	if !complete() || len(out.Resolvers) == 0 {
		return fail()
	}
	for _, r := range out.Resolvers {
		if len(r.Nameservers) == 0 && (r.Options != "mdns" || r.Domain == "") {
			return fail()
		}
	}
	return out, nil
}

type boundedDNSOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *boundedDNSOutput) Write(p []byte) (int, error) {
	if len(p) > maxDNSReadbackBytes-b.Len() {
		b.overflow = true
		return 0, ErrDNSReadback
	}
	return b.buffer.Write(p)
}

func (b *boundedDNSOutput) Len() int      { return b.buffer.Len() }
func (b *boundedDNSOutput) Bytes() []byte { return b.buffer.Bytes() }
