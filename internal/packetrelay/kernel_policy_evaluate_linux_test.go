//go:build linux

package packetrelay

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func kernelDeltaFixture() (KernelPolicyObservation, KernelPolicyObservation, KernelIPv4DeltaPolicy) {
	p := KernelIPv4DeltaPolicy{InterfaceIndex: 9, InterfaceName: "meridian0", Address: netip.MustParsePrefix("198.18.0.2/30"), Endpoints: []netip.Addr{netip.MustParseAddr("203.0.113.5")}, Routes: []KernelIPv4Route{
		{Destination: netip.MustParsePrefix("198.18.0.2/32"), Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_LOCAL, Scope: unix.RT_SCOPE_HOST, Protocol: unix.RTPROT_KERNEL, PreferredSource: true},
		{Destination: netip.MustParsePrefix("198.18.0.0/30"), Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Scope: unix.RT_SCOPE_LINK, Protocol: unix.RTPROT_KERNEL, PreferredSource: true},
		{Destination: netip.MustParsePrefix("198.19.0.0/24"), Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Scope: unix.RT_SCOPE_LINK, Protocol: unix.RTPROT_STATIC, Priority: 50},
		{Destination: netip.MustParsePrefix("198.18.0.3/32"), Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_BROADCAST, Scope: unix.RT_SCOPE_LINK, Protocol: unix.RTPROT_KERNEL, PreferredSource: true},
	}}
	base := make([]byte, 12)
	base[0] = unix.AF_INET
	base = append(base, kernelTestAttr(99, []byte{1, 2, 3, 4})...) // preserved, not approved
	before := KernelPolicyObservation{Namespace: KernelNamespaceIdentity{Device: 1, Inode: 2}, Records: []KernelPolicyRecord{{Type: unix.RTM_NEWRULE, Data: base}}}
	after := KernelPolicyObservation{Namespace: before.Namespace, Records: []KernelPolicyRecord{{Type: unix.RTM_NEWRULE, Data: append([]byte(nil), base...)}}}
	a := make([]byte, 8)
	a[0], a[1], a[2] = unix.AF_INET, byte(p.Address.Bits()), unix.IFA_F_PERMANENT
	binary.NativeEndian.PutUint32(a[4:], p.InterfaceIndex)
	ip := p.Address.Addr().As4()
	a = append(a, kernelTestAttr(unix.IFA_LOCAL, ip[:])...)
	a = append(a, kernelTestAttr(unix.IFA_ADDRESS, ip[:])...)
	a = append(a, kernelTestAttr(unix.IFA_LABEL, []byte(p.InterfaceName+"\x00"))...)
	after.Records = append(after.Records, KernelPolicyRecord{Type: unix.RTM_NEWADDR, Data: a})
	for _, r := range p.Routes {
		after.Records = append(after.Records, kernelDeltaRouteFixture(r, p))
	}
	return before, after, p
}

func kernelDeltaRouteFixture(r KernelIPv4Route, p KernelIPv4DeltaPolicy) KernelPolicyRecord {
	b := make([]byte, 12)
	b[0], b[1], b[4], b[5], b[6], b[7] = unix.AF_INET, byte(r.Destination.Bits()), byte(r.Table), r.Protocol, r.Scope, r.Type
	dst, source := r.Destination.Addr().As4(), p.Address.Addr().As4()
	b = append(b, kernelTestAttr(unix.RTA_DST, dst[:])...)
	b = append(b, kernelTestAttr(unix.RTA_OIF, kernelTestU32(p.InterfaceIndex))...)
	if r.PreferredSource {
		b = append(b, kernelTestAttr(unix.RTA_PREFSRC, source[:])...)
	}
	b = append(b, kernelTestAttr(unix.RTA_TABLE, kernelTestU32(r.Table))...)
	b = append(b, kernelTestAttr(unix.RTA_PRIORITY, kernelTestU32(r.Priority))...)
	return KernelPolicyRecord{Type: unix.RTM_NEWROUTE, Data: b}
}

func TestKernelPolicyDeltaExactAdditions(t *testing.T) {
	before, after, p := kernelDeltaFixture()
	if err := EvaluateKernelIPv4Delta(before, after, p); err != nil {
		t.Fatal(err)
	}
	// Netlink enumeration order is not a policy change.
	for i, j := 0, len(after.Records)-1; i < j; i, j = i+1, j-1 {
		after.Records[i], after.Records[j] = after.Records[j], after.Records[i]
	}
	if err := EvaluateKernelIPv4Delta(before, after, p); err != nil {
		t.Fatal("record order rejected", err)
	}
}

func TestKernelPolicyDeltaRejectsUnexpectedChanges(t *testing.T) {
	cases := map[string]func(*KernelPolicyObservation, *KernelPolicyObservation, *KernelIPv4DeltaPolicy){
		"baseline target address": func(b, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			r := KernelPolicyRecord{Type: unix.RTM_NEWADDR, Data: append([]byte(nil), a.Records[1].Data...)}
			r.Data[15]++
			b.Records = append(b.Records, r)
			a.Records = append(a.Records, r)
		},
		"baseline target route": func(b, a *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) {
			route := p.Routes[2]
			route.Destination = netip.MustParsePrefix("198.20.0.0/24")
			r := kernelDeltaRouteFixture(route, *p)
			b.Records = append(b.Records, r)
			a.Records = append(a.Records, r)
		},
		"namespace":                     func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Namespace.Inode++ },
		"baseline removal":              func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records = a.Records[1:] },
		"baseline changed unknown attr": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records[0].Data[16]++ },
		"missing address": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records = append(a.Records[:1], a.Records[2:]...)
		},
		"missing route": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records = a.Records[:len(a.Records)-1]
		},
		"duplicate route": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records = append(a.Records, a.Records[2])
		},
		"duplicate baseline": func(b, _ *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			b.Records = append(b.Records, b.Records[0])
		},
		"new rule": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			d := append([]byte(nil), a.Records[0].Data...)
			d[4]++
			a.Records = append(a.Records, KernelPolicyRecord{Type: unix.RTM_NEWRULE, Data: d})
		},
		"new IPv6":      func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records[1].Data[0] = unix.AF_INET6 },
		"address index": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records[1].Data[4]++ },
		"address flag": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[1].Data[2] |= unix.IFA_F_SECONDARY
		},
		"address scope": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[1].Data[3] = unix.RT_SCOPE_HOST
		},
		"address peer": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records[1].Data[23]++ },
		"address extra attr": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[1].Data = append(a.Records[1].Data, kernelTestAttr(999, []byte{1})...)
		},
		"route scope": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[3].Data[6] = unix.RT_SCOPE_UNIVERSE
		},
		"route flag":            func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records[3].Data[8] = 1 },
		"route TOS":             func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records[3].Data[3] = 1 },
		"route source selector": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { a.Records[3].Data[2] = 24 },
		"route priority":        func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) { d := a.Records[4].Data; d[len(d)-4]++ },
		"route table mismatch": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[3].Data[4] = unix.RT_TABLE_LOCAL
		},
		"route unknown attr": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[3].Data = append(a.Records[3].Data, kernelTestAttr(999, []byte{1})...)
		},
		"route gateway": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[3].Data = append(a.Records[3].Data, kernelTestAttr(unix.RTA_GATEWAY, []byte{198, 18, 0, 1})...)
		},
		"duplicate attribute": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[3].Data = append(a.Records[3].Data, kernelTestAttr(unix.RTA_OIF, kernelTestU32(9))...)
		},
		"malformed record": func(_, a *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			a.Records[3].Data = []byte{unix.AF_INET}
		},
		"mixed allowed tuple": func(_, a *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) {
			r := p.Routes[2]
			r.Destination = p.Routes[0].Destination
			a.Records[4] = kernelDeltaRouteFixture(r, *p)
		},
		"default": func(_, _ *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) {
			p.Routes[2].Destination = netip.MustParsePrefix("0.0.0.0/0")
		},
		"endpoint capture": func(_, _ *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) {
			p.Endpoints[0] = netip.MustParseAddr("198.19.0.5")
		},
		"address captures endpoint": func(_, _ *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) {
			p.Endpoints[0] = netip.MustParseAddr("198.18.0.1")
		},
		"duplicate provision": func(_, _ *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) {
			p.Routes = append(p.Routes, p.Routes[0])
		},
		"noncanonical destination": func(_, _ *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) {
			p.Routes[2].Destination = netip.MustParsePrefix("198.19.0.1/24")
		},
		"untrusted route protocol": func(_, _ *KernelPolicyObservation, p *KernelIPv4DeltaPolicy) { p.Routes[2].Protocol = unix.RTPROT_RA },
		"record cap": func(b, _ *KernelPolicyObservation, _ *KernelIPv4DeltaPolicy) {
			b.Records = make([]KernelPolicyRecord, 4097)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b, a, p := kernelDeltaFixture()
			change(&b, &a, &p)
			if EvaluateKernelIPv4Delta(b, a, p) == nil {
				t.Fatal("unprovisioned delta accepted")
			}
		})
	}
}

func TestKernelPolicyDeltaAddressMetadataAndBounds(t *testing.T) {
	for _, mode := range []string{"permanent metadata", "finite preferred", "finite valid", "extended flags", "wrong label", "missing source", "byte cap"} {
		t.Run(mode, func(t *testing.T) {
			b, a, p := kernelDeltaFixture()
			cache := make([]byte, 16)
			binary.NativeEndian.PutUint32(cache, ^uint32(0))
			binary.NativeEndian.PutUint32(cache[4:], ^uint32(0))
			flags := uint32(unix.IFA_F_PERMANENT)
			switch mode {
			case "finite preferred":
				cache[0] = 1
			case "finite valid":
				cache[4] = 1
			case "extended flags":
				flags |= unix.IFA_F_NOPREFIXROUTE
			case "wrong label":
				a.Records[1].Data[len(a.Records[1].Data)-4] = 'x'
			case "missing source":
				// Route layout is header, DST, OIF, PREFSRC, TABLE, PRIORITY.
				d := a.Records[3].Data
				a.Records[3].Data = append(append([]byte(nil), d[:28]...), d[36:]...)
			case "byte cap":
				b.Records = nil
				for i := 0; i < 18; i++ {
					d := make([]byte, 12)
					d[0] = unix.AF_INET
					value := make([]byte, 60000)
					value[0] = byte(i)
					d = append(d, kernelTestAttr(999, value)...)
					b.Records = append(b.Records, KernelPolicyRecord{Type: unix.RTM_NEWRULE, Data: d})
				}
			}
			a.Records[1].Data = append(a.Records[1].Data, kernelTestAttr(unix.IFA_CACHEINFO, cache)...)
			a.Records[1].Data = append(a.Records[1].Data, kernelTestAttr(unix.IFA_FLAGS, kernelTestU32(flags))...)
			err := EvaluateKernelIPv4Delta(b, a, p)
			if (err == nil) != (mode == "permanent metadata") {
				t.Fatal("incorrect metadata/bounds decision", err)
			}
		})
	}
}

func TestKernelPolicyDeltaBroadcastTuples(t *testing.T) {
	for _, mode := range []string{"modern", "older explicit lower", "unapproved lower", "wrong destination", "wrong metric", "wrong table", "wrong scope", "wrong protocol", "prefix31", "prefix32"} {
		t.Run(mode, func(t *testing.T) {
			b, a, p := kernelDeltaFixture()
			r := p.Routes[3]
			switch mode {
			case "older explicit lower", "unapproved lower":
				r.Destination = netip.PrefixFrom(p.Address.Masked().Addr(), 32)
				a.Records = append(a.Records, kernelDeltaRouteFixture(r, p))
				if mode == "older explicit lower" {
					p.Routes = append(p.Routes, r)
				}
			case "wrong destination":
				p.Routes[3].Destination = netip.MustParsePrefix("198.19.0.255/32")
			case "wrong metric":
				p.Routes[3].Priority = 1
			case "wrong table":
				p.Routes[3].Table = unix.RT_TABLE_MAIN
			case "wrong scope":
				p.Routes[3].Scope = unix.RT_SCOPE_HOST
			case "wrong protocol":
				p.Routes[3].Protocol = unix.RTPROT_STATIC
			case "prefix31":
				p.Address = netip.MustParsePrefix("198.18.0.2/31")
			case "prefix32":
				p.Address = netip.MustParsePrefix("198.18.0.2/32")
			}
			if mode != "modern" && mode != "older explicit lower" && mode != "unapproved lower" {
				// Make observed tuples match the invalid provisioning so a
				// tuple mismatch cannot hide a broken policy validator.
				a.Records[5] = kernelDeltaRouteFixture(p.Routes[3], p)
				if mode == "prefix31" || mode == "prefix32" {
					a.Records[1].Data[1] = byte(p.Address.Bits())
					p.Routes[1].Destination = p.Address.Masked()
					a.Records[3] = kernelDeltaRouteFixture(p.Routes[1], p)
				}
				if validKernelDeltaPolicy(p) {
					t.Fatal("invalid broadcast policy admitted")
				}
			}
			err := EvaluateKernelIPv4Delta(b, a, p)
			if (err == nil) != (mode == "modern" || mode == "older explicit lower") {
				t.Fatal("wrong broadcast tuple decision", err)
			}
		})
	}
}

func TestKernelPolicyDeltaPreferredSourcePresence(t *testing.T) {
	for _, mode := range []string{"static absent", "static present", "unexpected present", "unexpected absent", "wrong source", "kernel absent"} {
		t.Run(mode, func(t *testing.T) {
			b, a, p := kernelDeltaFixture()
			switch mode {
			case "static present", "unexpected absent", "wrong source":
				p.Routes[2].PreferredSource = true
			case "kernel absent":
				p.Routes[1].PreferredSource = false
				a.Records[3] = kernelDeltaRouteFixture(p.Routes[1], p)
			}
			if mode == "static present" || mode == "wrong source" {
				a.Records[4] = kernelDeltaRouteFixture(p.Routes[2], p)
			}
			if mode == "unexpected present" {
				r := p.Routes[2]
				r.PreferredSource = true
				a.Records[4] = kernelDeltaRouteFixture(r, p)
			}
			if mode == "wrong source" {
				a.Records[4].Data[35]++
			}
			err := EvaluateKernelIPv4Delta(b, a, p)
			if (err == nil) != (mode == "static absent" || mode == "static present") {
				t.Fatal("source presence/value mismatch accepted", err)
			}
		})
	}
}
