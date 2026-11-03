//go:build linux

package nmvpn

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

func configFixture() (Offer, Policy) {
	o := Offer{
		Session: "0123456789abcdef0123456789abcdef",
		Interface: "meridian0",
		Address: netip.MustParsePrefix("10.20.30.7/24"),
		Endpoint: netip.MustParseAddr("192.0.2.1"),
		Routes: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
	}
	p := Policy{Addresses: []netip.Prefix{o.Address}, Endpoints: []netip.Addr{o.Endpoint}, Routes: append([]netip.Prefix(nil), o.Routes...)}
	return o, p
}

func TestEncodeNetworkManagerSignaturesAndByteOrder(t *testing.T) {
	o, p := configFixture()
	got, err := Encode(o, p)
	if err != nil { t.Fatal(err) }
	if len(got.General) != 5 || len(got.IPv4) != 4 { t.Fatal("unexpected configuration keys") }
	for _, dict := range []map[string]dbus.Variant{got.General, got.IPv4} {
		if dbus.SignatureOf(dict).String() != "a{sv}" { t.Fatal("wrong dictionary signature") }
	}
	for key, sig := range map[string]string{"tundev":"s", "gateway":"u", "has-ip4":"b", "has-ip6":"b", "can-persist":"b"} {
		if got.General[key].Signature().String() != sig { t.Fatalf("wrong general signature for %s", key) }
	}
	for key, sig := range map[string]string{"address":"u", "prefix":"u", "routes":"aau", "never-default":"b"} {
		if got.IPv4[key].Signature().String() != sig { t.Fatalf("wrong IPv4 signature for %s", key) }
	}
	assertIP := func(v uint32, want [4]byte) {
		t.Helper()
		var raw [4]byte
		binary.NativeEndian.PutUint32(raw[:], v)
		if raw != want { t.Fatalf("network-order memory = %v, want %v", raw, want) }
	}
	assertIP(got.General["gateway"].Value().(uint32), [4]byte{192,0,2,1})
	assertIP(got.IPv4["address"].Value().(uint32), [4]byte{10,20,30,7})
	routes := got.IPv4["routes"].Value().([][]uint32)
	if len(routes) != 1 || len(routes[0]) != 4 { t.Fatal("wrong route tuple") }
	assertIP(routes[0][0], [4]byte{10,50,0,0})
	if !reflect.DeepEqual(routes[0][1:], []uint32{16,0,0}) { t.Fatal("prefix, next hop or metric changed") }
	if got.IPv4["prefix"].Value() != uint32(24) || got.IPv4["never-default"].Value() != true || got.General["has-ip6"].Value() != false || got.General["can-persist"].Value() != false { t.Fatal("unexpected routing flags") }
	// Encoded maps/slices are owned by the result, not shared across invocations.
	routes[0][0] = 0
	again, err := Encode(o,p)
	if err != nil || again.IPv4["routes"].Value().([][]uint32)[0][0] == 0 { t.Fatal("aliased output", err) }
}

func TestEncodeRejectsUnapprovedOrUnsupportedOffers(t *testing.T) {
	tests := map[string]func(*Offer,*Policy){
		"bad session": func(o *Offer,p *Policy){o.Session="reuse"},
		"bad interface": func(o *Offer,p *Policy){o.Interface="../../eth0"},
		"long interface": func(o *Offer,p *Policy){o.Interface="meridian012345678"},
		"loopback interface": func(o *Offer,p *Policy){o.Interface="lo"},
		"invalid address": func(o *Offer,p *Policy){o.Address=netip.Prefix{}},
		"IPv6 address": func(o *Offer,p *Policy){o.Address=netip.MustParsePrefix("fd00::1/64");p.Addresses=[]netip.Prefix{o.Address}},
		"zero prefix": func(o *Offer,p *Policy){o.Address=netip.MustParsePrefix("10.0.0.1/0");p.Addresses=[]netip.Prefix{o.Address}},
		"unapproved address": func(o *Offer,p *Policy){p.Addresses=nil},
		"unapproved endpoint": func(o *Offer,p *Policy){p.Endpoints=nil},
		"unspecified endpoint": func(o *Offer,p *Policy){o.Endpoint=netip.MustParseAddr("0.0.0.0");p.Endpoints=[]netip.Addr{o.Endpoint}},
		"loopback endpoint": func(o *Offer,p *Policy){o.Endpoint=netip.MustParseAddr("127.0.0.1");p.Endpoints=[]netip.Addr{o.Endpoint}},
		"multicast endpoint": func(o *Offer,p *Policy){o.Endpoint=netip.MustParseAddr("224.0.0.1");p.Endpoints=[]netip.Addr{o.Endpoint}},
		"linklocal endpoint": func(o *Offer,p *Policy){o.Endpoint=netip.MustParseAddr("169.254.1.1");p.Endpoints=[]netip.Addr{o.Endpoint}},
		"IPv6 endpoint": func(o *Offer,p *Policy){o.Endpoint=netip.MustParseAddr("2001:db8::1");p.Endpoints=[]netip.Addr{o.Endpoint}},
		"mapped IPv4": func(o *Offer,p *Policy){o.Endpoint=netip.MustParseAddr("::ffff:192.0.2.1");p.Endpoints=[]netip.Addr{o.Endpoint}},
		"endpoint in connected prefix": func(o *Offer,p *Policy){o.Endpoint=netip.MustParseAddr("10.20.30.8");p.Endpoints=[]netip.Addr{o.Endpoint}},
		"DNS": func(o *Offer,p *Policy){o.DNS=[]netip.Addr{netip.MustParseAddr("10.0.0.53")}},
		"domains": func(o *Offer,p *Policy){o.Domains=[]string{"internal.example"}},
		"unapproved route": func(o *Offer,p *Policy){p.Routes=nil},
		"invalid route": func(o *Offer,p *Policy){o.Routes=[]netip.Prefix{{}};p.Routes=o.Routes},
		"IPv6 route": func(o *Offer,p *Policy){o.Routes=[]netip.Prefix{netip.MustParsePrefix("fd00::/64")};p.Routes=o.Routes},
		"unmasked route": func(o *Offer,p *Policy){o.Routes=[]netip.Prefix{netip.MustParsePrefix("10.50.0.1/16")};p.Routes=o.Routes},
		"default route": func(o *Offer,p *Policy){o.Routes=[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")};p.Routes=o.Routes},
		"endpoint route": func(o *Offer,p *Policy){o.Routes=[]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")};p.Routes=o.Routes},
		"duplicate route": func(o *Offer,p *Policy){o.Routes=append(o.Routes,o.Routes[0])},
		"route limit": func(o *Offer,p *Policy){o.Routes=make([]netip.Prefix,129)},
	}
	for name, change := range tests { t.Run(name,func(t *testing.T){
		o,p:=configFixture();change(&o,&p)
		got,err:=Encode(o,p)
		if err==nil || got.General!=nil || got.IPv4!=nil {t.Fatal("accepted rejected offer or returned partial payload")}
	}) }
}

func TestEncodeNoRoutesHasTypedEmptyArray(t *testing.T) {
	o,p:=configFixture();o.Routes=nil
	got,err:=Encode(o,p)
	if err!=nil {t.Fatal(err)}
	v:=got.IPv4["routes"]
	if v.Signature().String()!="aau" || len(v.Value().([][]uint32))!=0 {t.Fatal("untyped empty route array")}
}
