package packetrelay

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func policy(t *testing.T) *Policy {
	t.Helper()
	p, e := NewPolicy(Config{AssignedIPv4: netip.MustParseAddr("10.8.0.2"), RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, Resolvers: []netip.Addr{netip.MustParseAddr("10.20.0.53")}, AllowTCP: true, AllowUDP: true, AllowICMPEcho: true, MaxPacketSize: 1500})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func fixSum(b []byte, offset int) {
	b[offset] = 0
	b[offset+1] = 0
	s := sum(b)
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	binary.BigEndian.PutUint16(b[offset:offset+2], ^uint16(s))
}
func packet(proto byte, src, dst string) []byte {
	n := 8
	if proto == 6 {
		n = 20
	}
	b := make([]byte, 20+n)
	b[0] = 0x45
	b[8] = 64
	b[9] = proto
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	body := b[20:]
	switch proto {
	case 1:
		body[0] = 8
		fixSum(body, 2)
	case 17:
		binary.BigEndian.PutUint16(body[0:2], 1234)
		binary.BigEndian.PutUint16(body[2:4], 443)
		binary.BigEndian.PutUint16(body[4:6], uint16(n))
	case 6:
		binary.BigEndian.PutUint16(body[0:2], 1234)
		binary.BigEndian.PutUint16(body[2:4], 443)
		body[12] = 0x50
		body[13] = 2
		transportSum(b, 16)
	}
	fixSum(b[:20], 10)
	return b
}
func transportSum(b []byte, offset int) {
	body := b[20:]
	body[offset] = 0
	body[offset+1] = 0
	s := sum(b[12:20]) + uint32(b[9]) + uint32(len(body)) + sum(body)
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	binary.BigEndian.PutUint16(body[offset:offset+2], ^uint16(s))
}
func TestValidProtocolsBothDirections(t *testing.T) {
	p := policy(t)
	for _, proto := range []byte{1, 6, 17} {
		for _, d := range []Direction{Outbound, Inbound} {
			src, dst := "10.8.0.2", "10.20.0.10"
			if d == Inbound {
				src, dst = dst, src
			}
			b := packet(proto, src, dst)
			if e := p.Validate(b, d); e != nil {
				t.Fatalf("protocol %d direction %d: %v", proto, d, e)
			}
		}
	}
}
func TestRejections(t *testing.T) {
	p := policy(t)
	tests := map[string]func([]byte) []byte{
		"ipv6": func(b []byte) []byte { b[0] = 0x65; return b }, "options": func(b []byte) []byte { b[0] = 0x46; return b }, "ttl": func(b []byte) []byte { b[8] = 0; return b }, "checksum": func(b []byte) []byte { b[10] ^= 1; return b }, "trailing": func(b []byte) []byte { return append(b, 0) }, "short": func(b []byte) []byte { return b[:19] }, "fragment": func(b []byte) []byte { b[6] = 0x20; return b }, "offset": func(b []byte) []byte { b[7] = 1; return b }, "reserved": func(b []byte) []byte { b[6] = 0x80; return b }, "protocol": func(b []byte) []byte { b[9] = 47; return b }, "spoof": func(b []byte) []byte { b[15] = 3; return b }, "outside": func(b []byte) []byte { b[18] = 1; return b }, "broadcast": func(b []byte) []byte { b[19] = 255; return b }, "network": func(b []byte) []byte { b[19] = 0; return b }, "multicast": func(b []byte) []byte { b[16] = 224; return b }, "udp-length": func(b []byte) []byte { b[25] = 7; return b }, "zero-port": func(b []byte) []byte { b[20] = 0; b[21] = 0; return b }, "dns": func(b []byte) []byte { binary.BigEndian.PutUint16(b[22:24], 53); return b }, "udp-checksum": func(b []byte) []byte { b[26] = 1; return b }}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			b := mut(packet(17, "10.8.0.2", "10.20.0.10"))
			if len(b) >= 20 && name != "checksum" {
				fixSum(b[:20], 10)
			}
			if p.Validate(b, Outbound) == nil {
				t.Fatal("accepted")
			}
		})
	}
	if p.Validate(packet(17, "10.20.0.10", "10.8.0.3"), Inbound) == nil {
		t.Fatal("spoofed inbound destination")
	}
}
func TestDNSAndTransport(t *testing.T) {
	p := policy(t)
	for _, d := range []Direction{Outbound, Inbound} {
		s, r := "10.8.0.2", "10.20.0.53"
		if d == Inbound {
			s, r = r, s
		}
		b := packet(17, s, r)
		off := 22
		if d == Inbound {
			off = 20
		}
		binary.BigEndian.PutUint16(b[off:off+2], 53)
		transportSum(b, 6)
		if p.Validate(b, d) != nil {
			t.Fatal("valid resolver packet rejected")
		}
		b[27] ^= 1
		if p.Validate(b, d) == nil {
			t.Fatal("bad checksum accepted")
		}
	}
	b := packet(1, "10.8.0.2", "10.20.0.10")
	b[20] = 5
	fixSum(b[20:], 2)
	if p.Validate(b, Outbound) == nil {
		t.Fatal("ICMP redirect accepted")
	}
	b = packet(6, "10.8.0.2", "10.20.0.10")
	b[32] = 0x40
	transportSum(b, 16)
	if p.Validate(b, Outbound) == nil {
		t.Fatal("short TCP header accepted")
	}
}
func TestConfigCopiedAndDefaultDeny(t *testing.T) {
	c := Config{AssignedIPv4: netip.MustParseAddr("10.8.0.2"), RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, MaxPacketSize: 1500}
	p, e := NewPolicy(c)
	if e != nil {
		t.Fatal(e)
	}
	if p.Validate(packet(17, "10.8.0.2", "10.20.0.10"), Outbound) == nil {
		t.Fatal("default allowed traffic")
	}
	c.AllowUDP = true
	p, e = NewPolicy(c)
	if e != nil {
		t.Fatal(e)
	}
	c.RemotePrefixes[0] = netip.MustParsePrefix("0.0.0.0/0")
	if p.Validate(packet(17, "10.8.0.2", "8.8.8.8"), Outbound) == nil {
		t.Fatal("policy mutated")
	}
	if _, e = NewPolicy(Config{}); e == nil {
		t.Fatal("empty configuration accepted")
	}
}

func TestDFAndTCPChecksum(t *testing.T) {
	p := policy(t)
	b := packet(6, "10.8.0.2", "10.20.0.10")
	b[6] = 0x40
	fixSum(b[:20], 10)
	if p.Validate(b, Outbound) != nil {
		t.Fatal("DF rejected")
	}
	b[39] ^= 1
	if p.Validate(b, Outbound) == nil {
		t.Fatal("invalid TCP checksum accepted")
	}
}
func TestSpecialRemoteAddresses(t *testing.T) {
	p, e := NewPolicy(Config{AssignedIPv4: netip.MustParseAddr("10.8.0.2"), RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, MaxPacketSize: 1500, AllowUDP: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range []string{"0.0.0.0", "0.1.2.3", "127.0.0.1", "169.254.1.2", "224.0.0.1", "240.0.0.1", "255.255.255.255"} {
		if p.Validate(packet(17, "10.8.0.2", a), Outbound) == nil {
			t.Fatalf("accepted %s", a)
		}
	}
}
func FuzzValidateNeverPanics(f *testing.F) {
	p, _ := NewPolicy(Config{AssignedIPv4: netip.MustParseAddr("10.8.0.2"), RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, MaxPacketSize: 1500, AllowTCP: true, AllowUDP: true, AllowICMPEcho: true})
	f.Add(packet(17, "10.8.0.2", "10.20.0.10"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _ = p.Validate(b, Outbound); _ = p.Validate(b, Inbound) })
}
