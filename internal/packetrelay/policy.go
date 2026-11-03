// Package packetrelay confines IPv4 packets at the broker boundary. The broker,
// never its native child, owns the host packet device.
package packetrelay

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrRejected = errors.New("packet rejected by broker policy")

// Config must come from separately authorized configuration, not from untrusted
// tunnel metadata. No traffic is enabled by default. DNS is restricted to the
// exact Resolvers (which must also be in RemotePrefixes); this is a packet/port
// restriction, not application inspection, and cannot prevent DNS-over-HTTPS.
// TCP and UDP allow any nonzero port except DNS, controlled separately below.
// ICMPEcho allows only echo request/reply, not redirects or ICMP errors.
// This is stateless filtering, not connection tracking or a host firewall.
type Config struct {
	AssignedIPv4                      netip.Addr
	RemotePrefixes                    []netip.Prefix
	Resolvers                         []netip.Addr
	AllowTCP, AllowUDP, AllowICMPEcho bool
	MaxPacketSize                     int
}

type Policy struct{ cfg Config }
type Direction uint8

const (
	Outbound Direction = iota
	Inbound
)

func unicast(a netip.Addr) bool {
	if !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return false
	}
	b := a.As4()
	return b[0] != 0 && b[0] < 224 && b != [4]byte{255, 255, 255, 255}
}
func NewPolicy(c Config) (*Policy, error) {
	if !unicast(c.AssignedIPv4) || len(c.RemotePrefixes) == 0 || c.MaxPacketSize < 28 || c.MaxPacketSize > 65535 {
		return nil, ErrRejected
	}
	for _, p := range c.RemotePrefixes {
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() {
			return nil, ErrRejected
		}
	}
	c.RemotePrefixes = append([]netip.Prefix(nil), c.RemotePrefixes...)
	c.Resolvers = append([]netip.Addr(nil), c.Resolvers...)
	p := &Policy{cfg: c}
	for _, r := range c.Resolvers {
		if !unicast(r) || !p.remote(r) {
			return nil, ErrRejected
		}
	}
	return p, nil
}
func (p *Policy) remote(a netip.Addr) bool {
	if !unicast(a) {
		return false
	}
	// Reject network/broadcast endpoints of every supplied subnet, even if a
	// broader entry overlaps. /31 and /32 are point-to-point/host routes.
	for _, n := range p.cfg.RemotePrefixes {
		if n.Contains(a) && n.Bits() < 31 {
			x := a.As4()
			base := n.Addr().As4()
			v := binary.BigEndian.Uint32(x[:])
			b := binary.BigEndian.Uint32(base[:])
			mask := uint32(0xffffffff) >> n.Bits()
			if v == b || v == b|mask {
				return false
			}
		}
	}
	for _, n := range p.cfg.RemotePrefixes {
		if n.Contains(a) {
			return true
		}
	}
	return false
}
func sum(b []byte) uint32 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	return s
}
func validSum(s uint32) bool {
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return s == 65535
}

// Validate accepts exactly one complete IPv4 datagram without a TUN PI header.
// IPv6, options, trailing bytes, fragments, reserved flags, TTL zero, spoofed
// endpoints, malformed transport headers and checksums fail closed.
func (p *Policy) Validate(b []byte, d Direction) error {
	if p == nil || (d != Inbound && d != Outbound) || len(b) < 20 || len(b) > p.cfg.MaxPacketSize || b[0] != 0x45 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) || b[8] == 0 || binary.BigEndian.Uint16(b[6:8])&0xbfff != 0 || !validSum(sum(b[:20])) {
		return ErrRejected
	}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	remote := dst
	if d == Outbound {
		if src != p.cfg.AssignedIPv4 {
			return ErrRejected
		}
	} else {
		if dst != p.cfg.AssignedIPv4 {
			return ErrRejected
		}
		remote = src
	}
	if !p.remote(remote) {
		return ErrRejected
	}
	body := b[20:]
	var sport, dport uint16
	switch b[9] {
	case 1:
		if !p.cfg.AllowICMPEcho || len(body) < 8 || (body[0] != 0 && body[0] != 8) || body[1] != 0 || !validSum(sum(body)) {
			return ErrRejected
		}
		return nil
	case 6:
		if !p.cfg.AllowTCP || len(body) < 20 || int(body[12]>>4)*4 < 20 || int(body[12]>>4)*4 > len(body) || body[12]&15 != 0 {
			return ErrRejected
		}
		// Validate TCP options structurally; padding after EOL must be zero.
		opts := body[20 : int(body[12]>>4)*4]
		for len(opts) > 0 {
			if opts[0] == 0 {
				for _, v := range opts {
					if v != 0 {
						return ErrRejected
					}
				}
				break
			}
			if opts[0] == 1 {
				opts = opts[1:]
				continue
			}
			if len(opts) < 2 || opts[1] < 2 || int(opts[1]) > len(opts) {
				return ErrRejected
			}
			opts = opts[int(opts[1]):]
		}
	case 17:
		if !p.cfg.AllowUDP || len(body) < 8 || int(binary.BigEndian.Uint16(body[4:6])) != len(body) {
			return ErrRejected
		}
	default:
		return ErrRejected
	}
	sport = binary.BigEndian.Uint16(body[:2])
	dport = binary.BigEndian.Uint16(body[2:4])
	if sport == 0 || dport == 0 {
		return ErrRejected
	}
	if sport == 53 || dport == 53 {
		found := false
		for _, r := range p.cfg.Resolvers {
			if r == remote {
				found = true
			}
		}
		if !found || (d == Outbound && dport != 53) || (d == Inbound && sport != 53) {
			return ErrRejected
		}
	}
	// UDP zero checksum is legal in IPv4. All nonzero UDP and all TCP checksums
	// must validate against their IPv4 pseudo-header.
	if b[9] != 17 || binary.BigEndian.Uint16(body[6:8]) != 0 {
		if !validSum(sum(b[12:20]) + uint32(b[9]) + uint32(len(body)) + sum(body)) {
			return ErrRejected
		}
	}
	return nil
}
