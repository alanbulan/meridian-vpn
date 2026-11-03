//go:build linux

// Package nmvpn contains an offline-testable NM-owned VPN configuration core.
// It is not a running VPN plugin, host ownership lease, or network acceptance check.
package nmvpn

import (
 "encoding/binary"
 "errors"
 "net/netip"
 "regexp"
 "slices"

 "github.com/godbus/dbus/v5"
)

const PluginPath = dbus.ObjectPath("/org/freedesktop/NetworkManager/VPN/Plugin")
const PluginInterface = "org.freedesktop.NetworkManager.VPN.Plugin"

// Offer must originate from the broker's authenticated, session-bound native
// channel. Interface is broker-assigned, never a gateway-provided device name.
// This first slice deliberately supports IPv4 split routing WITHOUT DNS changes.
type Offer struct {
 Session string
 Interface string
 Address netip.Prefix
 Endpoint netip.Addr
 Routes []netip.Prefix
 DNS []netip.Addr
 Domains []string
}

// Policy is a trusted administrator allowlist; entries match exactly, not by
// containment. No default routes, automatic DNS policy, or IPv6 are inferred.
type Policy struct {
 Addresses []netip.Prefix
 Endpoints []netip.Addr
 Routes []netip.Prefix
}

type Config struct {
 General map[string]dbus.Variant
 IPv4 map[string]dbus.Variant
}

var linkPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)
var sessionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validIP(a netip.Addr) bool {
 return a.Is4() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && a != netip.MustParseAddr("255.255.255.255")
}

// nmIPv4 represents C's in_addr.s_addr, not a host-order IP integer. NetworkManager
// takes the uint32 verbatim as network-order memory. D-Bus handles integer wire
// endianness separately. On little endian 192.0.2.1 becomes 0x010200c0.
func nmIPv4(a netip.Addr) uint32 {
 b := a.As4()
 return binary.NativeEndian.Uint32(b[:])
}

// Encode builds the real Config and Ip4Config a{sv} payloads. Success means only
// that configuration passed the limited policy, never that NM applied it.
func Encode(o Offer, p Policy) (Config, error) {
 bad := errors.New("unsupported or unapproved NM VPN configuration")
 if !sessionPattern.MatchString(o.Session) || !linkPattern.MatchString(o.Interface) || o.Interface == "lo" || !o.Address.IsValid() || o.Address.Bits() < 1 || !validIP(o.Address.Addr()) || !validIP(o.Endpoint) || o.Address.Contains(o.Endpoint) || !slices.Contains(p.Addresses, o.Address) || !slices.Contains(p.Endpoints, o.Endpoint) || len(o.Routes) > 128 || len(o.DNS) != 0 || len(o.Domains) != 0 {
  return Config{}, bad
 }
 routes := make([][]uint32, 0, len(o.Routes))
 seen := make(map[netip.Prefix]bool)
 for _, r := range o.Routes {
  if !r.IsValid() || !r.Addr().Is4() || r.Bits() == 0 || r != r.Masked() || !slices.Contains(p.Routes,r) || seen[r] || r.Contains(o.Endpoint) {
   return Config{}, bad
  }
  seen[r] = true
  // NM legacy IPv4 route tuple: destination, prefix, next hop, metric.
  // A zero next hop means directly through the point-to-point VPN interface.
  routes = append(routes, []uint32{nmIPv4(r.Addr()), uint32(r.Bits()), 0, 0})
 }
 return Config{
  General: map[string]dbus.Variant{
   "tundev": dbus.MakeVariant(o.Interface),
   "gateway": dbus.MakeVariant(nmIPv4(o.Endpoint)),
   "has-ip4": dbus.MakeVariant(true),
   "has-ip6": dbus.MakeVariant(false),
   "can-persist": dbus.MakeVariant(false),
  },
  IPv4: map[string]dbus.Variant{
   "address": dbus.MakeVariant(nmIPv4(o.Address.Addr())),
   "prefix": dbus.MakeVariant(uint32(o.Address.Bits())),
   "routes": dbus.MakeVariant(routes),
   "never-default": dbus.MakeVariant(true),
  },
 }, nil
}
