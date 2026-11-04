//go:build darwin

package macosvpn

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"
)

// Loopback RTM_GET only. No ping, packet transmission, DNS, route update or VPN.
func TestMacOSReadOnlyDestinationLookup(t *testing.T) {
	if os.Getenv("MERIDIAN_MACOS_POLICY_READBACK") != "1" {
		t.Skip("需要明确启用原生只读验证")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, text := range []string{"127.0.0.1", "::1"} {
		ip := netip.MustParseAddr(text)
		r, e := LookupDestinationRoute(ctx, ip)
		if e != nil {
			t.Fatal("只读数值目的地址查询未通过")
		}
		if r.Destination != ip || !r.MatchedPrefix.Contains(ip) || r.InterfaceName != "lo0" || r.InterfaceIndex <= 0 || r.Flags&1 == 0 {
			t.Fatal("回环目的路由不匹配")
		}
	}
}
