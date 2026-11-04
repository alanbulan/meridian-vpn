//go:build darwin

package macosvpn

import (
	"context"
	"os"
	"testing"
	"time"
)

// Explicit native CI opt-in only. No Start/Stop, settings changes or DNS query.
func TestMacOSReadOnlyPolicyReaders(t *testing.T) {
	if os.Getenv("MERIDIAN_MACOS_POLICY_READBACK") != "1" {
		t.Skip("需要明确启用原生只读验证")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	routes, err := ReadKernelRoutes(ctx)
	if err != nil {
		t.Fatal("内核路由只读验证未通过")
	}
	dns, err := ReadDNSConfiguration(ctx)
	if err != nil {
		t.Fatal("系统解析器只读验证未通过")
	}
	if len(routes.Records) == 0 || len(dns.Resolvers) == 0 || dns.QueryRoutingVerified {
		t.Fatal("只读证据不完整或错误提升为实际查询证明")
	}
	t.Logf("只读路由条目：%d；解析器条目：%d；未证明 VPN 可用", len(routes.Records), len(dns.Resolvers))
}
