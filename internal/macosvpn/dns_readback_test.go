package macosvpn

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

const dnsFixture = `DNS configuration
resolver #1
  search domain[0] : example.test
  nameserver[0] : 192.0.2.53
  if_index : 7 (ppp0)
  flags : Request A records
  reach : 0x00000002 (Reachable)
  order : 200000
resolver #2
  domain : local
  options : mdns
  timeout : 5
  flags : Request A records, Request AAAA records
  reach : 0x00000000 (Not Reachable)
  order : 300000
DNS configuration (for scoped queries)
resolver #1
  nameserver[0] : fe80::1%en0
  if_index : 4 (en0)
  flags : Scoped, Request A records, Request AAAA records
  reach : 0x00000002 (Reachable)
DNS configuration (for service-specific queries)
resolver #1
  nameserver[0] : 198.51.100.53
  service_identifier : 77
  flags : Service-specific, Request A records
  reach : 0x00000002 (Reachable)
`

func TestDNSReadbackScopeNotQueryProof(t *testing.T) {
	r, e := parseDNSReadback([]byte(dnsFixture))
	if e != nil || len(r.Resolvers) != 4 || r.QueryRoutingVerified {
		t.Fatal("错误解析或冒称实际选路")
	}
	if r.Resolvers[0].InterfaceIndex != 7 || r.Resolvers[2].Scope != "scoped" || r.Resolvers[3].ServiceIdentifier != 77 {
		t.Fatal("解析器作用域丢失")
	}
}
func TestDNSReadbackRejectsAmbiguityAndBounds(t *testing.T) {
	cases := []string{strings.Replace(dnsFixture, "  reach : 0x00000002 (Reachable)\n", "", 1), strings.Replace(dnsFixture, "Scoped, ", "", 1), "", strings.Repeat("x", maxDNSReadbackBytes+1), "No DNS configuration available", strings.Replace(dnsFixture, "nameserver[0]", "nameserver[1]", 1), strings.Replace(dnsFixture, "192.0.2.53", "not-an-ip", 1), strings.Replace(dnsFixture, "flags : Request A records", "flags : FutureFlag", 1), strings.Replace(dnsFixture, "order : 200000", "order : 200000\n order : 200001", 1), strings.Replace(dnsFixture, "order : 200000", "secret : private", 1), strings.Replace(dnsFixture, "resolver #2", "resolver #1", 1), strings.Replace(dnsFixture, "resolver #1", "resolver #129", 1), strings.Replace(dnsFixture, "192.0.2.53", "0.0.0.0", 1), strings.Replace(dnsFixture, "example.test", "bad\x00domain", 1), strings.Replace(dnsFixture, "options : mdns", "options : unknown", 1)}
	for i, s := range cases {
		if _, err := parseDNSReadback([]byte(s)); err != ErrDNSReadback {
			t.Fatalf("未拒绝无效样本 %d", i)
		}
	}
}
func TestDNSReadbackMemoryBound(t *testing.T) {
	var b boundedDNSOutput
	if _, e := b.Write(make([]byte, maxDNSReadbackBytes)); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Write([]byte("x")); e == nil || !b.overflow || b.Len() != maxDNSReadbackBytes {
		t.Fatal("输出未保持有界")
	}
}

func TestDNSReadbackIOCopyCannotBypassBound(t *testing.T) {
	var out boundedDNSOutput
	// Hide WriterTo so io.Copy must consider the destination ReaderFrom path.
	reader := struct{ io.Reader }{bytes.NewReader(make([]byte, maxDNSReadbackBytes+1))}
	if _, err := io.Copy(&out, reader); err == nil || !out.overflow || out.Len() > maxDNSReadbackBytes {
		t.Fatal("io.Copy 绕过输出上限")
	}
	if _, ok := any(&out).(io.ReaderFrom); ok {
		t.Fatal("不应暴露无界ReaderFrom")
	}
}
