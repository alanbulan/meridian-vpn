//go:build darwin

package macosvpn

import (
	"encoding/binary"
	"testing"
)

// Synthetic wire data only: these tests never call sysctl or inspect host routes.
func TestRouteReadbackDarwinDecodeSynthetic(t *testing.T) {
	for _, kind := range []string{"v4-default", "v4-host", "v4-network", "v6-default", "v6-scoped-host", "link", "use-counter", "bad-errno"} {
		t.Run(kind, func(t *testing.T) {
			dst, gw, mask := routeTestSockaddr("0.0.0.0"), routeTestSockaddr("192.0.2.1"), []byte{0, 0, 0, 0}
			flags := uint32(3)
			want := "0.0.0.0/0"
			switch kind {
			case "v4-host":
				dst = routeTestSockaddr("10.0.0.1")
				mask = nil
				flags = 7
				want = "10.0.0.1/32"
			case "v4-network":
				dst = routeTestSockaddr("10.0.0.0")
				mask = []byte{5, 0, 0, 0, 255, 0, 0, 0}
				want = "10.0.0.0/8"
			case "v6-default":
				dst = routeTestSockaddr("::")
				gw = routeTestSockaddr("fe80::1")
				binary.LittleEndian.PutUint32(gw[24:28], 7)
				want = "::/0"
			case "v6-scoped-host":
				dst = routeTestSockaddr("fe80::1")
				dst[10], dst[11] = 0, 7
				gw = routeTestSockaddr("fe80::2")
				gw[10], gw[11] = 0, 7
				mask = nil
				flags = 0x1000007
				want = "fe80::1/128"
			case "link":
				gw = []byte{8, 18, 7, 0, 0, 0, 0, 0}
				flags = 1
			}
			b := routeTestFrame(dst, gw, mask, flags)
			if kind == "use-counter" {
				binary.LittleEndian.PutUint32(b[28:32], 123)
			}
			if kind == "bad-errno" {
				b[24] = 1
			}
			r, err := decodeDarwinRouteRIB(b)
			if kind == "bad-errno" {
				if err == nil || r != nil {
					t.Fatal("errno accepted")
				}
				return
			}
			if err != nil || len(r) != 1 || r[0].Prefix.String() != want {
				t.Fatalf("decode: %+v %v", r, err)
			}
			if kind == "v6-scoped-host" && (r[0].ScopeInterfaceIndex != 7 || r[0].DestinationZoneIndex != 7 || r[0].GatewayZoneIndex != 7) {
				t.Fatal("IPv6 scope lost")
			}
			if kind == "link" && (!r[0].GatewayIsLink || r[0].Gateway.IsValid() || r[0].GatewayInterfaceIndex != 7) {
				t.Fatal("link gateway lost")
			}
		})
	}
}

func TestRouteRawMaskFamilyDecode(t *testing.T) {
	for _, af := range []byte{0, 2, 18, 30, 255} {
		b := routeTestFrame(routeTestSockaddr("10.0.0.0"), routeTestSockaddr("192.0.2.1"), []byte{8, af, 0, 0, 255, 0, 0, 0}, 3)
		records, err := decodeDarwinRouteRIB(b)
		if err != nil || len(records) != 1 || records[0].Prefix.String() != "10.0.0.0/8" {
			t.Fatalf("原始掩码族解码失败：%v", err)
		}
	}
}

func TestRouteRawMasksMixedDecodeAndNoncontiguousRejection(t *testing.T) {
	var combined []byte
	for _, frame := range rawMaskRegressionFrames() {
		combined = append(combined, frame...)
	}
	records, err := decodeDarwinRouteRIB(combined)
	want := []string{"10.0.0.0/8", "2001:db8::/64", "0.0.0.0/0", "::/0"}
	if err != nil || len(records) != len(want) {
		t.Fatalf("混合帧解码失败：%v", err)
	}
	for i, r := range records {
		if r.Prefix.String() != want[i] {
			t.Fatal("掩码位解析错误")
		}
	}
	for _, family := range []byte{18, 255} {
		mask := []byte{8, family, 0, 0, 255, 0, 255, 0}
		b := routeTestFrame(routeTestSockaddr("10.0.0.0"), routeTestSockaddr("192.0.2.1"), mask, 3)
		if r, err := decodeDarwinRouteRIB(b); err == nil || r != nil {
			t.Fatal("非连续掩码被接受")
		}
	}
}
