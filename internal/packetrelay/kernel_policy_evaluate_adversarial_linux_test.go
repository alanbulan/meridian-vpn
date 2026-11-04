//go:build linux

package packetrelay

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func kernelDeltaRewriteAttrs(b []byte, header int, change func(uint16, []byte) (uint16, []byte, bool)) []byte {
	out := append([]byte(nil), b[:header]...)
	for off := header; off < len(b); {
		n := int(binary.NativeEndian.Uint16(b[off:]))
		tag := binary.NativeEndian.Uint16(b[off+2:])
		value := append([]byte(nil), b[off+4:off+n]...)
		k, v, keep := change(tag, value)
		if keep {
			out = append(out, kernelTestAttr(k, v)...)
		}
		off += kernelAlign(n)
	}
	return out
}
func TestKernelPolicyDeltaAdversarialAttributes(t *testing.T) {
	// Mandatory address and route attributes, their flags, sizes and values.
	specs := []struct {
		index, header int
		kinds         []uint16
	}{{1, 8, []uint16{unix.IFA_LOCAL, unix.IFA_ADDRESS, unix.IFA_LABEL}}, {3, 12, []uint16{unix.RTA_DST, unix.RTA_OIF, unix.RTA_PREFSRC, unix.RTA_TABLE, unix.RTA_PRIORITY}}}
	for _, s := range specs {
		for _, kind := range s.kinds {
			for _, mode := range []string{"nested", "netorder", "short", "long", "wrong", "missing"} {
				t.Run(fmt.Sprintf("%d-%d-%s", s.index, kind, mode), func(t *testing.T) {
					b, a, p := kernelDeltaFixture()
					a.Records[s.index].Data = kernelDeltaRewriteAttrs(a.Records[s.index].Data, s.header, func(k uint16, v []byte) (uint16, []byte, bool) {
						if k != kind {
							return k, v, true
						}
						switch mode {
						case "nested":
							k |= 0x8000
						case "netorder":
							k |= 0x4000
						case "short":
							v = v[:len(v)-1]
						case "long":
							v = append(v, 0)
						case "wrong":
							v[0] ^= 1
						case "missing":
							return k, v, false
						}
						return k, v, true
					})
					wantAccept := mode == "missing" && ((s.index == 1 && kind == unix.IFA_LABEL) || (s.index == 3 && (kind == unix.RTA_TABLE || kind == unix.RTA_PRIORITY)))
					err := EvaluateKernelIPv4Delta(b, a, p)
					if (err == nil) != wantAccept {
						t.Fatalf("accept=%v, want %v: %v", err == nil, wantAccept, err)
					}
				})
			}
		}
	}
	for _, kind := range []uint16{unix.RTA_SRC, unix.RTA_IIF, unix.RTA_GATEWAY, unix.RTA_METRICS, unix.RTA_MULTIPATH, unix.RTA_FLOW, unix.RTA_MARK, unix.RTA_VIA, unix.RTA_ENCAP, unix.RTA_ENCAP_TYPE, 30 /* RTA_NH_ID: absent from this x/sys release */, unix.RTA_EXPIRES} {
		t.Run(fmt.Sprintf("forbidden-route-attr-%d", kind), func(t *testing.T) {
			b, a, p := kernelDeltaFixture()
			a.Records[3].Data = append(a.Records[3].Data, kernelTestAttr(kind, []byte{0, 0, 0, 0})...)
			if EvaluateKernelIPv4Delta(b, a, p) == nil {
				t.Fatal("forbidden attr accepted")
			}
		})
	}
	for _, mode := range []string{"table-from-attr", "attribute-order", "tuple-duplicate", "preexisting-route", "baseline-IPv6-address", "baseline-other-interface"} {
		t.Run(mode, func(t *testing.T) {
			b, a, p := kernelDeltaFixture()
			wantAccept := false
			switch mode {
			case "table-from-attr":
				a.Records[3].Data[4] = 0
				wantAccept = true
			case "attribute-order":
				d := a.Records[3].Data
				a.Records[3].Data = append(append(append([]byte(nil), d[:12]...), d[20:]...), d[12:20]...)
				wantAccept = true
			case "tuple-duplicate":
				r := a.Records[3]
				r.Data = append([]byte(nil), r.Data...)
				r.Data[4] = 0
				a.Records = append(a.Records, r)
			case "preexisting-route":
				b.Records = append(b.Records, a.Records[3])
			case "baseline-IPv6-address":
				d := make([]byte, 8)
				d[0], d[1], d[2] = unix.AF_INET6, 64, unix.IFA_F_PERMANENT
				binary.NativeEndian.PutUint32(d[4:], p.InterfaceIndex)
				d = append(d, kernelTestAttr(unix.IFA_ADDRESS, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})...)
				r := KernelPolicyRecord{Type: unix.RTM_NEWADDR, Data: d}
				b.Records = append(b.Records, r)
				a.Records = append(a.Records, r)
			case "baseline-other-interface":
				r := a.Records[1]
				r.Data = append([]byte(nil), r.Data...)
				binary.NativeEndian.PutUint32(r.Data[4:], 10)
				b.Records = append(b.Records, r)
				a.Records = append(a.Records, r)
				wantAccept = true
			}
			err := EvaluateKernelIPv4Delta(b, a, p)
			if (err == nil) != wantAccept {
				t.Fatalf("accept=%v want %v: %v", err == nil, wantAccept, err)
			}
		})
	}
}
