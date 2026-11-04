package windowsvpn

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

func adapterFixture(p int, base uint64) []byte {
	l, _ := adapterSDKLayout(p)
	b := make([]byte, 512)
	setptr := func(at int, v uint64) {
		if p == 8 {
			binary.LittleEndian.PutUint64(b[at:], v)
		} else {
			binary.LittleEndian.PutUint32(b[at:], uint32(v))
		}
	}
	set32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	set32(0, uint32(l.minimum))
	set32(4, 9)
	set32(l.kind, 23)
	set32(l.oper, 1)
	binary.LittleEndian.PutUint64(b[l.luid:], 0x1234)
	setptr(l.unicast, base+256)
	set32(256, uint32((l.uniMinimum+7)&^7))
	setptr(256+l.socket, base+384)
	set32(256+l.socketLength, 16)
	set32(256+l.dad, 4)
	set32(256+l.valid, 100)
	set32(256+l.preferred, 100)
	b[256+l.prefix] = 24
	binary.LittleEndian.PutUint16(b[384:], 2)
	copy(b[388:], []byte{10, 20, 30, 40})
	return b
}
func TestAdapterSDKLayouts(t *testing.T) {
	for _, p := range []int{4, 8} {
		l, ok := adapterSDKLayout(p)
		want := 176
		if p == 8 {
			want = 224
		}
		if !ok || l.luid != want || l.minimum != want+8 || l.dad != 16+3*p || l.prefix != 32+3*p {
			t.Fatal("IP Helper layout mismatch")
		}
	}
}
func TestAdapterDecoderBoundsAndState(t *testing.T) {
	for _, p := range []int{4, 8} {
		l, _ := adapterSDKLayout(p)
		base := uint64(0x100000)
		for _, kind := range []string{"valid", "outside adapter", "adapter cycle", "outside unicast", "unicast cycle", "outside sockaddr", "short adapter", "short unicast", "bad sockaddr length", "bad family", "tentative", "expired", "transient"} {
			t.Run(string(rune('0'+p))+"/"+kind, func(t *testing.T) {
				b := adapterFixture(p, base)
				setptr := func(at int, v uint64) {
					if p == 8 {
						binary.LittleEndian.PutUint64(b[at:], v)
					} else {
						binary.LittleEndian.PutUint32(b[at:], uint32(v))
					}
				}
				switch kind {
				case "outside adapter":
					setptr(l.next, base+1024)
				case "adapter cycle":
					setptr(l.next, base)
				case "outside unicast":
					setptr(l.unicast, base-8)
				case "unicast cycle":
					setptr(256+l.uniNext, base+256)
				case "outside sockaddr":
					setptr(256+l.socket, base+508)
				case "short adapter":
					binary.LittleEndian.PutUint32(b, 8)
				case "short unicast":
					binary.LittleEndian.PutUint32(b[256:], 8)
				case "bad sockaddr length":
					binary.LittleEndian.PutUint32(b[256+l.socketLength:], 0xffffffff)
				case "bad family":
					binary.LittleEndian.PutUint16(b[384:], 23)
				case "tentative":
					binary.LittleEndian.PutUint32(b[256+l.dad:], 1)
				case "expired":
					binary.LittleEndian.PutUint32(b[256+l.valid:], 0)
				case "transient":
					binary.LittleEndian.PutUint32(b[260:], 2)
				}
				rows, err := decodeAdapters(b, base, p)
				stateBad := kind == "tentative" || kind == "expired" || kind == "transient"
				if kind != "valid" && !stateBad {
					if err == nil {
						t.Fatal("malformed pointers accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				match, err := correlateInterface(netip.MustParseAddr("10.20.30.40"), rows)
				if stateBad {
					if err == nil {
						t.Fatal("unusable address correlated")
					}
				} else if err != nil || match.index != 9 || match.luid != 0x1234 {
					t.Fatal("valid adapter rejected")
				}
			})
		}
	}
}
func TestAdapterInventoryBoundedGrowth(t *testing.T) {
	calls := 0
	rows, err := inventoryAdapters(func(storage []uint64, size *uint32) uint32 {
		calls++
		if calls == 1 {
			*size = 20000
			return 111
		}
		b := adapterFixture(int(unsafe.Sizeof(uintptr(0))), uint64(uintptr(unsafe.Pointer(&storage[0]))))
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), len(storage)*8), b)
		*size = uint32(len(b))
		return 0
	})
	if err != nil || calls != 2 || len(rows) != 1 {
		t.Fatal("bounded growth failed", err)
	}
	for _, kind := range []string{"no growth", "too large", "persistent growth", "API error", "oversized success"} {
		t.Run(kind, func(t *testing.T) {
			n := 0
			_, err := inventoryAdapters(func(storage []uint64, size *uint32) uint32 {
				n++
				switch kind {
				case "no growth":
					return 111
				case "too large":
					*size = maxAdapterBytes + 1
					return 111
				case "persistent growth":
					*size += 1000
					return 111
				case "API error":
					return 5
				case "oversized success":
					*size++
					return 0
				}
				return 0
			})
			if err == nil || n > 3 {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	if rows, err := inventoryAdapters(func([]uint64, *uint32) uint32 { return 232 }); err != nil || len(rows) != 0 {
		t.Fatal("empty inventory failed")
	}
}

func FuzzAdapterDecoder(f *testing.F) {
	f.Add(adapterFixture(4, 0x100000), uint8(4))
	f.Add(adapterFixture(8, 0x100000), uint8(8))
	f.Add([]byte{}, uint8(4))
	f.Fuzz(func(t *testing.T, b []byte, p uint8) {
		if len(b) > maxAdapterBytes {
			t.Skip()
		}
		width := 4
		if p&1 != 0 || p == 8 {
			width = 8
		}
		_, _ = decodeAdapters(b, 0x100000, width)
	})
}
