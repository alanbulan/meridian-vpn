package windowsvpn

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"unsafe"
)

// IP Helper uses normal 8-byte SDK structure alignment, unlike ras.h pack(4).
// Decode pointers only as checked offsets inside the owned result allocation;
// never dereference arbitrary pointers supplied by a native result.
type adapterLayout struct{ pointer, next, unicast, kind, oper, luid, minimum, uniNext, socket, socketLength, dad, valid, preferred, prefix, uniMinimum int }

func adapterSDKLayout(p int) (adapterLayout, bool) {
	if p != 4 && p != 8 {
		return adapterLayout{}, false
	}
	speed := (104 + 10*p + 7) &^ 7
	luid := (speed + 24 + 2*p + 7) &^ 7
	l := adapterLayout{pointer: p, next: 8, unicast: 8 + 2*p, kind: 28 + 9*p, oper: 32 + 9*p, luid: luid, minimum: luid + 8, uniNext: 8, socket: 8 + p, socketLength: 8 + 2*p, dad: 16 + 3*p, valid: 20 + 3*p, preferred: 24 + 3*p, prefix: 32 + 3*p, uniMinimum: 33 + 3*p}
	return l, true
}

type adapterAddressesFunc func([]uint64, *uint32) uint32

const maxAdapterBytes = 4 * 1024 * 1024

func inventoryAdapters(call adapterAddressesFunc) ([]adapterIPv4, error) {
	if call == nil {
		return nil, ErrVerification
	}
	size := uint32(15000)
	for attempt := 0; attempt < 3; attempt++ {
		if size < 256 || size > maxAdapterBytes {
			return nil, ErrVerification
		}
		storage := make([]uint64, (size+7)/8)
		size = uint32(len(storage) * 8)
		code := call(storage, &size)
		if code == 111 {
			if size <= uint32(len(storage)*8) {
				return nil, ErrVerification
			}
			continue
		} // ERROR_BUFFER_OVERFLOW
		if code == 232 {
			return []adapterIPv4{}, nil
		} // ERROR_NO_DATA
		if code != 0 || size == 0 || size > uint32(len(storage)*8) {
			return nil, ErrVerification
		}
		bytes := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), int(size))
		result, err := decodeAdapters(bytes, uint64(uintptr(unsafe.Pointer(&storage[0]))), int(unsafe.Sizeof(uintptr(0))))
		runtime.KeepAlive(storage)
		return result, err
	}
	return nil, ErrVerification
}
func decodeAdapters(b []byte, base uint64, p int) ([]adapterIPv4, error) {
	fail := func() ([]adapterIPv4, error) { return nil, ErrVerification }
	l, ok := adapterSDKLayout(p)
	if !ok || base == 0 || base%8 != 0 || len(b) > maxAdapterBytes {
		return fail()
	}
	offset := func(ptr uint64, n int) (int, bool) {
		if ptr < base || n < 0 {
			return 0, false
		}
		o := ptr - base
		if o > uint64(len(b)) || uint64(n) > uint64(len(b))-o {
			return 0, false
		}
		return int(o), true
	}
	ptr := func(o int) uint64 {
		if p == 8 {
			return binary.LittleEndian.Uint64(b[o:])
		}
		return uint64(binary.LittleEndian.Uint32(b[o:]))
	}
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	seen := map[uint64]bool{}
	seenUni := map[uint64]bool{}
	result := []adapterIPv4{}
	for address := base; address != 0; {
		if seen[address] || len(result) >= 4096 || address%8 != 0 {
			return fail()
		}
		seen[address] = true
		start, ok := offset(address, l.minimum)
		if !ok {
			return fail()
		}
		length := u32(start)
		if length < uint32(l.minimum) {
			return fail()
		}
		if _, ok := offset(address, int(length)); !ok {
			return fail()
		}
		row := adapterIPv4{index: u32(start + 4), luid: binary.LittleEndian.Uint64(b[start+l.luid:]), kind: u32(start + l.kind), operStatus: u32(start + l.oper)}
		for uni := ptr(start + l.unicast); uni != 0; {
			if seenUni[uni] || len(row.addresses) >= 64 || uni%8 != 0 {
				return fail()
			}
			seenUni[uni] = true
			at, ok := offset(uni, l.uniMinimum)
			if !ok {
				return fail()
			}
			length := u32(at)
			if length < uint32(l.uniMinimum) {
				return fail()
			}
			if _, ok := offset(uni, int(length)); !ok {
				return fail()
			}
			socketLen := u32(at + l.socketLength)
			if socketLen != 16 {
				return fail()
			} // AF_INET sockaddr_in
			socket, ok := offset(ptr(at+l.socket), 16)
			if !ok || binary.LittleEndian.Uint16(b[socket:]) != 2 {
				return fail()
			}
			ip := netip.AddrFrom4([4]byte{b[socket+4], b[socket+5], b[socket+6], b[socket+7]})
			row.addresses = append(row.addresses, ip)
			if u32(at+l.dad) != 4 || u32(at+l.valid) == 0 || u32(at+l.preferred) == 0 || b[at+l.prefix] > 32 || u32(at+4)&2 != 0 {
				row.unusable = append(row.unusable, ip)
			}
			uni = ptr(at + l.uniNext)
		}
		result = append(result, row)
		address = ptr(start + l.next)
	}
	return result, nil
}
