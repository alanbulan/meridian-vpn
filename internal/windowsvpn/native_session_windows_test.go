//go:build windows

package windowsvpn

import (
	"context"
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"
)

// Exercises native ABI → real Go callback router → coordinator → projection
// ABI → deletion gate, using only our own Go-created function pointers.
func TestBoundWindowsSessionABIWithoutRAS(t *testing.T) {
	record := fixtureConnection()
	deleted := false
	dialCalls, hangCalls, projectionCalls := 0, 0, 0
	valid := true
	dial := syscall.NewCallback(func(ext uintptr, pb *uint16, p *uint32, kind, notifier uintptr, h *uintptr) uintptr {
		dialCalls++
		valid = valid && ext == 0 && pb != nil && p != nil && kind == 2 && notifier != 0 && h != nil && *h == 0
		if !valid {
			return 87
		}
		layout, _ := rasDialParameterLayout(int(unsafe.Sizeof(uintptr(0))))
		bytes := wordBytes(unsafe.Slice(p, layout.size/4))
		var id uintptr
		if unsafe.Sizeof(uintptr(0)) == 8 {
			id = uintptr(binary.LittleEndian.Uint64(bytes[layout.callbackID:]))
		} else {
			id = uintptr(binary.LittleEndian.Uint32(bytes[layout.callbackID:]))
		}
		*h = record.handle
		result, _, _ := syscall.SyscallN(notifier, id, 1, record.handle, 0xcccd, uintptr(rasConnected), 0, 0)
		valid = valid && result == 1
		return 0
	})
	hangup := syscall.NewCallback(func(h uintptr) uintptr { hangCalls++; valid = valid && h == record.handle; deleted = true; return 0 })
	projection := syscall.NewCallback(func(h, kind uintptr, p *nativePPPIPv4, size *uint32) uintptr {
		projectionCalls++
		valid = valid && h == record.handle && kind == uintptr(raspPPPIPv4) && p != nil && size != nil
		if !valid {
			return 87
		}
		return uintptr(fixtureProjection(h, p, size))
	})
	b := nativeSessionBindings{revalidate: unchangedEntry, enumerate: fixedConnections(record), interfaces: func() ([]adapterIPv4, error) { return fixtureAdapterRows(), nil }, status: func(h uintptr, s *nativeConnectionStatus) uint32 {
		if h != record.handle {
			return 87
		}
		if deleted {
			return rasInvalidHandle
		}
		return fixtureStatus(h, s)
	}}
	c, err := bindWindowsNativeSession(dial, hangup, projection, b)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = c.stop(context.Background())
		if c.current != nil {
			c.current.inputs.releaseAfterQuiescence()
		}
	}()
	if dialCalls != 0 || projectionCalls != 0 || hangCalls != 0 {
		t.Fatal("construction invoked native procedures")
	}
	if err := startBorrowed(c); err != nil {
		t.Fatal(err)
	}
	if err := c.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !valid || dialCalls != 1 || hangCalls != 1 || projectionCalls < 4 || c.current != nil {
		t.Fatal("integrated ABI/lifecycle mismatch")
	}
}
