//go:build windows

package windowsvpn

import (
	"syscall"
	"testing"
)

func TestNativeProjectionABIWithoutRAS(t *testing.T) {
	wantHandle := ^uintptr(0) - 23
	valid := false
	address := syscall.NewCallback(func(h, kind uintptr, p *nativePPPIPv4, size *uint32) uintptr {
		valid = h == wantHandle && kind == uintptr(raspPPPIPv4) && p != nil && size != nil && p.Size == 80 && *size == 80
		if p != nil && size != nil {
			fixtureProjection(h, p, size)
		}
		return 0
	})
	call, err := nativeProjectionIPv4(address)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := readPPPIPv4(wantHandle, call)
	if err != nil || !valid || ip.String() != "10.20.30.40" {
		t.Fatal("projection ABI mismatch")
	}
	if _, err := nativeProjectionIPv4(0); err == nil {
		t.Fatal("null address accepted")
	}
}
