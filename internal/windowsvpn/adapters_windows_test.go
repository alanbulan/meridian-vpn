//go:build windows

package windowsvpn

import (
	"syscall"
	"testing"
	"unsafe"
)

func TestNativeAdapterInventoryABIWithoutIPHelper(t *testing.T) {
	valid := false
	address := syscall.NewCallback(func(family, flags, reserved uintptr, storage *uint64, size *uint32) uintptr {
		valid = family == 2 && flags == 0x2e && reserved == 0 && storage != nil && size != nil && *size >= 15000
		if !valid {
			return 87
		}
		fixture := adapterFixture(int(unsafe.Sizeof(uintptr(0))), uint64(uintptr(unsafe.Pointer(storage))))
		copy(unsafe.Slice((*byte)(unsafe.Pointer(storage)), int(*size)), fixture)
		*size = uint32(len(fixture))
		return 0
	})
	inventory, err := nativeAdapterInventory(address)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := inventory()
	if err != nil || !valid || len(rows) != 1 || rows[0].index != 9 {
		t.Fatal("native inventory ABI mismatch", err)
	}
}
