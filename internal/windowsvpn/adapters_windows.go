//go:build windows

package windowsvpn

import (
	"runtime"
	"syscall"
	"unsafe"
)

// Explicitly injected GetAdaptersAddresses address; no DLL resolution or call
// occurs during construction. Requests IPv4 unicast inventory only, omitting
// ancillary lists. Native storage lives through synchronous decoding only.
func nativeAdapterInventory(address uintptr) (interfaceSnapshotFunc, error) {
	if address == 0 {
		return nil, ErrUnavailable
	}
	return func() ([]adapterIPv4, error) {
		return inventoryAdapters(func(storage []uint64, size *uint32) uint32 {
			result, _, _ := syscall.SyscallN(address, 2, 0x2e, 0, uintptr(unsafe.Pointer(&storage[0])), uintptr(unsafe.Pointer(size)))
			runtime.KeepAlive(storage)
			runtime.KeepAlive(size)
			return uint32(result)
		})
	}, nil
}
