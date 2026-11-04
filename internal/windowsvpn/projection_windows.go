//go:build windows

package windowsvpn

import (
	"runtime"
	"syscall"
	"unsafe"
)

// No resolver/default caller: address must be an explicitly resolved trusted
// RasGetProjectionInfoW procedure. Tests provide only a Go-created ABI stub.
func nativeProjectionIPv4(address uintptr) (projectionIPv4Func, error) {
	if address == 0 {
		return nil, ErrUnavailable
	}
	return func(handle uintptr, output *nativePPPIPv4, size *uint32) uint32 {
		result, _, _ := syscall.SyscallN(address, handle, uintptr(raspPPPIPv4), uintptr(unsafe.Pointer(output)), uintptr(unsafe.Pointer(size)))
		runtime.KeepAlive(output)
		runtime.KeepAlive(size)
		return uint32(result)
	}, nil
}
