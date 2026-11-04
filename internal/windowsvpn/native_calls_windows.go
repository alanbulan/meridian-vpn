//go:build windows

package windowsvpn

import (
	"runtime"
	"syscall"
	"unsafe"
)

// nativeRASTransport binds already-resolved, trusted procedure addresses. There
// is deliberately no DLL resolver, default constructor, exported application
// entry point in this bridge. Explicit session wiring supplies borrowedOperations. Tests supply
// only our own Go ABI stubs; no tests resolve or invoke actual RAS procedures.
func nativeRASTransport(dialAddress, hangupAddress uintptr) (nativeRASCalls, error) {
	if dialAddress == 0 || hangupAddress == 0 {
		return nativeRASCalls{}, ErrUnavailable
	}
	return nativeRASCalls{
		dial: func(phonebook *uint16, parameters *uint32, notifier uintptr, handle *uintptr) uint32 {
			// RasDialW(NULL, exact PBK, params, RASDIALFUNC2, notifier, &NULL).
			// NULL extensions deliberately disable paused-state restarts and custom EAP.
			// DWORD return is authoritative; GetLastError must not replace that result.
			result, _, _ := syscall.SyscallN(dialAddress, 0, uintptr(unsafe.Pointer(phonebook)), uintptr(unsafe.Pointer(parameters)), 2, notifier, uintptr(unsafe.Pointer(handle)))
			runtime.KeepAlive(phonebook)
			runtime.KeepAlive(parameters)
			runtime.KeepAlive(handle)
			return uint32(result)
		},
		hangup: func(handle uintptr) uint32 {
			result, _, _ := syscall.SyscallN(hangupAddress, handle)
			return uint32(result)
		},
	}, nil
}
