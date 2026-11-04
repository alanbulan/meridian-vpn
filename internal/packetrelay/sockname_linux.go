//go:build linux && !386 && !s390x

package packetrelay

import (
	"syscall"
	"unsafe"
)

func rawUnixName(fd int, peer bool, addr *syscall.RawSockaddrUnix, size *uint32) syscall.Errno {
	call := uintptr(syscall.SYS_GETSOCKNAME)
	if peer {
		call = uintptr(syscall.SYS_GETPEERNAME)
	}
	_, _, errno := syscall.Syscall(call, uintptr(fd), uintptr(unsafe.Pointer(addr)), uintptr(unsafe.Pointer(size)))
	return errno
}
