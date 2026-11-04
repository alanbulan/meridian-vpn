//go:build linux && (386 || s390x)

package packetrelay

import (
	"syscall"
	"unsafe"
)

// Linux 386 and s390x use the socketcall multiplexer in Go's syscall package.
func rawUnixName(fd int, peer bool, addr *syscall.RawSockaddrUnix, size *uint32) syscall.Errno {
	call := uintptr(6) // SYS_GETSOCKNAME socketcall operation.
	if peer {
		call = 7 // SYS_GETPEERNAME socketcall operation.
	}
	// Keep pointers typed until Syscall. The three fields have the same ABI
	// layout as socketcall's unsigned-long argument array on these architectures.
	args := struct {
		fd   uintptr
		addr *syscall.RawSockaddrUnix
		size *uint32
	}{uintptr(fd), addr, size}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, call, uintptr(unsafe.Pointer(&args)), 0)
	return errno
}
