//go:build windows

package windowsvpn

import (
	"runtime"
	"syscall"
	"unsafe"
)

// newSystemBorrowedSession is the explicit limited-mode real-system binding. It resolves
// procedures from the Windows system directory but does not dial or enumerate.
// Loading RAS can start its service. StartSystemBorrowed reaches this only after
// per-use consent in the explicitly enabled limited-mode UI. Live gateway
// acceptance remains unperformed; this is not a default application backend.
// The resulting coordinator can only borrow an already validated profile and
// never creates/edits entries, saves credentials, changes PSKs, routes or DNS.
func newSystemBorrowedSession() (*borrowedCoordinator, error) {
	kernel := syscall.NewLazyDLL("kernel32.dll") // Windows KnownDLL
	directoryProc := kernel.NewProc("GetSystemDirectoryW")
	if directoryProc.Find() != nil {
		return nil, ErrUnavailable
	}
	directory := make([]uint16, 32768)
	n, _, _ := directoryProc.Call(uintptr(unsafe.Pointer(&directory[0])), uintptr(len(directory)))
	runtime.KeepAlive(directory)
	if n == 0 || n >= uintptr(len(directory)) {
		return nil, ErrUnavailable
	}
	path, ok := fixedUTF16(directory)
	if !ok || path == "" {
		return nil, ErrUnavailable
	}
	ras := syscall.NewLazyDLL(path + `\rasapi32.dll`)
	dial := ras.NewProc("RasDialW")
	hangup := ras.NewProc("RasHangUpW")
	projection := ras.NewProc("RasGetProjectionInfoW")
	enumerate := ras.NewProc("RasEnumConnectionsW")
	status := ras.NewProc("RasGetConnectStatusW")
	adapters := syscall.NewLazyDLL(path + `\iphlpapi.dll`).NewProc("GetAdaptersAddresses")
	for _, proc := range []*syscall.LazyProc{dial, hangup, projection, enumerate, status, adapters} {
		if proc.Find() != nil {
			return nil, ErrUnavailable
		}
	}
	b := nativeSessionBindings{
		revalidate: RevalidateSystemEntry,
		enumerate: func(buffer []uint32, size, count *uint32) uint32 {
			result, _, _ := enumerate.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(size)), uintptr(unsafe.Pointer(count)))
			runtime.KeepAlive(buffer)
			runtime.KeepAlive(size)
			runtime.KeepAlive(count)
			return uint32(result)
		},
		status: func(handle uintptr, output *nativeConnectionStatus) uint32 {
			result, _, _ := status.Call(handle, uintptr(unsafe.Pointer(output)))
			runtime.KeepAlive(output)
			return uint32(result)
		},
	}
	return bindWindowsNativeAPIs(dial.Addr(), hangup.Addr(), projection.Addr(), adapters.Addr(), b)
}
