//go:build windows

package windowsvpn

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var systemConnections struct {
	once sync.Once
	enumerate, status *syscall.LazyProc
	err error
}

func systemConnectionProcs() (*syscall.LazyProc, *syscall.LazyProc, error) {
	systemConnections.once.Do(func() {
		kernel := syscall.NewLazyDLL("kernel32.dll")
		directoryProc := kernel.NewProc("GetSystemDirectoryW")
		if directoryProc.Find() != nil { systemConnections.err = ErrConnectionObservation; return }
		directory := make([]uint16, 32768)
		n, _, _ := directoryProc.Call(uintptr(unsafe.Pointer(&directory[0])), uintptr(len(directory)))
		runtime.KeepAlive(directory)
		if n == 0 || n >= uintptr(len(directory)) { systemConnections.err = ErrConnectionObservation; return }
		path, ok := fixedUTF16(directory)
		if !ok || path == "" { systemConnections.err = ErrConnectionObservation; return }
		ras := syscall.NewLazyDLL(path + `\rasapi32.dll`)
		enumerate := ras.NewProc("RasEnumConnectionsW")
		status := ras.NewProc("RasGetConnectStatusW")
		if enumerate.Find() != nil || status.Find() != nil { systemConnections.err = ErrConnectionObservation; return }
		systemConnections.enumerate, systemConnections.status = enumerate, status
	})
	return systemConnections.enumerate, systemConnections.status, systemConnections.err
}

// ObserveSystemConnections performs explicit read-only RAS enumeration/status
// inspection for a previously validated entry. It revalidates the profile on
// both sides and compares two connection enumerations, including correlation ID.
// A connection appearing in enumeration is NOT a reference owned by this
// process. No RasDial, RasHangUp, credentials or profile mutation API is loaded.
// RAS may start its service. No result permits dialing: pending external dials
// may be invisible, and a new connection can appear after this function returns.
// This API is not wired to the application; snapshots must not be persisted or
// exported automatically. It never returns a handle usable for disconnection.
func ObserveSystemConnections(entry EntryEvidence) (ConnectionSnapshot, error) {
	if entry.properties.GUID == [16]byte{} || !validSelection(entry.entry) || !supportedEntry(entry.properties, entry.gateway) { return ConnectionSnapshot{}, ErrConnectionObservation }
	enumerate, status, err := systemConnectionProcs()
	if err != nil { return ConnectionSnapshot{}, err }
	return observeConnections(entry,
		func(buffer []uint32, size, count *uint32) uint32 {
			result, _, _ := enumerate.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(size)), uintptr(unsafe.Pointer(count)))
			runtime.KeepAlive(buffer); runtime.KeepAlive(size); runtime.KeepAlive(count)
			return uint32(result)
		},
		func(handle uintptr, output *nativeConnectionStatus) uint32 {
			result, _, _ := status.Call(handle, uintptr(unsafe.Pointer(output)))
			runtime.KeepAlive(output)
			return uint32(result)
		},
		RevalidateSystemEntry,
	)
}
