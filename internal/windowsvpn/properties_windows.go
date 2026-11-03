//go:build windows

package windowsvpn

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var systemProperties struct {
	once sync.Once
	proc, driveType, attributes *syscall.LazyProc
	err error
}

func systemPropertiesProcs() (*syscall.LazyProc, *syscall.LazyProc, *syscall.LazyProc, error) {
	systemProperties.once.Do(func() {
		// kernel32 is a KnownDLL. Resolve RAS only from the system directory.
		kernel := syscall.NewLazyDLL("kernel32.dll")
		directoryProc := kernel.NewProc("GetSystemDirectoryW")
		driveType := kernel.NewProc("GetDriveTypeW")
		attributes := kernel.NewProc("GetFileAttributesW")
		if directoryProc.Find() != nil || driveType.Find() != nil || attributes.Find() != nil { systemProperties.err = ErrEntryProperties; return }
		directory := make([]uint16, 32768)
		n, _, _ := directoryProc.Call(uintptr(unsafe.Pointer(&directory[0])), uintptr(len(directory)))
		runtime.KeepAlive(directory)
		if n == 0 || n >= uintptr(len(directory)) { systemProperties.err = ErrEntryProperties; return }
		path, ok := fixedUTF16(directory)
		if !ok || path == "" { systemProperties.err = ErrEntryProperties; return }
		proc := syscall.NewLazyDLL(path + `\rasapi32.dll`).NewProc("RasGetEntryPropertiesW")
		if proc.Find() != nil { systemProperties.err = ErrEntryProperties; return }
		systemProperties.proc, systemProperties.driveType, systemProperties.attributes = proc, driveType, attributes
	})
	return systemProperties.proc, systemProperties.driveType, systemProperties.attributes, systemProperties.err
}

// InspectSystemEntry explicitly reads one existing, local fixed-drive phonebook
// profile, rejecting observed reparse points. This is not an atomic path lock.
// The expected gateway must come from the user's intended destination,
// not from the entry being checked. It never dials, reads credentials, writes
// profiles, or obtains ownership. No DLL is loaded at package initialization.
// Loading RAS may start its Windows service. A passing snapshot is NOT permission
// or proof that dialing is safe; OS/global IPsec and credential policy remain
// outside this read-only metadata check. There is no application wiring.
func InspectSystemEntry(entry PhonebookEntry, expectedGateway string) (EntryEvidence, error) {
	if !validSelection(entry) { return EntryEvidence{}, ErrEntryProperties }
	if _, ok := canonicalGateway(expectedGateway); !ok { return EntryEvidence{}, ErrEntryProperties }
	proc, driveType, attributes, err := systemPropertiesProcs()
	if err != nil { return EntryEvidence{}, err }
	root, err := syscall.UTF16PtrFromString(entry.PhonebookPath[:3])
	if err != nil { return EntryEvidence{}, ErrEntryProperties }
	kind, _, _ := driveType.Call(uintptr(unsafe.Pointer(root)))
	runtime.KeepAlive(root)
	if kind != 3 { return EntryEvidence{}, ErrEntryProperties } // DRIVE_FIXED
	if !checkPhonebookPath(entry.PhonebookPath, func(path string) (uint32, error) {
		pointer, err := syscall.UTF16PtrFromString(path)
		if err != nil { return 0, ErrEntryProperties }
		flags, _, _ := attributes.Call(uintptr(unsafe.Pointer(pointer)))
		runtime.KeepAlive(pointer)
		if uint32(flags) == 0xffffffff { return 0, ErrEntryProperties }
		return uint32(flags), nil
	}) { return EntryEvidence{}, ErrEntryProperties }
	phonebook, err := syscall.UTF16PtrFromString(entry.PhonebookPath)
	if err != nil { return EntryEvidence{}, ErrEntryProperties }
	name, err := syscall.UTF16PtrFromString(entry.Name)
	if err != nil { return EntryEvidence{}, ErrEntryProperties }
	return inspectEntryProperties(func(_ PhonebookEntry, buffer []uint32, size *uint32) uint32 {
		result, _, _ := proc.Call(uintptr(unsafe.Pointer(phonebook)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(size)), 0, 0)
		runtime.KeepAlive(phonebook)
		runtime.KeepAlive(name)
		runtime.KeepAlive(buffer)
		runtime.KeepAlive(size)
		return uint32(result)
	}, entry, expectedGateway)
}

// RevalidateSystemEntry rereads the exact selected entry and compares every
// captured setting and its read-only GUID. It cannot prevent a subsequent race.
func RevalidateSystemEntry(previous EntryEvidence) error {
	current, err := InspectSystemEntry(previous.entry, previous.gateway)
	if err != nil || current.properties != previous.properties { return ErrEntryProperties }
	return nil
}
