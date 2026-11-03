//go:build windows

package windowsvpn

import (
 "runtime"
 "sync"
 "syscall"
 "unsafe"
)

// Resolve and load system DLLs at most once, on the first explicit discovery.
// Cached failure is fail-closed for this process; no repeated loader side effects.
var systemEntries struct {
 once sync.Once
 proc *syscall.LazyProc
 err error
}

func systemEnumerationProc() (*syscall.LazyProc,error) {
 systemEntries.once.Do(func() {
 // kernel32 is a Windows KnownDLL. Resolve Rasapi32 from the system directory,
 // never from the current working directory or an attacker-controlled PATH.
 kernel := syscall.NewLazyDLL("kernel32.dll")
 systemDirectory := kernel.NewProc("GetSystemDirectoryW")
 if err := systemDirectory.Find(); err != nil { systemEntries.err = ErrEnumeration; return }
 directory := make([]uint16,32768)
 n,_,_ := systemDirectory.Call(uintptr(unsafe.Pointer(&directory[0])),uintptr(len(directory)))
 runtime.KeepAlive(directory)
 if n == 0 || n >= uintptr(len(directory)) { systemEntries.err = ErrEnumeration; return }
 path,ok := fixedUTF16(directory)
 if !ok || path == "" { systemEntries.err = ErrEnumeration; return }
 ras := syscall.NewLazyDLL(path + `\rasapi32.dll`)
 proc := ras.NewProc("RasEnumEntriesW")
 if err := proc.Find(); err != nil { systemEntries.err = ErrEnumeration; return }

 systemEntries.proc = proc
 })
 return systemEntries.proc,systemEntries.err
}

// EnumerateSystemEntries discovers existing current-user and all-user RAS
// phonebooks using RasEnumEntriesW. It does not dial, inspect credentials, write
// phonebooks, or claim entries are compatible VPNs. No DLL is loaded at init.
// Names and paths may identify people or organizations: never log or export
// results automatically. Paths are retained only to disambiguate entry identity.
func EnumerateSystemEntries() ([]PhonebookEntry,error) {
 proc,err := systemEnumerationProc()
 if err != nil { return nil,err }
 return enumerateEntries(func(entries []nativeEntryName, size,count *uint32) uint32 {
  var pointer unsafe.Pointer
  if len(entries) != 0 { pointer = unsafe.Pointer(&entries[0]) }
  result,_,_ := proc.Call(0,0,uintptr(pointer),uintptr(unsafe.Pointer(size)),uintptr(unsafe.Pointer(count)))
  runtime.KeepAlive(entries)
  runtime.KeepAlive(size)
  runtime.KeepAlive(count)
  return uint32(result)
 })
}
