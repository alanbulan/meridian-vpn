//go:build windows

package windowsvpn

import (
	"syscall"
	"testing"
	"unsafe"
)

// Invoke only our own Go trampoline through the Windows ABI. No RAS DLL or
// function is loaded/called; this neither opens a phonebook nor changes network.
func TestNativeRASCallbackTrampolineABIWithoutRAS(t *testing.T) {
	address, err := nativeRASCallback()
	if err != nil || address == 0 { t.Fatal("callback stub unavailable") }
	second, err := nativeRASCallback()
	if err != nil || second != address { t.Fatal("callback stub not process singleton") }
	// Advance monotonically into the upper half; do not restore/reuse IDs.
	highBit := uintptr(1) << (unsafe.Sizeof(uintptr(0))*8 - 1)
	systemCallbackRouter.mu.Lock()
	if systemCallbackRouter.nextID < highBit { systemCallbackRouter.nextID = highBit }
	systemCallbackRouter.mu.Unlock()
	a, err := systemCallbackRouter.register()
	if err != nil { t.Fatal(err) }
	defer a.retire()
	want := callbackEvent{0xfedcba98, ^uintptr(0)-7, 0x87654321, 0xabcdef01, 0xffffffff, 0x80000000}
	result, _, _ := syscall.SyscallN(address, a.id, uintptr(want.subEntry), want.handle, uintptr(want.message), uintptr(want.state), uintptr(want.code), uintptr(want.extendedCode))
	if result != 1 { t.Fatal("native callback returned wrong continuation flag") }
	got, err := a.next(callbackTestContext(t))
	if err != nil || got != want { t.Fatal("native callback argument ABI mismatch") }
	a.retire()
	result, _, _ = syscall.SyscallN(address, a.id, 1, 0x4321, 0xcccd, 0x2000, 0, 0)
	if result != 0 { t.Fatal("native late callback accepted") }
}

func TestNativeRASCallbackContainsRecoverablePanic(t *testing.T) {
	address, err := nativeRASCallback()
	if err != nil { t.Fatal(err) }
	a, err := systemCallbackRouter.register()
	if err != nil { t.Fatal(err) }
	defer a.retire()
	// Inject an impossible-in-production closed mailbox to make both dispatch
	// and failure notification panic. Neither may cross the native ABI frame.
	systemCallbackRouter.mu.Lock()
	close(a.wake)
	systemCallbackRouter.mu.Unlock()
	defer func() {
		systemCallbackRouter.mu.Lock()
		a.wake = make(chan struct{}, 1)
		systemCallbackRouter.mu.Unlock()
	}()
	result, _, _ := syscall.SyscallN(address, a.id, 1, 42, 0xcccd, 0, 0, 0)
	if result != 0 { t.Fatal("panic did not stop callback notifications") }
	if _, err := a.next(callbackTestContext(t)); err != errCallback { t.Fatal("panic did not fault route") }
}
