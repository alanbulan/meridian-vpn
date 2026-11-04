//go:build windows

package windowsvpn

import (
	"syscall"
	"testing"
)

// No RAS DLL lookup or call: both function pointers are our own Go stubs.
func TestNativeRASTransportABIWithoutRAS(t *testing.T) {
	input, err := newBorrowedInputs(fixtureEntry(), "user", "", []byte("secret"), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer input.releaseAfterQuiescence()
	wantHandle := ^uintptr(0) - 17
	wantNotifier := ^uintptr(0) - 31
	var dialCount, hangupCount int
	var argsOK, hangupOK bool
	dial := syscall.NewCallback(func(extensions uintptr, pb *uint16, params *uint32, kind, notifier uintptr, output *uintptr) uintptr {
		dialCount++
		argsOK = extensions == 0 && pb == &input.phonebook[0] && params == &input.parameters[0] && kind == 2 && notifier == wantNotifier && output != nil && *output == 0
		if output != nil {
			*output = wantHandle
		}
		// Include upper bits on 64-bit: DWORD, not uintptr, is the API return.
		return ^uintptr(0)
	})
	hangup := syscall.NewCallback(func(handle uintptr) uintptr {
		hangupCount++
		hangupOK = handle == wantHandle
		return 6
	})
	calls, err := nativeRASTransport(dial, hangup)
	if err != nil {
		t.Fatal(err)
	}
	handle, code, err := calls.begin(input, wantNotifier)
	if err != nil || !argsOK || dialCount != 1 || handle != wantHandle || code != 0xffffffff {
		t.Fatal("RasDialW transport ABI mismatch")
	}
	code, err = calls.release(handle)
	if err != nil || !hangupOK || hangupCount != 1 || code != 6 {
		t.Fatal("RasHangUpW transport ABI mismatch")
	}
	if inputsZero(input) {
		t.Fatal("transport released coordinator inputs")
	}
}

func TestNativeRASTransportRejectsMissingAddresses(t *testing.T) {
	for _, addresses := range [][2]uintptr{{0, 0}, {1, 0}, {0, 1}} {
		if _, err := nativeRASTransport(addresses[0], addresses[1]); err == nil {
			t.Fatal("missing procedure accepted")
		}
	}
}
