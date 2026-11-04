package windowsvpn

import (
	"encoding/binary"
	"runtime"
	"unsafe"
)

// nativeRASCalls is only the direct-call transport, not borrowedOperations.
// It has no Quiesce implementation and cannot enable the production adapter.
// Functions are trusted, synchronous invocation boundaries: asynchronous native
// consumers may continue using inputs afterward, which remain coordinator-owned.
type nativeRASCalls struct {
	dial   func(*uint16, *uint32, uintptr, *uintptr) uint32
	hangup func(uintptr) uint32
}

func (calls nativeRASCalls) begin(inputs *borrowedInputs, notifier uintptr) (uintptr, uint32, error) {
	if calls.dial == nil || notifier == 0 || !liveDialInputs(inputs) {
		return 0, 0, ErrOperation
	}
	// Never seed a handle to reconnect/restart an existing connection. A nonzero
	// direct output is returned even alongside an error and must be released once.
	var handle uintptr
	code := calls.dial(&inputs.phonebook[0], &inputs.parameters[0], notifier, &handle)
	runtime.KeepAlive(inputs)
	runtime.KeepAlive(&handle)
	return handle, code, nil
}

func (calls nativeRASCalls) release(handle uintptr) (uint32, error) {
	if calls.hangup == nil || handle == 0 {
		return 0, ErrOperation
	}
	// No retries or ownership inference here. The reference ledger must authorize
	// exactly one call; enumeration and callback handles are not release authority.
	return calls.hangup(handle), nil
}

// Trusted callers must serialize ownership through the coordinator. This check
// rejects released/value-copied storage but is not a lease against misuse by a
// concurrent internal caller that releases buffers while an invocation is active.
func liveDialInputs(input *borrowedInputs) bool {
	if input == nil {
		return false
	}
	borrowedInputAnchor.Lock()
	defer borrowedInputAnchor.Unlock()
	if _, ok := borrowedInputAnchor.active[input]; !ok || input.released {
		return false
	}
	layout, ok := rasDialParameterLayout(int(unsafe.Sizeof(uintptr(0))))
	if !ok || len(input.parameters)*4 != layout.size || input.parameters[0] != uint32(layout.size) ||
		len(input.phonebook) < 2 || input.phonebook[len(input.phonebook)-1] != 0 {
		return false
	}
	b := wordBytes(input.parameters)
	var id uint64
	if unsafe.Sizeof(uintptr(0)) == 8 {
		id = binary.LittleEndian.Uint64(b[layout.callbackID:])
	} else {
		id = uint64(binary.LittleEndian.Uint32(b[layout.callbackID:]))
	}
	return id != 0
}
