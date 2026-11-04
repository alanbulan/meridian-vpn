package windowsvpn

import (
	"encoding/binary"
	"runtime"
	"sync"
	"unsafe"
)

// Quarantined storage must survive even if a caller drops its coordinator.
// Otherwise a Pinner finalizer could panic or a native consumer could outlive
// the only Go owner. This bounded process anchor is removed only after the
// trusted injected boundary establishes quiescence and reference cleanup.
// It is not native isolation, encrypted storage or a crash-recovery mechanism.
var borrowedInputAnchor = struct {
	sync.Mutex
	active map[*borrowedInputs]struct{}
}{active: make(map[*borrowedInputs]struct{})}

const maxBorrowedInputs = 32

type borrowedInputs struct {
	phonebook  []uint16
	parameters []uint32
	pinner     runtime.Pinner
	released   bool
}

func newBorrowedInputs(entry PhonebookEntry, username, domain string, password []byte, callbackID uintptr) (*borrowedInputs, error) {
	if callbackID == 0 {
		return nil, ErrOperation
	}
	borrowedInputAnchor.Lock()
	defer borrowedInputAnchor.Unlock()
	if len(borrowedInputAnchor.active) >= maxBorrowedInputs {
		return nil, ErrBusy
	}
	phonebook, parameters, err := marshalDialParameters(entry, username, domain, password)
	if err != nil {
		return nil, err
	}
	input := &borrowedInputs{phonebook: phonebook, parameters: parameters}
	layout, _ := rasDialParameterLayout(int(unsafe.Sizeof(uintptr(0))))
	if unsafe.Sizeof(uintptr(0)) == 8 {
		binary.LittleEndian.PutUint64(wordBytes(parameters)[layout.callbackID:], uint64(callbackID))
	} else {
		binary.LittleEndian.PutUint32(wordBytes(parameters)[layout.callbackID:], uint32(callbackID))
	}
	input.pinner.Pin(&phonebook[0])
	input.pinner.Pin(&parameters[0])
	borrowedInputAnchor.active[input] = struct{}{}
	return input, nil
}

// Only the coordinator's proven-cleanup path (or pre-Begin failure) may call
// this. Callback retirement and a successful initial dial return do not suffice.
// Serialized with anchor accounting; independent aliases cannot unpin twice.
func (input *borrowedInputs) releaseAfterQuiescence() {
	if input == nil {
		return
	}
	borrowedInputAnchor.Lock()
	defer borrowedInputAnchor.Unlock()
	if input.released {
		return
	}
	if _, owned := borrowedInputAnchor.active[input]; !owned {
		// A value-copy is not the anchored owner, even if it aliases buffers.
		return
	}
	clear(input.parameters)
	clear(input.phonebook)
	input.pinner.Unpin()
	input.released = true
	delete(borrowedInputAnchor.active, input)
	runtime.KeepAlive(input)
}
