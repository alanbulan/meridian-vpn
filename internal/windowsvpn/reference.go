package windowsvpn

import (
	"errors"
	"sync"
)

var errReleaseConsumed = errors.New("RAS reference release was already attempted; it must not be repeated")

const rasInvalidHandle = uint32(6)

// dialReference is an unexported, injected bookkeeping primitive for ONE
// future RasDial invocation. It does not call RasDial, reserve an entry, prove
// ownership/exclusivity or authorize any OS operation. It is not wired to the
// Controller or a native driver. No secrets or filesystem paths are stored.
//
// Only the direct return from that invocation may be recorded. An enumerated
// handle, callback handle or a previous attempt's handle is NOT a new reference.
// Every nonzero direct result is a debt, even when RasDial reports an error.
// Actual native provenance/callback lifetime remains unimplemented and must be
// established before using this primitive with real system functions.
// Copies of the wrapper share the same ledger. Retain one constructor result
// per direct RasDial invocation; never create a second ledger for one result.
// The zero value is deliberately unusable rather than lazily creating debt.
type dialReference struct { state *dialReferenceState }

type dialReferenceState struct {
	mu sync.Mutex
	returned, tainted bool
	handle uintptr
	dialCode uint32
	releaseAttempted, releaseReturned bool
	releaseCode uint32
	polling, terminated bool
}

func newDialReference() *dialReference { return &dialReference{state: &dialReferenceState{}} }

func (reference *dialReference) recordDialReturn(handle uintptr, code uint32) error {
	if reference == nil || reference.state == nil { return ErrOperation }
	r := reference.state
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.returned {
		// Never replace the first handle. Its one release obligation remains,
		// but a duplicate/misrouted completion forbids cleanup consideration.
		r.tainted = true
		return ErrOperation
	}
	r.returned, r.handle, r.dialCode = true, handle, code
	if handle == 0 && code == 0 { r.tainted = true; return ErrOperation }
	return nil
}

// release invokes the injected hangup function at most once, for the immutable
// direct-result handle. Mark consumption BEFORE crossing the native boundary:
// neither an error, panic/uncertain outcome nor concurrent Stop may reissue it.
// This is distinct from retrying termination probes or owned-object cleanup.
// No production hangup function is provided by this package.
func (reference *dialReference) release(hangup func(uintptr) uint32) error {
	if reference == nil || reference.state == nil { return ErrCleanup }
	r := reference.state
	r.mu.Lock()
	if !r.returned || r.handle == 0 || hangup == nil { r.mu.Unlock(); return ErrCleanup }
	if r.releaseAttempted { r.mu.Unlock(); return errReleaseConsumed }
	r.releaseAttempted = true
	handle := r.handle
	r.mu.Unlock()
	code := hangup(handle)
	r.mu.Lock()
	r.releaseCode, r.releaseReturned = code, true
	r.mu.Unlock()
	if code != 0 { return ErrCleanup }
	return nil
}

// checkTermination performs at most one injected status query per call. Only
// ERROR_INVALID_HANDLE proves this reference's required asynchronous termination
// check. ERROR_SUCCESS plus a disconnected state is not enough. An API error,
// surviving/shared/reused handle or uncertain hangup leaves cleanup blocked.
// A future driver supplies its own cancellation/deadline around repeated probes;
// this function does not turn a blocking native query into cancellable work.
func (reference *dialReference) checkTermination(status func(uintptr) uint32) error {
	if reference == nil || reference.state == nil { return ErrCleanup }
	r := reference.state
	r.mu.Lock()
	if !r.releaseReturned || r.releaseCode != 0 || r.tainted || status == nil { r.mu.Unlock(); return ErrCleanup }
	if r.terminated { r.mu.Unlock(); return nil }
	if r.polling { r.mu.Unlock(); return ErrBusy }
	r.polling = true
	handle := r.handle
	r.mu.Unlock()
	// Ensure a failing injected boundary cannot leave polling permanently busy.
	// It still cannot cause a second release or claim termination.
	defer func() { r.mu.Lock(); r.polling = false; r.mu.Unlock() }()
	code := status(handle)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tainted || code != rasInvalidHandle { return ErrCleanup }
	r.terminated = true
	return nil
}

// referenceTerminationConfirmed is only an ordering prerequisite before a
// future driver may CONSIDER cleanup of its own objects. It is not permission
// to clear credentials/delete entries: native consumers must separately be
// quiescent, and object ownership, identity, isolation and cleanup effects need
// proof. In particular, this does not establish an exclusive RAS connection.
// A failed dial returning no handle has no reference to release, but this
// method does not authorize cleanup or infer callback quiescence in that case.
func (reference *dialReference) referenceTerminationConfirmed() bool {
	if reference == nil || reference.state == nil { return false }
	r := reference.state
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.returned && r.handle != 0 && r.releaseReturned && r.releaseCode == 0 && r.terminated && !r.tainted
}
