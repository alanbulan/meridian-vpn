package windowsvpn

// terminatedRASInputs verifies the ordinary conservative RAS cleanup endpoint:
// the initial call returned, its one HangUp succeeded, status confirmed deletion,
// and this attempt's callback route is retired. Microsoft's Disconnecting
// contract allows process exit at the deletion endpoint. Inference: standard
// RAS input storage can be reclaimed then; a surviving shared handle is NOT
// such evidence and must never trigger another HangUp to force deletion.
//
// This is NOT native stack quiescence: the process-lifetime callback trampoline
// may still have a scalar-only return frame. Retired routing prevents that frame
// or future callbacks from touching attempt state or credentials. Additional
// custom consumers outside this transport still require their own Quiesce join.
// No memory is erased or unpinned here and no OS function is called.
func terminatedRASInputs(a *borrowedAttempt) error {
	if a == nil || !a.beginCalled || !a.returnKnown || a.handle == 0 || a.callback == nil ||
		a.callback.router == nil || a.reference == nil || a.reference.state == nil {
		return ErrCleanup
	}
	// Bind the confirmation to this attempt's exact immutable direct result.
	state := a.reference.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.returned || !state.releaseReturned || state.releaseCode != 0 ||
		!state.terminated || state.tainted || state.handle != a.handle || state.dialCode != a.code {
		return ErrCleanup
	}
	r := a.callback.router
	r.mu.Lock()
	defer r.mu.Unlock()
	if !a.callback.retired || r.attempts[a.callback.id] != nil {
		return ErrCleanup
	}
	return nil
}
