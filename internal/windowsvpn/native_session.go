package windowsvpn

import (
	"context"
	"net"
)

// nativeSessionBindings joins reviewed transports and read-only observations.
// These are trusted internal procedures, not user-provided function addresses.
// A dormant system-DLL constructor supplies real transports and inventory; no
// application-default activation exists. All calls are synchronous at
// their invocation boundary; contexts cannot preempt a blocking OS function.
type nativeSessionBindings struct {
	calls      nativeRASCalls
	revalidate func(EntryEvidence) error
	enumerate  enumConnectionsFunc
	status     getConnectionStatusFunc
	projection projectionIPv4Func
	interfaces interfaceSnapshotFunc
	router     *callbackRouter
	notifier   uintptr
}
type nativeSessionOperations struct {
	bindings    nativeSessionBindings
	coordinator *borrowedCoordinator
	notInvoked  *borrowedInputs
	identity    *nativeSessionIdentity
}

type nativeSessionIdentity struct {
	ras     handleIPv4Evidence
	adapter interfaceBinding
}

func newBoundNativeSession(b nativeSessionBindings) (*borrowedCoordinator, error) {
	if b.calls.dial == nil || b.calls.hangup == nil || b.revalidate == nil || b.enumerate == nil || b.status == nil || b.projection == nil || b.interfaces == nil || b.router == nil || b.notifier == 0 {
		return nil, ErrUnavailable
	}
	ops := &nativeSessionOperations{bindings: b}
	c := newBorrowedCoordinator(ops, b.router)
	ops.coordinator = c
	return c, nil
}
func (o *nativeSessionOperations) Revalidate(ctx context.Context, e EntryEvidence) error {
	if ctx.Err() != nil {
		return ErrVerification
	}
	return o.bindings.revalidate(e)
}
func (o *nativeSessionOperations) Begin(ctx context.Context, input *borrowedInputs) (uintptr, uint32) {
	o.notInvoked = nil
	o.identity = nil
	if ctx.Err() != nil {
		o.notInvoked = input
		return 0, 995
	}
	handle, code, err := o.bindings.calls.begin(input, o.bindings.notifier)
	if err != nil {
		o.notInvoked = input
		return 0, 87
	}
	return handle, code
}
func (o *nativeSessionOperations) Hangup(handle uintptr) uint32 {
	code, err := o.bindings.calls.release(handle)
	if err != nil {
		return 87
	}
	return code
}
func (o *nativeSessionOperations) Status(handle uintptr) uint32 {
	status := nativeConnectionStatus{Size: connectionStatusSize}
	return o.bindings.status(handle, &status)
}
func (o *nativeSessionOperations) Quiesce(ctx context.Context, input *borrowedInputs, handle uintptr) error {
	if ctx.Err() != nil {
		return ErrCleanup
	}
	a := o.coordinator.current // caller holds the coordinator's lifecycle gate
	if a == nil || a.inputs != input || a.handle != handle {
		return ErrCleanup
	}
	if input != nil && o.notInvoked == input && handle == 0 {
		// Pre-call cancellation/validation failure has no native input consumer.
		return nil
	}
	return terminatedRASInputs(a)
}
func (o *nativeSessionOperations) Inspect(ctx context.Context, e EntryEvidence, handle uintptr) (borrowedObservation, error) {
	fail := func() (borrowedObservation, error) { return borrowedObservation{}, ErrVerification }
	b := o.bindings
	var first handleIPv4Evidence
	var binding interfaceBinding
	for pass := 0; pass < 2; pass++ {
		if ctx.Err() != nil {
			return fail()
		}
		observation, err := inspectHandleIPv4(e, handle, b.enumerate, b.status, b.projection, b.revalidate)
		if err != nil {
			return fail()
		}
		rows, err := b.interfaces()
		if err != nil {
			return fail()
		}
		match, err := correlateInterface(observation.address, rows)
		if err != nil {
			return fail()
		}
		if pass == 0 {
			first = observation
			binding = match
		} else if observation != first || match != binding {
			return fail()
		}
	}
	// Correlation is point-in-time. Revalidate the RAS side after the final
	// adapter inventory so an inventory callback cannot hide a changed handle.
	last, err := inspectHandleIPv4(e, handle, b.enumerate, b.status, b.projection, b.revalidate)
	if err != nil || last != first || ctx.Err() != nil {
		return fail()
	}
	identity := nativeSessionIdentity{first, binding}
	if o.identity != nil && *o.identity != identity {
		return fail()
	}
	o.identity = &identity
	return borrowedObservation{handle, e.properties.GUID, true, binding.index, net.IP(first.address.AsSlice()), e.gateway}, nil
}
