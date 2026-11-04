package windowsvpn

import (
	"context"
	"net"
	"sync"
	"time"
)

// Borrowed mode never creates, edits or deletes profiles or PSKs. All grants
// are per attempt. A future UI must disclose possible Windows credential
// persistence, shared references, and retention of pinned inputs while cleanup
// is uncertain. These flags alone do not prove native calls safe or implemented.
type borrowedConsent struct{ network, credentialPersistence, sharedReference bool }

type borrowedObservation struct {
	handle         uintptr
	entryGUID      [16]byte
	connected      bool
	interfaceIndex uint32
	address        net.IP
	gateway        string
}

// borrowedOperations is a TRUSTED injected boundary, not supplied by end users.
// The explicit limited-mode native binding implements this contract. Begin may
// use pinned inputs until
// Quiesce confirms every native consumer has stopped; its immediate return,
// callback terminal state and callback retirement do not establish that fact.
// Operations must not replace/resize storage fields, copy the Pinner, unpin it,
// or erase inputs; storage ownership remains exclusively with this coordinator.
// Begin's context applies to the initial invocation only. It must return before
// cleanup can proceed; the coordinator does not detach a blocked native call.
// Quiesce must not infer completion from ctx cancellation or route retirement.
// Inspect must bind fresh profile/handle/gateway/interface/address evidence,
// not just return a connected flag. Native functions must not log credentials.
// No credential/profile mutation or deletion operation is available here.
type borrowedOperations interface {
	Revalidate(context.Context, EntryEvidence) error
	Begin(context.Context, *borrowedInputs) (uintptr, uint32)
	Hangup(uintptr) uint32
	Status(uintptr) uint32
	Quiesce(context.Context, *borrowedInputs, uintptr) error
	Inspect(context.Context, EntryEvidence, uintptr) (borrowedObservation, error)
}

type borrowedAttempt struct {
	entry                                      EntryEvidence
	callback                                   *callbackRegistration
	inputs                                     *borrowedInputs
	reference                                  *dialReference
	beginCalled, returnKnown, releaseOK, ready bool
	handle                                     uintptr
	code                                       uint32
}

// This unexported coordinator is not a core.Adapter and never loads RAS. It
// joins lifetime/consent contracts using injected operations only. It cannot
// authorize a production dial or claim routing/DNS correctness or isolation.
type borrowedCoordinator struct {
	gate     chan struct{}
	mu       sync.Mutex
	cancel   context.CancelFunc
	stopping int
	current  *borrowedAttempt
	router   *callbackRouter
	ops      borrowedOperations
}

func newBorrowedCoordinator(ops borrowedOperations, router *callbackRouter) *borrowedCoordinator {
	// A future native implementation must supply the exact router behind its
	// process-lifetime trampoline. There is deliberately no default native path.
	return &borrowedCoordinator{gate: make(chan struct{}, 1), router: router, ops: ops}
}

func (c *borrowedCoordinator) acquire(ctx context.Context) error {
	if c == nil || c.gate == nil || ctx == nil {
		return ErrOperation
	}
	select {
	case c.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *borrowedCoordinator) unlock() { <-c.gate }

func (c *borrowedCoordinator) start(ctx context.Context, entry EntryEvidence, username, domain string, password []byte, consent borrowedConsent) error {
	if !consent.network || !consent.credentialPersistence || !consent.sharedReference {
		return ErrAuthorization
	}
	if entry.properties.GUID == [16]byte{} || !validSelection(entry.entry) || !supportedEntry(entry.properties, entry.gateway) {
		return ErrVerification
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.unlock()
	c.mu.Lock()
	if c.current != nil || c.stopping != 0 {
		c.mu.Unlock()
		return ErrBusy
	}
	if nilValue(c.ops) || c.router == nil {
		c.mu.Unlock()
		return ErrUnavailable
	}
	op, cancel := context.WithTimeout(ctx, 90*time.Second)
	c.cancel = cancel
	a := &borrowedAttempt{entry: entry, reference: newDialReference()}
	c.current = a
	c.mu.Unlock()
	defer func() { cancel(); c.mu.Lock(); c.cancel = nil; c.mu.Unlock() }()
	fail := func(cause error) error {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c.cleanup(cleanup) != nil {
			return ErrCleanup
		}
		return cause
	}
	if err := op.Err(); err != nil {
		return fail(err)
	}
	if guardedError(func() error { return c.ops.Revalidate(op, entry) }) != nil {
		return fail(ErrVerification)
	}
	var err error
	a.callback, err = c.router.register()
	if err != nil {
		return fail(ErrOperation)
	}
	a.inputs, err = newBorrowedInputs(entry.entry, username, domain, password, a.callback.id)
	if err != nil {
		return fail(err)
	}
	if err := op.Err(); err != nil {
		return fail(err)
	}
	a.beginCalled = true
	if guardedError(func() error {
		a.handle, a.code = c.ops.Begin(op, a.inputs)
		a.returnKnown = true
		return a.reference.recordDialReturn(a.handle, a.code)
	}) != nil {
		return fail(ErrOperation)
	}
	if a.code != 0 {
		return fail(ErrOperation)
	}
	if err := op.Err(); err != nil {
		return fail(err)
	}
	for {
		event, err := a.callback.next(op)
		if err != nil {
			if op.Err() != nil {
				return fail(op.Err())
			}
			return fail(ErrOperation)
		}
		if event.handle != a.handle || event.handle == 0 || event.subEntry > 1 || event.message != 0xcccd {
			return fail(ErrVerification)
		}
		if event.code != 0 || event.extendedCode != 0 || event.state == 0x2001 {
			return fail(ErrOperation)
		}
		if event.state&0x1000 != 0 {
			return fail(ErrUnsupported)
		} // No paused-state prompts/restarts.
		if event.state != rasConnected {
			continue
		}
		if c.verify(op, a) != nil || !a.confirmReady(op) {
			return fail(ErrVerification)
		}
		if err := op.Err(); err != nil {
			return fail(err)
		}
		return nil
	}
}

// guardedError prevents an injected/native panic or raw error from bypassing
// the coordinator's uncertainty tracking. It must not be used to claim success.
func guardedError(call func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrOperation
		}
	}()
	return call()
}

// confirmReady linearizes readiness against callback admission. Every queued
// event after Connected must still match the direct result and connected state.
// A failure is sticky, even if later callbacks report Connected again. This is
// a point-in-time check, not a promise that native state cannot later change.
func (a *borrowedAttempt) confirmReady(ctx context.Context) bool {
	if a.callback == nil {
		return false
	}
	r := a.callback.router
	r.mu.Lock()
	defer r.mu.Unlock()
	registration := a.callback
	if r.attempts[registration.id] != registration || registration.faulted || registration.retired || ctx.Err() != nil {
		a.ready = false
		return false
	}
	for _, event := range registration.events {
		if event.handle != a.handle || event.handle == 0 || event.subEntry > 1 || event.message != 0xcccd ||
			event.code != 0 || event.extendedCode != 0 || event.state != rasConnected {
			registration.faulted = true
			a.ready = false
			return false
		}
	}
	clear(registration.events)
	registration.events = registration.events[:0]
	a.ready = true
	return true
}

func (c *borrowedCoordinator) verify(ctx context.Context, a *borrowedAttempt) error {
	if ctx.Err() != nil {
		return ErrVerification
	}
	if guardedError(func() error { return c.ops.Revalidate(ctx, a.entry) }) != nil {
		return ErrVerification
	}
	var o borrowedObservation
	if guardedError(func() error { var err error; o, err = c.ops.Inspect(ctx, a.entry, a.handle); return err }) != nil {
		return ErrVerification
	}
	ip := o.address
	if o.handle != a.handle || o.entryGUID != a.entry.properties.GUID || !o.connected || o.interfaceIndex == 0 || ip == nil ||
		(ip.To4() == nil && ip.To16() == nil) || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return ErrVerification
	}
	gateway, ok := canonicalGateway(o.gateway)
	if !ok || gateway != a.entry.gateway {
		return ErrVerification
	}
	if guardedError(func() error { return c.ops.Revalidate(ctx, a.entry) }) != nil || ctx.Err() != nil {
		return ErrVerification
	}
	return nil
}

func (c *borrowedCoordinator) check(ctx context.Context) error {
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.unlock()
	c.mu.Lock()
	if c.stopping != 0 {
		c.mu.Unlock()
		return ErrBusy
	}
	a := c.current
	op, cancel := context.WithTimeout(ctx, 10*time.Second)
	c.cancel = cancel
	c.mu.Unlock()
	defer func() { cancel(); c.mu.Lock(); c.cancel = nil; c.mu.Unlock() }()
	if a == nil || !a.ready {
		return ErrVerification
	}
	if c.verify(op, a) != nil || !a.confirmReady(op) {
		a.ready = false
		if c.cleanup(ctx) != nil {
			return ErrCleanup
		}
		return ErrVerification
	}
	return nil
}

func (c *borrowedCoordinator) stop(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrCleanup
	}
	c.mu.Lock()
	c.stopping++
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.stopping--; c.mu.Unlock() }()
	if c.acquire(ctx) != nil {
		return ErrCleanup
	}
	defer c.unlock()
	return c.cleanup(ctx)
}

// One cleanup call performs at most one termination probe, never a busy loop.
// Later Stop retries may probe/quiesce again, but never repeat Hangup. A shared
// surviving handle keeps this conservative implementation quarantined; it never
// disconnects another reference to make the handle disappear.
func (c *borrowedCoordinator) cleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c.mu.Lock()
	a := c.current
	c.mu.Unlock()
	if a == nil {
		return nil
	}
	a.ready = false
	if a.callback != nil {
		a.callback.retire()
	}
	if a.beginCalled {
		if !a.returnKnown || (a.handle == 0 && a.code == 0) || ctx.Err() != nil {
			return ErrCleanup
		}
		if a.handle != 0 {
			if !a.releaseOK {
				if guardedError(func() error { return a.reference.release(c.ops.Hangup) }) != nil {
					return ErrCleanup
				}
				a.releaseOK = true
			}
			if guardedError(func() error { return a.reference.checkTermination(c.ops.Status) }) != nil {
				return ErrCleanup
			}
			if terminatedRASInputs(a) != nil {
				return ErrCleanup
			}
		}
		if guardedError(func() error { return c.ops.Quiesce(ctx, a.inputs, a.handle) }) != nil || ctx.Err() != nil {
			return ErrCleanup
		}
	}
	a.inputs.releaseAfterQuiescence()
	c.mu.Lock()
	if c.current == a {
		c.current = nil
	}
	c.mu.Unlock()
	return nil
}
