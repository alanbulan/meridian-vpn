package windowsvpn

import (
	"context"
	"errors"
	"sync"
)

var errCallback = errors.New("Windows RAS callback routing is unavailable or incomplete")

const (
	maxCallbackAttempts = 32
	maxCallbackEvents = 16
)

// callbackEvent is untrusted scalar notification data, never an acquired RAS
// reference or evidence of connection readiness. It carries no credential data.
type callbackEvent struct {
	subEntry uint32
	handle uintptr
	message, state, code, extendedCode uint32
}

// callbackRouter routes one process-lifetime trampoline by nonzero integer IDs.
// IDs are never reused, including after retirement; exhaustion fails closed.
// It does not own native input buffers, dial, hang up or prove OS quiescence.
type callbackRouter struct {
	mu sync.Mutex
	nextID uintptr
	attempts map[uintptr]*callbackRegistration
}

type callbackRegistration struct {
	router *callbackRouter
	id uintptr
	// The router mutex protects all fields below except channel operations.
	events []callbackEvent
	wake chan struct{}
	retired, faulted bool
}

func newCallbackRouter() *callbackRouter {
	return &callbackRouter{nextID: 1, attempts: make(map[uintptr]*callbackRegistration)}
}

func (r *callbackRouter) register() (*callbackRegistration, error) {
	if r == nil { return nil, errCallback }
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nextID == 0 || r.attempts == nil || len(r.attempts) >= maxCallbackAttempts { return nil, errCallback }
	id := r.nextID
	r.nextID++ // Wrapping to zero permanently disables registration.
	a := &callbackRegistration{router: r, id: id, wake: make(chan struct{}, 1), events: make([]callbackEvent, 0, maxCallbackEvents)}
	r.attempts[id] = a
	return a, nil
}

// dispatch never invokes application code or waits for an event consumer. The
// mutex bounds admission/retirement to short in-memory operations. Overflow is
// an explicit fault, not silent loss of a terminal event. Zero tells RAS to stop
// notifications; it is NOT cancellation or permission to free native inputs.
func (r *callbackRouter) dispatch(id uintptr, event callbackEvent) uintptr {
	if r == nil { return 0 }
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.attempts[id]
	if a == nil || a.retired || a.faulted { return 0 }
	if len(a.events) == maxCallbackEvents {
		a.faulted = true
		clear(a.events)
		a.events = nil
		a.signal()
		return 0
	}
	a.events = append(a.events, event)
	a.signal()
	return 1
}

func (a *callbackRegistration) signal() {
	select { case a.wake <- struct{}{}: default: }
}

func (r *callbackRouter) fault(id uintptr) {
	if r == nil { return }
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.attempts[id]; a != nil {
		a.faulted = true
		clear(a.events)
		a.events = nil
		a.signal()
	}
}

// next observes notifications only. Canceling the wait does not retire the ID,
// stop native work, consume a reference, or authorize freeing password buffers.
// One lifecycle consumer should read a registration; callbacks may be concurrent.
func (a *callbackRegistration) next(ctx context.Context) (callbackEvent, error) {
	if a == nil || a.router == nil || ctx == nil { return callbackEvent{}, errCallback }
	for {
		if err := ctx.Err(); err != nil { return callbackEvent{}, err }
		a.router.mu.Lock()
		if a.retired || a.faulted || a.router.attempts[a.id] != a {
			a.router.mu.Unlock()
			return callbackEvent{}, errCallback
		}
		if len(a.events) > 0 {
			event := a.events[0]
			copy(a.events, a.events[1:])
			a.events[len(a.events)-1] = callbackEvent{}
			a.events = a.events[:len(a.events)-1]
			a.router.mu.Unlock()
			return event, nil
		}
		a.router.mu.Unlock()
		select { case <-ctx.Done(): return callbackEvent{}, ctx.Err(); case <-a.wake: }
	}
}

// retire serializes with admitted dispatch bodies and discards their queued
// events. Later callbacks cannot reacquire this registration. This only closes
// the Go event route: a native callback stack or RAS input consumer may still
// exist. Do not infer native quiescence, hangup completion or buffer-release
// permission. No callback function pointer is freed; the trampoline lives for
// the process. Retirement is idempotent and safe through wrapper aliases.
func (a *callbackRegistration) retire() {
	if a == nil || a.router == nil { return }
	a.router.mu.Lock()
	defer a.router.mu.Unlock()
	if a.router.attempts[a.id] != a { return }
	delete(a.router.attempts, a.id)
	a.retired = true
	clear(a.events)
	a.events = nil
	a.signal()
}
