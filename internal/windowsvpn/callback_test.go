package windowsvpn

import (
	"context"
	"sync"
	"testing"
	"time"
)

func callbackTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCallbackRoutesScalarsWithoutInferringStateOrOwnership(t *testing.T) {
	router := newCallbackRouter()
	a, err := router.register()
	if err != nil || a.id == 0 { t.Fatal("registration failed") }
	defer a.retire()
	// Sparse, reordered, duplicate and error states are copied, not interpreted
	// as readiness or a reference. None requires an earlier direct dial return.
	for _, event := range []callbackEvent{
		{1, 42, 0xcccd, rasConnected, 0, 0},
		{1, 42, 0xcccd, 1, 0, 0},
		{1, 42, 0xcccd, 1, 0, 0},
		{1, 42, 0xcccd, 0x2001, 691, 99},
	} {
		if router.dispatch(a.id, event) != 1 { t.Fatal("notification rejected") }
		got, err := a.next(callbackTestContext(t))
		if err != nil || got != event { t.Fatal("scalar notification changed") }
	}
	if router.dispatch(0, callbackEvent{}) != 0 || router.dispatch(a.id+1, callbackEvent{}) != 0 { t.Fatal("unknown ID accepted") }
}

func TestCallbackOverflowFailsClosedAndRemainsBounded(t *testing.T) {
	router := newCallbackRouter()
	a, _ := router.register()
	defer a.retire()
	for i := 0; i < maxCallbackEvents; i++ {
		if router.dispatch(a.id, callbackEvent{state: uint32(i)}) != 1 { t.Fatal("queue prematurely full") }
	}
	if router.dispatch(a.id, callbackEvent{state: rasConnected}) != 0 { t.Fatal("overflow silently lost event") }
	if _, err := a.next(callbackTestContext(t)); err != errCallback { t.Fatal("overflow did not invalidate pending observations") }
	if router.dispatch(a.id, callbackEvent{}) != 0 { t.Fatal("faulted attempt resumed notifications") }
	if len(a.events) != 0 { t.Fatal("fault retained events") }
}

func TestCallbackRetirementRejectsLateEventsAndNeverReusesIDs(t *testing.T) {
	router := newCallbackRouter()
	a, _ := router.register()
	_ = router.dispatch(a.id, callbackEvent{handle: 42})
	a.retire()
	a.retire()
	if router.dispatch(a.id, callbackEvent{handle: 99}) != 0 { t.Fatal("late event reactivated retired attempt") }
	if _, err := a.next(callbackTestContext(t)); err != errCallback { t.Fatal("retired event delivered") }
	b, err := router.register()
	if err != nil || b.id == a.id { t.Fatal("callback ID reused") }
	defer b.retire()
	if router.dispatch(a.id, callbackEvent{}) != 0 { t.Fatal("old callback reached newer attempt") }
	if len(b.events) != 0 { t.Fatal("old callback polluted new attempt") }
}

func TestCallbackCapacityAndIDExhaustionFailClosed(t *testing.T) {
	router := newCallbackRouter()
	var registrations []*callbackRegistration
	for i := 0; i < maxCallbackAttempts; i++ {
		a, err := router.register()
		if err != nil { t.Fatal(err) }
		registrations = append(registrations, a)
	}
	if _, err := router.register(); err != errCallback { t.Fatal("registry exceeded bound") }
	for _, a := range registrations { a.retire() }
	if len(router.attempts) != 0 { t.Fatal("retired registry entries retained") }
	router.nextID = ^uintptr(0)
	last, err := router.register()
	if err != nil || last.id != ^uintptr(0) { t.Fatal("last token not issued") }
	last.retire()
	if _, err := router.register(); err != errCallback { t.Fatal("wrapped ID reused") }
	var zero callbackRouter
	if _, err := zero.register(); err != errCallback { t.Fatal("zero router accepted") }
	if zero.dispatch(1, callbackEvent{}) != 0 { t.Fatal("zero router dispatched") }
}

func TestCallbackCancellationOnlyCancelsObserver(t *testing.T) {
	router := newCallbackRouter()
	a, _ := router.register()
	defer a.retire()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.next(ctx); err != context.Canceled { t.Fatal("cancel ignored") }
	// Cancellation before direct RasDial return does not consume future
	// notifications, retire the route or manufacture a handle to hang up.
	if router.dispatch(a.id, callbackEvent{handle: 73}) != 1 { t.Fatal("observer cancellation retired attempt") }
	if got, err := a.next(callbackTestContext(t)); err != nil || got.handle != 73 { t.Fatal("post-cancel observation lost") }
}

func TestCallbackConcurrentRetirementAndDispatch(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		router := newCallbackRouter()
		a, _ := router.register()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; router.dispatch(a.id, callbackEvent{handle: 42}) }()
		}
		wg.Add(1)
		go func() { defer wg.Done(); <-start; a.retire() }()
		close(start)
		wg.Wait()
		if len(router.attempts) != 0 || len(a.events) != 0 { t.Fatal("retirement left admitted event state") }
		if router.dispatch(a.id, callbackEvent{}) != 0 { t.Fatal("late callback accepted") }
	}
}

func TestCallbackRetirementAndFaultWakeWaiter(t *testing.T) {
	for _, fault := range []bool{false, true} {
		router := newCallbackRouter()
		a, _ := router.register()
		result := make(chan error, 1)
		ctx := callbackTestContext(t)
		go func() { _, err := a.next(ctx); result <- err }()
		if fault { router.fault(a.id) } else { a.retire() }
		select {
		case err := <-result: if err != errCallback { t.Fatal("waiter did not receive route fault") }
		case <-ctx.Done(): t.Fatal("waiter stranded")
		}
		a.retire()
	}
}
