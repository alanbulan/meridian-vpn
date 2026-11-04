package windowsvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

type fakeBorrowedOps struct {
	router                                    *callbackRouter
	begin                                     func(context.Context, *borrowedInputs) (uintptr, uint32)
	revalidate                                func(context.Context, EntryEvidence) error
	inspect                                   func(context.Context, EntryEvidence, uintptr) (borrowedObservation, error)
	quiesce                                   func(context.Context, *borrowedInputs, uintptr) error
	hangup                                    func(uintptr) uint32
	status                                    func(uintptr) uint32
	begins, hangs, probes, joins, inspections atomic.Int32
}

func borrowedTestEntry() EntryEvidence {
	return EntryEvidence{entry: fixtureEntry(), gateway: "vpn.example.test", properties: fixtureProperties()}
}
func borrowedTestConsent() borrowedConsent { return borrowedConsent{true, true, true} }
func callbackIDOf(input *borrowedInputs) uintptr {
	layout, _ := rasDialParameterLayout(int(unsafe.Sizeof(uintptr(0))))
	b := wordBytes(input.parameters)[layout.callbackID:]
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return uintptr(binary.LittleEndian.Uint64(b))
	}
	return uintptr(binary.LittleEndian.Uint32(b))
}
func (f *fakeBorrowedOps) Revalidate(ctx context.Context, e EntryEvidence) error {
	if f.revalidate != nil {
		return f.revalidate(ctx, e)
	}
	return nil
}
func (f *fakeBorrowedOps) Begin(ctx context.Context, input *borrowedInputs) (uintptr, uint32) {
	f.begins.Add(1)
	if f.begin != nil {
		return f.begin(ctx, input)
	}
	f.router.dispatch(callbackIDOf(input), callbackEvent{subEntry: 1, handle: 71, message: 0xcccd, state: rasConnected})
	return 71, 0
}
func (f *fakeBorrowedOps) Hangup(handle uintptr) uint32 {
	f.hangs.Add(1)
	if f.hangup != nil {
		return f.hangup(handle)
	}
	return 0
}
func (f *fakeBorrowedOps) Status(handle uintptr) uint32 {
	f.probes.Add(1)
	if f.status != nil {
		return f.status(handle)
	}
	return rasInvalidHandle
}
func (f *fakeBorrowedOps) Quiesce(ctx context.Context, i *borrowedInputs, h uintptr) error {
	f.joins.Add(1)
	if f.quiesce != nil {
		return f.quiesce(ctx, i, h)
	}
	return nil
}
func (f *fakeBorrowedOps) Inspect(ctx context.Context, e EntryEvidence, h uintptr) (borrowedObservation, error) {
	f.inspections.Add(1)
	if f.inspect != nil {
		return f.inspect(ctx, e, h)
	}
	return borrowedObservation{h, e.properties.GUID, true, 9, net.ParseIP("10.20.30.40"), e.gateway}, nil
}

func newBorrowedFixture(t *testing.T) (*borrowedCoordinator, *fakeBorrowedOps) {
	t.Helper()
	router := newCallbackRouter()
	f := &fakeBorrowedOps{router: router}
	c := newBorrowedCoordinator(f, router)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.stop(ctx)
		// Failure tests intentionally quarantine. There is NO native consumer
		// in these fixtures: release test-owned storage only after goroutines
		// have joined. This is not a production cleanup escape hatch.
		if c.current != nil {
			if c.current.callback != nil {
				c.current.callback.retire()
			}
			c.current.inputs.releaseAfterQuiescence()
		}
	})
	return c, f
}

func startBorrowed(c *borrowedCoordinator) error {
	return c.start(context.Background(), borrowedTestEntry(), "fixture-user", "", []byte("fixture-password"), borrowedTestConsent())
}
func inputsZero(input *borrowedInputs) bool {
	for _, p := range input.parameters {
		if p != 0 {
			return false
		}
	}
	for _, p := range input.phonebook {
		if p != 0 {
			return false
		}
	}
	return true
}

func TestBorrowedRequiresEveryConsentAndValidatedEntry(t *testing.T) {
	c, f := newBorrowedFixture(t)
	for _, consent := range []borrowedConsent{{}, {false, true, true}, {true, false, true}, {true, true, false}} {
		if c.start(context.Background(), borrowedTestEntry(), "user", "", []byte("pass"), consent) != ErrAuthorization {
			t.Fatal("missing grant accepted")
		}
	}
	if c.start(context.Background(), EntryEvidence{}, "user", "", []byte("pass"), borrowedTestConsent()) != ErrVerification {
		t.Fatal("unvalidated profile accepted")
	}
	if f.begins.Load() != 0 {
		t.Fatal("native boundary reached before authorization")
	}
	if newBorrowedCoordinator(nil, newCallbackRouter()).start(context.Background(), borrowedTestEntry(), "user", "", []byte("pass"), borrowedTestConsent()) != ErrUnavailable {
		t.Fatal("missing implementation accepted")
	}
}

func TestBorrowedEarlyCallbackNeedsIndependentEvidenceAndErasesAfterStop(t *testing.T) {
	c, f := newBorrowedFixture(t)
	password := []byte("fixture-password")
	original := bytes.Clone(password)
	if err := c.start(context.Background(), borrowedTestEntry(), "user", "", password, borrowedTestConsent()); err != nil {
		t.Fatal(err)
	}
	if !c.current.ready || f.inspections.Load() != 1 {
		t.Fatal("did not independently verify readiness")
	}
	input := c.current.inputs
	if inputsZero(input) || input.released || !bytes.Equal(password, original) {
		t.Fatal("live input lifetime/caller secret corrupted")
	}
	if err := c.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !input.released || !inputsZero(input) || c.current != nil || f.hangs.Load() != 1 || f.joins.Load() != 1 {
		t.Fatal("cleanup was not confirmed once")
	}
	if err := c.stop(context.Background()); err != nil || f.hangs.Load() != 1 {
		t.Fatal("repeated Stop repeated hangup")
	}
	if err := startBorrowed(c); err != nil {
		t.Fatal("confirmed cleanup blocked later attempt")
	}
}

func TestBorrowedPendingSharedHandleAndQuiescenceRemainQuarantined(t *testing.T) {
	c, f := newBorrowedFixture(t)
	if err := startBorrowed(c); err != nil {
		t.Fatal(err)
	}
	input := c.current.inputs
	f.status = func(uintptr) uint32 { return 0 }
	if c.stop(context.Background()) != ErrCleanup || input.released || inputsZero(input) || c.current.ready {
		t.Fatal("surviving/shared handle not quarantined")
	}
	if startBorrowed(c) != ErrBusy {
		t.Fatal("reconnected over uncertain cleanup")
	}
	f.status = nil
	f.quiesce = func(context.Context, *borrowedInputs, uintptr) error {
		return errors.New("synthetic private native detail")
	}
	if c.stop(context.Background()) != ErrCleanup || input.released {
		t.Fatal("termination alone released native inputs")
	}
	f.quiesce = nil
	if err := c.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.hangs.Load() != 1 || !inputsZero(input) || !input.released {
		t.Fatal("retried hangup or failed final erase")
	}
}

func TestBorrowedFailedAndUnknownDialReturns(t *testing.T) {
	for _, tc := range []struct {
		name       string
		handle     uintptr
		code       uint32
		panicBegin bool
		want       error
	}{
		{"failure with reference", 71, 691, false, ErrOperation},
		{"failure without reference", 0, 691, false, ErrOperation},
		{"impossible success", 0, 0, false, ErrCleanup},
		{"unknown outcome", 0, 0, true, ErrCleanup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f := newBorrowedFixture(t)
			var input *borrowedInputs
			f.begin = func(_ context.Context, i *borrowedInputs) (uintptr, uint32) {
				input = i
				if tc.panicBegin {
					panic("synthetic native uncertainty")
				}
				return tc.handle, tc.code
			}
			if err := startBorrowed(c); err != tc.want {
				t.Fatalf("wrong bounded failure: %v", err)
			}
			if tc.want == ErrCleanup {
				if input.released || c.current == nil || f.joins.Load() != 0 || f.hangs.Load() != 0 {
					t.Fatal("unknown native result treated as cleanup proof")
				}
			} else if !inputsZero(input) || !input.released || f.joins.Load() != 1 {
				t.Fatal("known failed invocation did not join and erase")
			}
			if tc.handle != 0 && f.hangs.Load() != 1 {
				t.Fatal("error result leaked direct reference")
			}
		})
	}
}

func TestBorrowedFailedOrUncertainHangupIsNeverRepeated(t *testing.T) {
	for _, panicHangup := range []bool{false, true} {
		c, f := newBorrowedFixture(t)
		if err := startBorrowed(c); err != nil {
			t.Fatal(err)
		}
		input := c.current.inputs
		f.hangup = func(uintptr) uint32 {
			if panicHangup {
				panic("synthetic unknown hangup")
			}
			return 5
		}
		for i := 0; i < 3; i++ {
			if c.stop(context.Background()) != ErrCleanup {
				t.Fatal("uncertain release accepted")
			}
		}
		if f.hangs.Load() != 1 || f.probes.Load() != 0 || f.joins.Load() != 0 || input.released {
			t.Fatal("uncertain release repeated or treated as proof")
		}
	}
}

func TestBorrowedRejectsCallbackMismatchOverflowAndPausedState(t *testing.T) {
	for _, tc := range []struct {
		name        string
		handle      uintptr
		state, code uint32
		count       int
		want        error
	}{
		{"wrong callback handle", 99, rasConnected, 0, 1, ErrVerification},
		{"queue overflow", 71, rasConnected, 0, maxCallbackEvents + 1, ErrOperation},
		{"paused auth", 71, 0x1000, 0, 1, ErrUnsupported},
		{"callback error", 71, 1, 691, 1, ErrOperation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f := newBorrowedFixture(t)
			f.begin = func(_ context.Context, i *borrowedInputs) (uintptr, uint32) {
				for n := 0; n < tc.count; n++ {
					f.router.dispatch(callbackIDOf(i), callbackEvent{1, tc.handle, 0xcccd, tc.state, tc.code, 0})
				}
				return 71, 0
			}
			f.hangup = func(h uintptr) uint32 {
				if h != 71 {
					t.Fatal("adopted callback reference")
				}
				return 0
			}
			if err := startBorrowed(c); err != tc.want {
				t.Fatalf("wrong failure: %v", err)
			}
			if f.inspections.Load() != 0 || f.hangs.Load() != 1 || c.current != nil {
				t.Fatal("bad callback became ready or blocked confirmed cleanup")
			}
		})
	}
}

func TestBorrowedRejectsUnboundFreshEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*borrowedObservation){
		"handle":    func(o *borrowedObservation) { o.handle++ },
		"profile":   func(o *borrowedObservation) { o.entryGUID[0]++ },
		"state":     func(o *borrowedObservation) { o.connected = false },
		"interface": func(o *borrowedObservation) { o.interfaceIndex = 0 },
		"address":   func(o *borrowedObservation) { o.address = net.ParseIP("127.0.0.1") },
		"gateway":   func(o *borrowedObservation) { o.gateway = "other.example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			c, f := newBorrowedFixture(t)
			f.inspect = func(_ context.Context, e EntryEvidence, h uintptr) (borrowedObservation, error) {
				o := borrowedObservation{h, e.properties.GUID, true, 9, net.ParseIP("10.20.30.40"), e.gateway}
				mutate(&o)
				return o, nil
			}
			if startBorrowed(c) != ErrVerification || c.current != nil || f.hangs.Load() != 1 {
				t.Fatal("unbound evidence became ready")
			}
		})
	}
}

func TestBorrowedCancellationBeforeHandleReturn(t *testing.T) {
	c, f := newBorrowedFixture(t)
	entered := make(chan struct{})
	f.begin = func(ctx context.Context, _ *borrowedInputs) (uintptr, uint32) {
		close(entered)
		<-ctx.Done()
		return 71, 0
	}
	done := make(chan error, 1)
	go func() { done <- startBorrowed(c) }()
	<-entered
	if err := c.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != context.Canceled {
		t.Fatalf("cancellation not propagated: %v", err)
	}
	if f.hangs.Load() != 1 || f.joins.Load() != 1 || c.current != nil {
		t.Fatal("late direct result not released/joined")
	}
}

func TestBorrowedStopDeadlineCannotDetachBlockedInvocation(t *testing.T) {
	c, f := newBorrowedFixture(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	f.begin = func(context.Context, *borrowedInputs) (uintptr, uint32) { close(entered); <-finish; return 71, 0 }
	done := make(chan error, 1)
	go func() { done <- startBorrowed(c) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if c.stop(ctx) != ErrCleanup || f.hangs.Load() != 0 {
		t.Fatal("Stop guessed a handle or ignored waiting deadline")
	}
	close(finish)
	if err := <-done; err != context.Canceled {
		t.Fatal(err)
	}
	if err := c.stop(context.Background()); err != nil || f.hangs.Load() != 1 {
		t.Fatal("late return cleanup failed")
	}
}

func TestBorrowedConcurrentStopsAndFreshCheckFailure(t *testing.T) {
	c, f := newBorrowedFixture(t)
	if err := startBorrowed(c); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.stop(context.Background()); err != nil {
				t.Errorf("Stop: %v", err)
			}
		}()
	}
	wg.Wait()
	if f.hangs.Load() != 1 {
		t.Fatal("concurrent Stop duplicated release")
	}
	if err := startBorrowed(c); err != nil {
		t.Fatal(err)
	}
	f.revalidate = func(context.Context, EntryEvidence) error { return errors.New("private profile changed") }
	if c.check(context.Background()) != ErrVerification || c.current != nil {
		t.Fatal("fresh profile drift left session ready")
	}
}

func TestBorrowedPinnedStorageIsBoundedAndAnchored(t *testing.T) {
	borrowedInputAnchor.Lock()
	baseline := len(borrowedInputAnchor.active)
	borrowedInputAnchor.Unlock()
	var inputs []*borrowedInputs
	defer func() {
		for _, i := range inputs {
			i.releaseAfterQuiescence()
		}
	}()
	for n := baseline; n < maxBorrowedInputs; n++ {
		i, err := newBorrowedInputs(fixtureEntry(), "user", "", []byte("fixture-password"), uintptr(n+1))
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, i)
	}
	if _, err := newBorrowedInputs(fixtureEntry(), "user", "", []byte("fixture-password"), 1); err != ErrBusy {
		t.Fatal("unbounded pinned credentials")
	}
	runtime.GC()
	borrowedInputAnchor.Lock()
	count := len(borrowedInputAnchor.active)
	borrowedInputAnchor.Unlock()
	if count != maxBorrowedInputs {
		t.Fatal("live/quarantined inputs lost their process anchor")
	}
}

func TestBorrowedInvalidCredentialsNeverBeginOrLeakRegistration(t *testing.T) {
	c, f := newBorrowedFixture(t)
	if c.start(context.Background(), borrowedTestEntry(), "user", "", nil, borrowedTestConsent()) != ErrOperation {
		t.Fatal("empty secret accepted")
	}
	if f.begins.Load() != 0 || c.current != nil || len(c.router.attempts) != 0 {
		t.Fatal("validation failure entered native boundary or leaked route")
	}
}

func TestBorrowedOverflowDuringVerificationCannotBecomeReady(t *testing.T) {
	c, f := newBorrowedFixture(t)
	f.inspect = func(_ context.Context, e EntryEvidence, h uintptr) (borrowedObservation, error) {
		for n := 0; n <= maxCallbackEvents; n++ {
			f.router.dispatch(c.current.callback.id, callbackEvent{1, h, 0xcccd, rasConnected, 0, 0})
		}
		return borrowedObservation{h, e.properties.GUID, true, 9, net.ParseIP("10.20.30.40"), e.gateway}, nil
	}
	if startBorrowed(c) != ErrVerification || c.current != nil {
		t.Fatal("faulted route became ready")
	}
}

func TestBorrowedStopCancelsFreshInspection(t *testing.T) {
	c, f := newBorrowedFixture(t)
	if err := startBorrowed(c); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	f.inspect = func(ctx context.Context, _ EntryEvidence, _ uintptr) (borrowedObservation, error) {
		close(entered)
		<-ctx.Done()
		return borrowedObservation{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- c.check(context.Background()) }()
	<-entered
	if err := c.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != ErrVerification {
		t.Fatal(err)
	}
	if f.hangs.Load() != 1 || c.current != nil {
		t.Fatal("canceled inspection lost cleanup")
	}
}

func TestBorrowedStatusAndQuiescePanicsKeepInputsPinned(t *testing.T) {
	for _, statusPanic := range []bool{true, false} {
		c, f := newBorrowedFixture(t)
		if err := startBorrowed(c); err != nil {
			t.Fatal(err)
		}
		input := c.current.inputs
		if statusPanic {
			f.status = func(uintptr) uint32 { panic("synthetic probe failure") }
		} else {
			f.quiesce = func(context.Context, *borrowedInputs, uintptr) error { panic("synthetic join failure") }
		}
		if c.stop(context.Background()) != ErrCleanup || input.released {
			t.Fatal("uncertain probe/join released inputs")
		}
		f.status, f.quiesce = nil, nil
		if err := c.stop(context.Background()); err != nil || f.hangs.Load() != 1 || !inputsZero(input) {
			t.Fatal("safe retry failed or repeated hangup")
		}
	}
}

func TestBorrowedInputValueCopyCannotReleaseAnchoredOwner(t *testing.T) {
	input, err := newBorrowedInputs(fixtureEntry(), "user", "", []byte("fixture-password"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer input.releaseAfterQuiescence()
	copyOfInput := *input
	copyOfInput.releaseAfterQuiescence()
	if inputsZero(input) || input.released {
		t.Fatal("value copy erased/unpinned live owner")
	}
	input.releaseAfterQuiescence()
	if !inputsZero(input) || !input.released {
		t.Fatal("anchored owner could not release")
	}
}

func TestBorrowedQueuedFailureCannotBecomeReady(t *testing.T) {
	for name, event := range map[string]callbackEvent{
		"disconnected":   {1, 71, 0xcccd, 0x2001, 0, 0},
		"error":          {1, 71, 0xcccd, rasConnected, 691, 0},
		"extended error": {1, 71, 0xcccd, rasConnected, 0, 1},
		"wrong handle":   {1, 72, 0xcccd, rasConnected, 0, 0},
		"wrong message":  {1, 71, 0, rasConnected, 0, 0},
		"paused":         {1, 71, 0xcccd, 0x1000, 0, 0},
	} {
		for _, phase := range []string{"before return", "during inspection", "after ready"} {
			t.Run(name+"/"+phase, func(t *testing.T) {
				c, f := newBorrowedFixture(t)
				send := func(id uintptr) {
					f.router.dispatch(id, event)
					// A later Connected must not erase a prior failure.
					f.router.dispatch(id, callbackEvent{1, 71, 0xcccd, rasConnected, 0, 0})
				}
				switch phase {
				case "before return":
					f.begin = func(_ context.Context, i *borrowedInputs) (uintptr, uint32) {
						f.router.dispatch(callbackIDOf(i), callbackEvent{1, 71, 0xcccd, rasConnected, 0, 0})
						send(callbackIDOf(i))
						return 71, 0
					}
				case "during inspection":
					f.inspect = func(_ context.Context, e EntryEvidence, h uintptr) (borrowedObservation, error) {
						send(c.current.callback.id)
						return borrowedObservation{h, e.properties.GUID, true, 9, net.ParseIP("10.20.30.40"), e.gateway}, nil
					}
				}
				err := startBorrowed(c)
				if phase == "after ready" {
					if err != nil {
						t.Fatal(err)
					}
					send(c.current.callback.id)
					err = c.check(context.Background())
				}
				if err == nil {
					t.Fatal("queued failure granted readiness")
				}
				if c.current != nil && c.current.ready {
					t.Fatal("failure retained ready flag")
				}
				if f.hangs.Load() != 1 {
					t.Fatal("direct reference not released exactly once")
				}
			})
		}
	}
}
