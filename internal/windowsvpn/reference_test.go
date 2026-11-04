package windowsvpn

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestDialReferenceTracksFailureHandleAndDelayedTermination(t *testing.T) {
	for _, dialCode := range []uint32{0, 691} {
		reference := newDialReference()
		if err := reference.recordDialReturn(71, dialCode); err != nil { t.Fatal(err) }
		if reference.referenceTerminationConfirmed() { t.Fatal("dial return authorized cleanup") }
		calls := 0
		if err := reference.checkTermination(func(uintptr) uint32 { t.Fatal("queried before release"); return rasInvalidHandle }); err != ErrCleanup { t.Fatal(err) }
		if err := reference.release(func(h uintptr) uint32 { calls++; if h != 71 { t.Fatal("wrong reference") }; return 0 }); err != nil { t.Fatal(err) }
		if reference.referenceTerminationConfirmed() { t.Fatal("hangup return authorized cleanup") }
		for _, code := range []uint32{0, 5, 0} {
			if err := reference.checkTermination(func(h uintptr) uint32 { if h != 71 { t.Fatal("wrong probe handle") }; return code }); err != ErrCleanup { t.Fatal("pending/error/shared handle counted as termination") }
			if reference.referenceTerminationConfirmed() { t.Fatal("unconfirmed termination") }
		}
		if err := reference.checkTermination(func(uintptr) uint32 { return rasInvalidHandle }); err != nil { t.Fatal(err) }
		if !reference.referenceTerminationConfirmed() { t.Fatal("termination prerequisite not recorded") }
		if err := reference.checkTermination(func(uintptr) uint32 { t.Fatal("queried already terminated handle"); return 0 }); err != nil { t.Fatal(err) }
		if err := reference.release(func(uintptr) uint32 { calls++; return 0 }); !errors.Is(err, errReleaseConsumed) || calls != 1 { t.Fatal("released a reference twice") }
	}
}

func TestDialReferenceNeverAdoptsReplacementResult(t *testing.T) {
	reference := newDialReference()
	if err := reference.recordDialReturn(71, 0); err != nil { t.Fatal(err) }
	if err := reference.recordDialReturn(72, 0); err != ErrOperation { t.Fatal("second native completion accepted") }
	if err := reference.release(func(h uintptr) uint32 { if h != 71 { t.Fatal("adopted replacement handle") }; return 0 }); err != nil { t.Fatal(err) }
	if err := reference.checkTermination(func(uintptr) uint32 { t.Fatal("queried tainted result"); return rasInvalidHandle }); err != ErrCleanup { t.Fatal(err) }
	if reference.referenceTerminationConfirmed() { t.Fatal("ambiguous result authorized cleanup") }
}

func TestDialReferenceFailedOrUncertainReleaseNeverRetries(t *testing.T) {
	for _, result := range []uint32{5, rasInvalidHandle, 691} {
		reference := newDialReference()
		_ = reference.recordDialReturn(71, 0)
		calls := 0
		if err := reference.release(func(uintptr) uint32 { calls++; return result }); err != ErrCleanup { t.Fatal(err) }
		if err := reference.release(func(uintptr) uint32 { calls++; return 0 }); err != errReleaseConsumed || calls != 1 { t.Fatal("retried failed/uncertain hangup") }
		if err := reference.checkTermination(func(uintptr) uint32 { t.Fatal("failed release treated as completed"); return rasInvalidHandle }); err != ErrCleanup { t.Fatal(err) }
		if reference.referenceTerminationConfirmed() { t.Fatal("failed release authorized cleanup") }
	}
	reference := newDialReference()
	_ = reference.recordDialReturn(71, 0)
	func() {
		defer func() { if recover() == nil { t.Fatal("expected injected panic") } }()
		_ = reference.release(func(uintptr) uint32 { panic("synthetic uncertain outcome") })
	}()
	if err := reference.release(func(uintptr) uint32 { t.Fatal("retried after uncertain native outcome"); return 0 }); err != errReleaseConsumed { t.Fatal(err) }
	if reference.referenceTerminationConfirmed() { t.Fatal("uncertain release authorized cleanup") }
	if err := reference.checkTermination(func(uintptr) uint32 { t.Fatal("queried after uncertain release"); return rasInvalidHandle }); err != ErrCleanup { t.Fatal(err) }
}

func TestDialReferenceSerializesConcurrentRelease(t *testing.T) {
	reference := newDialReference()
	_ = reference.recordDialReturn(71, 0)
	entered, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	first := make(chan error, 1)
	go func() { first <- reference.release(func(h uintptr) uint32 { calls.Add(1); if h != 71 { panic("wrong handle") }; close(entered); <-finish; return 0 }) }()
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); if err := reference.release(func(uintptr) uint32 { calls.Add(1); return 0 }); err != errReleaseConsumed { t.Errorf("concurrent release: %v", err) } }()
	}
	wg.Wait()
	if err := reference.checkTermination(func(uintptr) uint32 { t.Fatal("queried before release returned"); return rasInvalidHandle }); err != ErrCleanup { t.Fatal(err) }
	close(finish)
	if err := <-first; err != nil || calls.Load() != 1 { t.Fatal("release not exactly once") }
	if err := reference.checkTermination(func(uintptr) uint32 { return rasInvalidHandle }); err != nil { t.Fatal(err) }
}

func TestDialReferenceSerializesTerminationAndRejectsLateDuplicate(t *testing.T) {
	reference := newDialReference()
	_ = reference.recordDialReturn(71, 0)
	_ = reference.release(func(uintptr) uint32 { return 0 })
	entered, finish := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- reference.checkTermination(func(uintptr) uint32 { close(entered); <-finish; return rasInvalidHandle }) }()
	<-entered
	if err := reference.checkTermination(func(uintptr) uint32 { t.Fatal("concurrent status query"); return rasInvalidHandle }); err != ErrBusy { t.Fatal(err) }
	if err := reference.recordDialReturn(71, 0); err != ErrOperation { t.Fatal("duplicate completion accepted") }
	close(finish)
	if err := <-result; err != ErrCleanup { t.Fatal("late ambiguity missed") }
	if reference.referenceTerminationConfirmed() { t.Fatal("tainted observation authorized cleanup") }
}

func TestDialReferenceRejectsMissingAndNilBoundaries(t *testing.T) {
	for _, code := range []uint32{0, 691} {
		reference := newDialReference()
		err := reference.recordDialReturn(0, code)
		if (err == nil) != (code != 0) { t.Fatal("invalid empty result classification") }
		if err := reference.release(func(uintptr) uint32 { t.Fatal("released a null handle"); return 0 }); err != ErrCleanup { t.Fatal(err) }
		if reference.referenceTerminationConfirmed() { t.Fatal("null result claimed consumer quiescence") }
	}
	reference := newDialReference()
	if err := reference.release(func(uintptr) uint32 { t.Fatal("released before native return"); return 0 }); err != ErrCleanup { t.Fatal(err) }
	_ = reference.recordDialReturn(71, 0)
	if err := reference.release(nil); err != ErrCleanup { t.Fatal(err) }
	if err := reference.release(func(uintptr) uint32 { return 0 }); err != nil { t.Fatal("nil boundary consumed release") }
	if err := reference.checkTermination(nil); err != ErrCleanup { t.Fatal(err) }
	if err := reference.checkTermination(func(uintptr) uint32 { return rasInvalidHandle }); err != nil { t.Fatal(err) }
}


func TestDialReferenceStatusPanicAndLateDuplicate(t *testing.T) {
	reference := newDialReference()
	_ = reference.recordDialReturn(71, 0)
	_ = reference.release(func(uintptr) uint32 { return 0 })
	func() {
		defer func() { if recover() == nil { t.Fatal("expected injected status panic") } }()
		_ = reference.checkTermination(func(uintptr) uint32 { panic("synthetic status failure") })
	}()
	if reference.referenceTerminationConfirmed() { t.Fatal("failed probe confirmed termination") }
	if err := reference.release(func(uintptr) uint32 { t.Fatal("status panic reset release debt"); return 0 }); err != errReleaseConsumed { t.Fatal(err) }
	if err := reference.checkTermination(func(uintptr) uint32 { return rasInvalidHandle }); err != nil { t.Fatal("status panic left poll busy") }
	if !reference.referenceTerminationConfirmed() { t.Fatal("valid retry probe not recorded") }
	if err := reference.recordDialReturn(71, 0); err != ErrOperation { t.Fatal("late duplicate accepted") }
	if reference.referenceTerminationConfirmed() { t.Fatal("late duplicate failed to taint confirmed result") }
}

func TestDialReferenceCopiesShareDebtAndZeroFailsClosed(t *testing.T) {
	reference := newDialReference()
	_ = reference.recordDialReturn(71, 0)
	copyOfReference := *reference
	if err := reference.release(func(uintptr) uint32 { return 0 }); err != nil { t.Fatal(err) }
	if err := copyOfReference.release(func(uintptr) uint32 { t.Fatal("copy duplicated release permission"); return 0 }); err != errReleaseConsumed { t.Fatal(err) }
	if err := copyOfReference.checkTermination(func(uintptr) uint32 { return rasInvalidHandle }); err != nil { t.Fatal(err) }
	if !reference.referenceTerminationConfirmed() { t.Fatal("copy did not share lifecycle state") }
	for _, zero := range []*dialReference{nil, {}} {
		if zero.recordDialReturn(71, 0) != ErrOperation { t.Fatal("zero ledger admitted a result") }
		if zero.release(func(uintptr) uint32 { t.Fatal("zero ledger released a handle"); return 0 }) != ErrCleanup { t.Fatal("zero ledger did not block release") }
		if zero.checkTermination(func(uintptr) uint32 { t.Fatal("zero ledger queried a handle"); return rasInvalidHandle }) != ErrCleanup { t.Fatal("zero ledger did not block query") }
		if zero.referenceTerminationConfirmed() { t.Fatal("zero ledger authorized cleanup") }
	}
}
