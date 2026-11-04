package windowsvpn

import "testing"

func TestNativeCallTransportPreservesFailureReference(t *testing.T) {
	input, err := newBorrowedInputs(fixtureEntry(), "user", "", []byte("secret"), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer input.releaseAfterQuiescence() // Fake functions have no native consumers.
	called := false
	calls := nativeRASCalls{dial: func(pb *uint16, p *uint32, notifier uintptr, h *uintptr) uint32 {
		called = true
		if pb != &input.phonebook[0] || p != &input.parameters[0] || notifier != 31 || *h != 0 {
			t.Fatal("argument mismatch or seeded handle")
		}
		*h = ^uintptr(0) - 9
		return 691
	}}
	handle, code, err := calls.begin(input, 31)
	if err != nil || !called || handle != ^uintptr(0)-9 || code != 691 {
		t.Fatal("error lost direct handle")
	}
	if inputsZero(input) {
		t.Fatal("initial return erased live inputs")
	}
}

func TestNativeCallTransportRejectsInvalidInputs(t *testing.T) {
	input, err := newBorrowedInputs(fixtureEntry(), "user", "", []byte("secret"), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer input.releaseAfterQuiescence()
	calls := nativeRASCalls{dial: func(*uint16, *uint32, uintptr, *uintptr) uint32 { t.Fatal("invalid input invoked dial"); return 0 }}
	copied := *input
	for _, v := range []*borrowedInputs{nil, {}, &copied} {
		if _, _, err := calls.begin(v, 31); err == nil {
			t.Fatal("invalid owner accepted")
		}
	}
	if _, _, err := calls.begin(input, 0); err == nil {
		t.Fatal("null notifier accepted")
	}
	if _, _, err := (nativeRASCalls{}).begin(input, 31); err == nil {
		t.Fatal("missing procedure accepted")
	}
	input.releaseAfterQuiescence()
	if _, _, err := calls.begin(input, 31); err == nil {
		t.Fatal("released input accepted")
	}
}

func TestNativeCallTransportReleaseHasNoImplicitRetry(t *testing.T) {
	n := 0
	calls := nativeRASCalls{hangup: func(h uintptr) uint32 {
		n++
		if h != 71 {
			t.Fatal("wrong handle")
		}
		return 6
	}}
	if _, err := calls.release(0); err == nil || n != 0 {
		t.Fatal("null handle invoked hangup")
	}
	code, err := calls.release(71)
	if err != nil || code != 6 || n != 1 {
		t.Fatal("release return/retry mismatch")
	}
	if _, err := (nativeRASCalls{}).release(71); err == nil {
		t.Fatal("missing hangup accepted")
	}
}
