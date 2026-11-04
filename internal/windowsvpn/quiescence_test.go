package windowsvpn

import "testing"

func TestTerminatedRASInputsNeedsDeletionAndRetiredRoute(t *testing.T) {
	router := newCallbackRouter()
	registration, err := router.register()
	if err != nil {
		t.Fatal(err)
	}
	defer registration.retire()
	reference := newDialReference()
	a := &borrowedAttempt{beginCalled: true, returnKnown: true, handle: 71, reference: reference, callback: registration}
	if err := reference.recordDialReturn(71, 0); err != nil {
		t.Fatal(err)
	}
	if terminatedRASInputs(a) == nil {
		t.Fatal("unreleased inputs accepted")
	}
	hangs := 0
	if err := reference.release(func(uintptr) uint32 { hangs++; return 0 }); err != nil {
		t.Fatal(err)
	}
	if err := reference.checkTermination(func(uintptr) uint32 { return 0 }); err == nil {
		t.Fatal("shared surviving handle treated as deleted")
	}
	registration.retire()
	if terminatedRASInputs(a) == nil {
		t.Fatal("retired route substituted for deletion")
	}
	if err := reference.checkTermination(func(uintptr) uint32 { return rasInvalidHandle }); err != nil {
		t.Fatal(err)
	}
	if err := terminatedRASInputs(a); err != nil {
		t.Fatal("documented deletion endpoint rejected", err)
	}
	if hangs != 1 {
		t.Fatal("cleanup repeated hangup")
	}
	if router.dispatch(registration.id, callbackEvent{handle: 71}) != 0 {
		t.Fatal("late callback reacquired attempt")
	}
	a.handle = 72
	if terminatedRASInputs(a) == nil {
		t.Fatal("other reference proof accepted")
	}
	a.handle = 71
	a.returnKnown = false
	if terminatedRASInputs(a) == nil {
		t.Fatal("unknown initial result accepted")
	}
}
func TestTerminatedRASInputsRejectsLiveCallbackRoute(t *testing.T) {
	router := newCallbackRouter()
	registration, err := router.register()
	if err != nil {
		t.Fatal(err)
	}
	defer registration.retire()
	reference := newDialReference()
	reference.recordDialReturn(71, 691)
	reference.release(func(uintptr) uint32 { return 0 })
	reference.checkTermination(func(uintptr) uint32 { return rasInvalidHandle })
	a := &borrowedAttempt{beginCalled: true, returnKnown: true, handle: 71, code: 691, reference: reference, callback: registration}
	if terminatedRASInputs(a) == nil {
		t.Fatal("active route accepted")
	}
	registration.retire()
	if err := terminatedRASInputs(a); err != nil {
		t.Fatal("failed dial with deleted reference rejected", err)
	}
	if terminatedRASInputs(nil) == nil {
		t.Fatal("nil attempt accepted")
	}
}

func TestTerminatedRASInputsRejectsInvalidProof(t *testing.T) {
	for _, kind := range []string{"wrong code", "tainted", "nil reference", "zero reference", "failed hangup", "route identity"} {
		t.Run(kind, func(t *testing.T) {
			router := newCallbackRouter()
			registration, err := router.register()
			if err != nil {
				t.Fatal(err)
			}
			registration.retire()
			ref := newDialReference()
			ref.recordDialReturn(71, 691)
			code := uint32(0)
			if kind == "failed hangup" {
				code = 5
			}
			ref.release(func(uintptr) uint32 { return code })
			ref.checkTermination(func(uintptr) uint32 { return rasInvalidHandle })
			a := &borrowedAttempt{beginCalled: true, returnKnown: true, handle: 71, code: 691, reference: ref, callback: registration}
			switch kind {
			case "wrong code":
				a.code = 0
			case "tainted":
				ref.recordDialReturn(71, 691)
			case "nil reference":
				a.reference = nil
			case "zero reference":
				a.reference = &dialReference{}
			case "route identity":
				router.mu.Lock()
				router.attempts[registration.id] = &callbackRegistration{}
				router.mu.Unlock()
			}
			if terminatedRASInputs(a) == nil {
				t.Fatal("invalid cleanup proof accepted")
			}
		})
	}
}
