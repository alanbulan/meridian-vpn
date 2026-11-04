package windowsvpn

import (
	"context"
	"net/netip"
	"testing"
)

func fixtureAdapterRows() []adapterIPv4 {
	return []adapterIPv4{{9, 0x1234, 23, 1, []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil}}
}
func TestInterfaceCorrelationRejectsAmbiguityAndWrongIdentity(t *testing.T) {
	ip := netip.MustParseAddr("10.20.30.40")
	for _, kind := range []string{"valid", "duplicate address", "duplicate index", "duplicate luid", "down", "not ppp", "missing", "zero index", "zero luid", "mapped ipv4"} {
		t.Run(kind, func(t *testing.T) {
			rows := fixtureAdapterRows()
			switch kind {
			case "duplicate address":
				r := rows[0]
				r.index++
				r.luid++
				rows = append(rows, r)
			case "duplicate index":
				r := rows[0]
				r.luid++
				r.addresses = nil
				rows = append(rows, r)
			case "duplicate luid":
				r := rows[0]
				r.index++
				r.addresses = nil
				rows = append(rows, r)
			case "down":
				rows[0].operStatus = 2
			case "not ppp":
				rows[0].kind = 6
			case "missing":
				rows[0].addresses = nil
			case "zero index":
				rows[0].index = 0
			case "zero luid":
				rows[0].luid = 0
			case "mapped ipv4":
				rows[0].addresses = []netip.Addr{netip.MustParseAddr("::ffff:10.20.30.40")}
			}
			got, err := correlateInterface(ip, rows)
			if kind == "valid" {
				if err != nil || got.index != 9 || got.luid != 0x1234 {
					t.Fatal("valid observation rejected")
				}
			} else if err == nil {
				t.Fatal("ambiguous observation accepted")
			}
		})
	}
}

type boundNativeFixture struct {
	c       *borrowedCoordinator
	b       nativeSessionBindings
	hangs   int
	deleted bool
	shared  bool
}

func newBoundNativeFixture(t *testing.T) *boundNativeFixture {
	t.Helper()
	f := &boundNativeFixture{}
	r := fixtureConnection()
	router := newCallbackRouter()
	f.b = nativeSessionBindings{
		revalidate: unchangedEntry, enumerate: fixedConnections(r), projection: fixtureProjection,
		interfaces: func() ([]adapterIPv4, error) { return fixtureAdapterRows(), nil }, router: router, notifier: 31,
	}
	f.b.status = func(h uintptr, s *nativeConnectionStatus) uint32 {
		if h != r.handle {
			t.Fatal("wrong direct handle")
		}
		if f.deleted {
			return rasInvalidHandle
		}
		return fixtureStatus(h, s)
	}
	f.b.calls = nativeRASCalls{
		dial: func(pb *uint16, p *uint32, n uintptr, h *uintptr) uint32 {
			if *h != 0 || n != 31 {
				t.Fatal("wrong dial arguments")
			}
			f.deleted = false
			input := f.c.current.inputs
			if pb != &input.phonebook[0] || p != &input.parameters[0] {
				t.Fatal("wrong parameter owner")
			}
			router.dispatch(callbackIDOf(input), callbackEvent{1, r.handle, 0xcccd, rasConnected, 0, 0})
			*h = r.handle
			return 0
		}, hangup: func(h uintptr) uint32 {
			if h != r.handle {
				t.Fatal("released wrong handle")
			}
			f.hangs++
			f.deleted = !f.shared
			return 0
		},
	}
	var err error
	f.c, err = newBoundNativeSession(f.b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = f.c.stop(context.Background())
		if f.c.current != nil {
			f.c.current.inputs.releaseAfterQuiescence()
		}
	})
	return f
}
func TestBoundNativeSessionEndToEndWithoutRAS(t *testing.T) {
	f := newBoundNativeFixture(t)
	if err := startBorrowed(f.c); err != nil {
		t.Fatal(err)
	}
	input := f.c.current.inputs
	if err := f.c.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inputsZero(input) {
		t.Fatal("connected secret erased before deletion")
	}
	if err := f.c.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !inputsZero(input) || f.hangs != 1 || f.c.current != nil {
		t.Fatal("deleted session not cleaned exactly once")
	}
	if err := startBorrowed(f.c); err != nil {
		t.Fatal("reconnect after cleanup", err)
	}
	if err := f.c.stop(context.Background()); err != nil || f.hangs != 2 {
		t.Fatal("second attempt cleanup")
	}
}
func TestBoundNativeSessionSharedReferenceQuarantines(t *testing.T) {
	f := newBoundNativeFixture(t)
	f.shared = true
	if err := startBorrowed(f.c); err != nil {
		t.Fatal(err)
	}
	input := f.c.current.inputs
	if err := f.c.stop(context.Background()); err != ErrCleanup {
		t.Fatal("shared handle freed")
	}
	if inputsZero(input) {
		t.Fatal("shared input prematurely erased")
	}
	if err := startBorrowed(f.c); err != ErrBusy {
		t.Fatal("quarantined reconnect accepted")
	}
	_ = f.c.stop(context.Background())
	if f.hangs != 1 {
		t.Fatal("shared reference received extra hangup")
	}
	f.deleted = true
	if err := f.c.stop(context.Background()); err != nil || !inputsZero(input) || f.hangs != 1 {
		t.Fatal("later deletion cleanup failed")
	}
}
func TestBoundNativeSessionRejectsAdapterDrift(t *testing.T) {
	for _, kind := range []string{"index", "luid", "address", "down", "inventory error"} {
		t.Run(kind, func(t *testing.T) {
			f := newBoundNativeFixture(t)
			ops := f.c.ops.(*nativeSessionOperations)
			calls := 0
			ops.bindings.interfaces = func() ([]adapterIPv4, error) {
				calls++
				rows := fixtureAdapterRows()
				if calls > 1 {
					switch kind {
					case "index":
						rows[0].index++
					case "luid":
						rows[0].luid++
					case "address":
						rows[0].addresses = nil
					case "down":
						rows[0].operStatus = 2
					case "inventory error":
						return nil, ErrOperation
					}
				}
				return rows, nil
			}
			if err := startBorrowed(f.c); err == nil {
				t.Fatal("unstable interface set ready")
			}
			if f.c.current != nil || f.hangs != 1 {
				t.Fatal("failed verification not cleaned")
			}
		})
	}
}
func TestBoundNativeSessionRejectsMissingBindings(t *testing.T) {
	if _, err := newBoundNativeSession(nativeSessionBindings{}); err != ErrUnavailable {
		t.Fatal("missing native bindings accepted")
	}
}

func TestBoundSessionFinalRASRecheckDetectsSnapshotMutation(t *testing.T) {
	f := newBoundNativeFixture(t)
	ops := f.c.ops.(*nativeSessionOperations)
	count := 0
	record := fixtureConnection()
	ops.bindings.enumerate = func(b []uint32, s, c *uint32) uint32 { return writeConnections([]connectionRecord{record}, b, s, c) }
	ops.bindings.interfaces = func() ([]adapterIPv4, error) {
		count++
		if count == 2 {
			record.correlation[0]++
		}
		return fixtureAdapterRows(), nil
	}
	if err := startBorrowed(f.c); err == nil {
		t.Fatal("final RAS drift missed")
	}
}

func TestBoundSessionIdentityCannotChangeBetweenChecks(t *testing.T) {
	f := newBoundNativeFixture(t)
	if err := startBorrowed(f.c); err != nil {
		t.Fatal(err)
	}
	ops := f.c.ops.(*nativeSessionOperations)
	ops.bindings.interfaces = func() ([]adapterIPv4, error) { rows := fixtureAdapterRows(); rows[0].luid++; return rows, nil }
	if err := f.c.check(context.Background()); err == nil {
		t.Fatal("different adapter adopted across checks")
	}
	if f.hangs != 1 {
		t.Fatal("drift did not clean owned reference")
	}
}
func TestBoundSessionPreInvocationCancellationCallsNothing(t *testing.T) {
	f := newBoundNativeFixture(t)
	ops := f.c.ops.(*nativeSessionOperations)
	calls := 0
	ops.bindings.calls.dial = func(*uint16, *uint32, uintptr, *uintptr) uint32 { calls++; return 0 }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if handle, code := ops.Begin(ctx, nil); handle != 0 || code == 0 || calls != 0 {
		t.Fatal("canceled native invocation executed")
	}
}
