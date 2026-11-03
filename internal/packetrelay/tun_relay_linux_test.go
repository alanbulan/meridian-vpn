//go:build linux

package packetrelay

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Every endpoint below is in-memory. No test calls AcquireTUN, opens a device,
// creates a socket, changes network state, or launches a native worker.
func fakeTUNRelay(t *testing.T) (*TUNRelay, *TUNResource, *fakeTUNDevice, *fakePackets, *tunRelayClaim) {
	t.Helper()
	d := newFakeTUN()
	d.packets = fake()
	tun, err := acquireFakeTUN(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	child, claim := fake(), &tunRelayClaim{}
	r, err := bindTUNRelay(tun, child, claim)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.Stop(ctx)
	})
	return r, tun, d, child, claim
}

func waitTUNRelay(t *testing.T, r *TUNRelay) (Counts, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	counts, err := r.Wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("relay did not join")
	}
	return counts, err
}

func TestTUNRelayRetainedFlowAndIdentity(t *testing.T) {
	r, tun, d, child, _ := fakeTUNRelay(t)
	binding := r.Binding()
	if err := r.CheckBinding(binding); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), policy(t)); err != nil {
		t.Fatal(err)
	}
	d.packets.reads <- packet(17, "10.8.0.2", "10.20.0.10")
	child.reads <- packet(17, "10.20.0.10", "10.8.0.2")
	receive(t, child.writes)
	receive(t, d.packets.writes)
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	counts, err := waitTUNRelay(t, r)
	if !errors.Is(err, context.Canceled) || counts.Outbound != 1 || counts.Inbound != 1 {
		t.Fatalf("result: %+v %v", counts, err)
	}
	if d.createCalls != 1 || d.observeCalls != 3 || d.closeCalls != 1 || child.closes.Load() != 1 {
		t.Fatal("resource reopened, close repeated, or observation missing")
	}
	if err = r.CheckBinding(binding); err != nil || r.Binding() != binding {
		t.Fatal("cleanup erased immutable identity")
	}
	if value, err := tun.InitialObservation(); err != nil || value.Name != "mrd0" {
		t.Fatal("cleanup erased acquisition evidence")
	}
	if err = r.Stop(context.Background()); err != nil || d.closeCalls != 1 || child.closes.Load() != 1 {
		t.Fatal("repeated stop replayed cleanup")
	}
	if err = r.Start(context.Background(), policy(t)); err == nil {
		t.Fatal("restarted stopped relay")
	}
	other, _, _, _, _ := fakeTUNRelay(t)
	if r.CheckBinding(other.Binding()) == nil || r.CheckBinding(TUNRelayBinding{}) == nil {
		t.Fatal("foreign identity accepted")
	}
}

func TestTUNRelayBindOwnershipAndDuplicates(t *testing.T) {
	r, tun, _, child, claim := fakeTUNRelay(t)
	for _, candidate := range []PacketIO{child, fake()} {
		for _, c := range []*tunRelayClaim{claim, {}} {
			if next, err := bindTUNRelay(tun, candidate, c); next != nil || err == nil {
				t.Fatal("duplicate TUN admitted")
			}
		}
		if candidate.(*fakePackets).closes.Load() != 0 {
			t.Fatal("failed bind took ownership or closed active alias")
		}
	}
	d := newFakeTUN()
	another, err := acquireFakeTUN(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	defer another.Close()
	if next, err := bindTUNRelay(another, child, claim); next != nil || err == nil {
		t.Fatal("child bound to two TUNs")
	}
	if another.relay != nil || d.closeCalls != 0 || child.closes.Load() != 0 {
		t.Fatal("failed child claim altered resource ownership")
	}
	if err = r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if next, err := bindTUNRelay(another, child, claim); next != nil || err == nil {
		t.Fatal("child claim reset after stop")
	}
}

func TestTUNRelayPublicEntryRejectsUnverifiedEndpoints(t *testing.T) {
	for _, child := range []*DatagramPackets{nil, {}} {
		if r, err := BindTUNRelay(&TUNResource{}, child); r != nil || err == nil {
			t.Fatal("unverified concrete endpoint accepted")
		}
	}
	var nilPackets *fakePackets
	for _, child := range []PacketIO{nil, nilPackets} {
		if r, err := bindTUNRelay(&TUNResource{}, child, &tunRelayClaim{}); r != nil || err == nil {
			t.Fatal("nil endpoint accepted")
		}
	}
	child := fake()
	for _, tun := range []*TUNResource{nil, {}} {
		if r, err := bindTUNRelay(tun, child, &tunRelayClaim{}); r != nil || err == nil {
			t.Fatal("unacquired resource accepted")
		}
	}
	if child.closes.Load() != 0 {
		t.Fatal("failed bind consumed caller's child")
	}
	var zero TUNRelay
	if zero.CheckBinding(zero.Binding()) == nil || zero.Start(context.Background(), policy(t)) == nil || zero.Stop(context.Background()) == nil {
		t.Fatal("zero relay usable")
	}
	if _, err := zero.Wait(context.Background()); err == nil {
		t.Fatal("zero relay wait usable")
	}
	var absent *TUNRelay
	if absent.CheckBinding(absent.Binding()) == nil {
		t.Fatal("nil relay identity valid")
	}
}

func TestTUNRelayFirstStartFailureOwnsCleanup(t *testing.T) {
	for _, reason := range []string{"nil-context", "canceled", "nil-policy", "zero-policy", "changed", "observation-error", "during-observation", "already-closed"} {
		t.Run(reason, func(t *testing.T) {
			r, tun, d, child, _ := fakeTUNRelay(t)
			binding := r.Binding()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := policy(t)
			switch reason {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "nil-policy":
				p = nil
			case "zero-policy":
				p = &Policy{}
			case "changed":
				d.value.Name = "replacement"
			case "observation-error":
				d.observeErr = io.ErrUnexpectedEOF
			case "during-observation":
				d.onObserve = cancel
			case "already-closed":
				_ = tun.Close()
			}
			if err := r.Start(ctx, p); err == nil {
				t.Fatal("failed start accepted")
			}
			if _, err := waitTUNRelay(t, r); err == nil {
				t.Fatal("failure not retained")
			}
			if d.closeCalls != 1 || child.closes.Load() != 1 {
				t.Fatal("failed startup lost cleanup ownership")
			}
			if r.CheckBinding(binding) != nil {
				t.Fatal("failed start erased identity")
			}
			if r.Start(context.Background(), policy(t)) == nil {
				t.Fatal("failed start replayed")
			}
		})
	}
}

func TestTUNRelayStopBeforeStartAndWaitTimeout(t *testing.T) {
	r, _, d, child, _ := fakeTUNRelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("wait did not honor context")
	}
	if d.closeCalls != 0 || child.closes.Load() != 0 {
		t.Fatal("wait canceled unopened run")
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Start(context.Background(), policy(t)) == nil {
		t.Fatal("stop before start not permanent")
	}
	if _, err := r.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("terminal operation result missing")
	}
	if d.closeCalls != 1 || child.closes.Load() != 1 {
		t.Fatal("stop lost owned endpoint")
	}
}

func TestTUNRelayBothDirectionFailures(t *testing.T) {
	for _, direction := range []string{"out", "in"} {
		for _, reason := range []string{"malformed", "oversize", "short", "write-error", "eof", "blocked-write"} {
			t.Run(direction+"/"+reason, func(t *testing.T) {
				r, _, d, child, _ := fakeTUNRelay(t)
				src, dst := d.packets, child
				b := packet(17, "10.8.0.2", "10.20.0.10")
				if direction == "in" {
					src, dst = child, d.packets
					b = packet(17, "10.20.0.10", "10.8.0.2")
				}
				want := ErrRejected
				switch reason {
				case "malformed":
					b[0] = 0
				case "oversize":
					b = make([]byte, 1600)
				case "short":
					dst.short = true
					want = io.ErrShortWrite
				case "write-error":
					dst.writeErr = io.ErrUnexpectedEOF
					want = io.ErrUnexpectedEOF
				case "eof":
					b = nil
					want = io.EOF
				case "blocked-write":
					dst.blockWrite = true
					dst.writeStarted = make(chan struct{}, 1)
					want = context.Canceled
				}
				if err := r.Start(context.Background(), policy(t)); err != nil {
					t.Fatal(err)
				}
				src.reads <- b
				if reason == "blocked-write" {
					select {
					case <-dst.writeStarted:
					case <-time.After(time.Second):
						t.Fatal("write never entered")
					}
					if err := r.Stop(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				_, err := waitTUNRelay(t, r)
				if !errors.Is(err, want) || d.closeCalls != 1 || child.closes.Load() != 1 {
					t.Fatalf("failure not joined: %v", err)
				}
			})
		}
	}
}

func TestTUNRelayCloseAndObservationDriftTerminate(t *testing.T) {
	for _, drift := range []bool{false, true} {
		r, tun, d, child, _ := fakeTUNRelay(t)
		binding := r.Binding()
		if err := r.Start(context.Background(), policy(t)); err != nil {
			t.Fatal(err)
		}
		if drift {
			d.value.Name = "replacement"
			if _, err := tun.Observe(context.Background()); err == nil {
				t.Fatal("drift accepted")
			}
		} else {
			_ = tun.Close()
		}
		_, _ = waitTUNRelay(t, r)
		if d.closeCalls != 1 || child.closes.Load() != 1 || r.CheckBinding(binding) != nil {
			t.Fatal("original-resource close lost relay or identity")
		}
	}
}

func TestTUNRelayCloseErrorsAreSticky(t *testing.T) {
	for _, phase := range []string{"before-start", "start-failure", "running"} {
		for _, side := range []string{"host", "child", "both"} {
			t.Run(phase+"/"+side, func(t *testing.T) {
				r, _, d, child, _ := fakeTUNRelay(t)
				binding := r.Binding()
				if side != "child" {
					d.closeErr = io.ErrUnexpectedEOF
				}
				if side != "host" {
					child.closeErr = io.ErrShortWrite
				}
				if phase == "running" {
					if err := r.Start(context.Background(), policy(t)); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "start-failure" {
					if err := r.Start(nil, policy(t)); !errors.Is(err, ErrCleanup) {
						t.Fatal("failed start lost cleanup error")
					}
				}
				for i := 0; i < 2; i++ {
					if err := r.Stop(context.Background()); !errors.Is(err, ErrCleanup) {
						t.Fatal("cleanup uncertainty erased")
					}
				}
				_, err := waitTUNRelay(t, r)
				if !errors.Is(err, ErrCleanup) || (side != "child" && !errors.Is(err, io.ErrUnexpectedEOF)) || (side != "host" && !errors.Is(err, io.ErrShortWrite)) {
					t.Fatal("close evidence lost")
				}
				if d.closeCalls != 1 || child.closes.Load() != 1 || r.CheckBinding(binding) != nil {
					t.Fatal("cleanup replayed or identity erased")
				}
			})
		}
	}
}

// Deliberately violate the private fake's close-unblocks contract to establish
// that a timeout cannot be mistaken for a join or discard the original owner.
type delayedRelayPackets struct {
	*fakePackets
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (d *delayedRelayPackets) ReadPacket(b []byte) (int, error) {
	d.once.Do(func() { close(d.entered) })
	<-d.release
	return 0, io.EOF
}

func TestTUNRelayStopTimeoutRetainsOriginalJoin(t *testing.T) {
	d := newFakeTUN()
	d.packets = fake()
	tun, err := acquireFakeTUN(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	child := &delayedRelayPackets{fakePackets: fake(), release: make(chan struct{}), entered: make(chan struct{})}
	r, err := bindTUNRelay(tun, child, &tunRelayClaim{})
	if err != nil {
		t.Fatal(err)
	}
	binding := r.Binding()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(child.release) }) }
	t.Cleanup(func() { release(); _ = r.Stop(context.Background()) })
	if err = r.Start(context.Background(), policy(t)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.entered:
	case <-time.After(time.Second):
		t.Fatal("pump did not enter")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = r.Stop(ctx); !errors.Is(err, ErrCleanup) || !errors.Is(err, context.Canceled) {
		t.Fatal("unjoined stop reported clean")
	}
	if r.CheckBinding(binding) != nil {
		t.Fatal("timeout erased recovery identity")
	}
	release()
	if err = r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _ = waitTUNRelay(t, r)
	if d.closeCalls != 1 || child.closes.Load() != 1 {
		t.Fatal("timeout replayed cleanup")
	}
}

func TestTUNRelayConcurrentStartStopAndObservation(t *testing.T) {
	for attempt := 0; attempt < 30; attempt++ {
		r, tun, d, child, _ := fakeTUNRelay(t)
		binding := r.Binding()
		p := policy(t)
		var group sync.WaitGroup
		for i := 0; i < 16; i++ {
			group.Add(1)
			go func(i int) {
				defer group.Done()
				switch i % 4 {
				case 0:
					_ = r.Start(context.Background(), p)
				case 1:
					_ = r.Stop(context.Background())
				case 2:
					_, _ = tun.Observe(context.Background())
					_ = tun.Close()
				case 3:
					if r.CheckBinding(binding) != nil {
						t.Error("immutable identity changed")
					}
				}
			}(i)
		}
		group.Wait()
		_, _ = waitTUNRelay(t, r)
		if d.closeCalls != 1 || child.closes.Load() != 1 {
			t.Fatal("concurrent lifecycle duplicated cleanup")
		}
	}
}

func TestTUNRelayConcurrentBindClaims(t *testing.T) {
	for _, sharedTUN := range []bool{false, true} {
		for attempt := 0; attempt < 30; attempt++ {
			d1, d2 := newFakeTUN(), newFakeTUN()
			tun1, err := acquireFakeTUN(context.Background(), d1)
			if err != nil {
				t.Fatal(err)
			}
			tun2, err := acquireFakeTUN(context.Background(), d2)
			if err != nil {
				t.Fatal(err)
			}
			child1, child2 := fake(), fake()
			claim1, claim2 := &tunRelayClaim{}, &tunRelayClaim{}
			secondTUN, secondChild, secondClaim := tun2, child1, claim1
			if sharedTUN {
				secondTUN, secondChild, secondClaim = tun1, child2, claim2
			}
			start := make(chan struct{})
			winners := make(chan *TUNRelay, 2)
			var group sync.WaitGroup
			group.Add(2)
			go func() { defer group.Done(); <-start; r, _ := bindTUNRelay(tun1, child1, claim1); winners <- r }()
			go func() {
				defer group.Done()
				<-start
				r, _ := bindTUNRelay(secondTUN, secondChild, secondClaim)
				winners <- r
			}()
			close(start)
			group.Wait()
			first, second := <-winners, <-winners
			if (first == nil) == (second == nil) {
				t.Fatal("concurrent claims did not have exactly one winner")
			}
			if first == nil {
				first = second
			}
			if d1.closeCalls != 0 || d2.closeCalls != 0 || child1.closes.Load() != 0 || child2.closes.Load() != 0 {
				t.Fatal("rejected bind closed an endpoint")
			}
			if sharedTUN {
				if (claim1.owner == nil) == (claim2.owner == nil) || tun2.relay != nil {
					t.Fatal("loser's child claim consumed")
				}
			} else if (tun1.relay == nil) == (tun2.relay == nil) || claim2.owner != nil {
				t.Fatal("loser's TUN claim consumed")
			}
			if err := first.Stop(context.Background()); err != nil {
				t.Fatal(err)
			}
			_ = tun1.Close()
			_ = tun2.Close()
			if child1.closes.Load() == 0 {
				_ = child1.Close()
			}
			if child2.closes.Load() == 0 {
				_ = child2.Close()
			}
		}
	}
}

func TestTUNRelayRejectsCopiedOwners(t *testing.T) {
	r, tun, _, _, _ := fakeTUNRelay(t)
	// Reflection deliberately copies without a copylocks lint violation. Even
	// a caller ignoring the pointer-only API must not create a second owner.
	copied := reflect.New(reflect.TypeOf(r).Elem()).Interface().(*TUNRelay)
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(r).Elem())
	if copied.CheckBinding(r.Binding()) == nil || copied.Start(context.Background(), policy(t)) == nil || copied.Stop(context.Background()) == nil {
		t.Fatal("copied lifecycle accepted")
	}
	if _, err := copied.Wait(context.Background()); err == nil {
		t.Fatal("copied wait accepted")
	}
	copyTUN := reflect.New(reflect.TypeOf(tun).Elem()).Interface().(*TUNResource)
	reflect.ValueOf(copyTUN).Elem().Set(reflect.ValueOf(tun).Elem())
	if next, err := bindTUNRelay(copyTUN, fake(), &tunRelayClaim{}); next != nil || err == nil {
		t.Fatal("copied TUN accepted")
	}
}
