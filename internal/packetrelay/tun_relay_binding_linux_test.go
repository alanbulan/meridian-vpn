//go:build linux

package packetrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Only the TUN is injected. Concrete packet endpoints come from anonymous local
// socketpairs. These tests never open a device or launch a native process.
func packetBindingRelay(t *testing.T) (*TUNRelay, *TUNResource, *fakeTUNDevice, *DatagramPackets, *DatagramPackets) {
	t.Helper()
	d := newFakeTUN()
	d.packets = fake()
	tun, err := acquireFakeTUN(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	peer, child := pairEnds(t)
	r, err := BindTUNRelay(tun, child)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.Stop(ctx)
	})
	return r, tun, d, peer, child
}

func assertPacketBindingRejected(t *testing.T, r *TUNRelay, ctx context.Context, child *DatagramPackets, name string) error {
	t.Helper()
	b, observation, err := r.ObservePacketBinding(ctx, child, name)
	if err == nil || b != (TUNRelayBinding{}) || observation != (TUNObservation{}) {
		t.Fatalf("rejection returned binding or observation: %+v %+v %v", b, observation, err)
	}
	return err
}

func TestTUNRelayPacketBindingFreshOriginalObservation(t *testing.T) {
	r, tun, d, peer, child := packetBindingRelay(t)
	b, value, err := r.ObservePacketBinding(context.Background(), child, "mrd0")
	if err != nil || b != r.Binding() || value != d.value || d.observeCalls != 3 {
		t.Fatalf("original binding: %+v %+v %v", b, value, err)
	}
	if r.attempted || d.closeCalls != 0 || tun.relay != r || child.relayClaim.owner != r {
		t.Fatal("observation started, closed, or changed ownership")
	}
	value.Name = "caller-mutated"
	if err = r.CheckPacketBinding(b, child); err != nil || d.observeCalls != 3 {
		t.Fatal("historical check performed live I/O")
	}
	b2, value2, err := r.ObservePacketBinding(context.Background(), child, "mrd0")
	if err != nil || b2 != b || value2 != d.value || d.observeCalls != 4 {
		t.Fatal("binding copied metadata into resource or cached a stale observation")
	}
	// The check neither consumes a pending record nor starts the relay pumps.
	want := []byte("still owned by the original relay")
	if _, err = peer.WritePacket(want); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.ObservePacketBinding(context.Background(), child, "mrd0"); err != nil {
		t.Fatal(err)
	}
	if err = child.file.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := child.ReadPacket(buf)
	if err != nil || !bytes.Equal(buf[:n], want) || len(d.packets.writes) != 0 {
		t.Fatal("observation consumed or forwarded a packet", err)
	}
	if err = child.file.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err = r.Start(context.Background(), policy(t)); err != nil {
		t.Fatal("observation consumed the relay's Start attempt", err)
	}
	if _, _, err = r.ObservePacketBinding(context.Background(), child, "mrd0"); err != nil {
		t.Fatal("running, unfinished relay could not be observed", err)
	}
	if err = r.Stop(context.Background()); err != nil || r.CheckPacketBinding(b, child) != nil {
		t.Fatal("stop erased historical identity", err)
	}
}

func TestTUNRelayPacketBindingRejectsOwnerAndChildSubstitution(t *testing.T) {
	r, tun, d, _, child := packetBindingRelay(t)
	other, otherTUN, otherDevice, _, otherChild := packetBindingRelay(t)
	_, unclaimedChild := pairEnds(t)
	// Reflection deliberately copies the owners without a copylocks lint error.
	copiedRelay := reflect.New(reflect.TypeOf(r).Elem()).Interface().(*TUNRelay)
	reflect.ValueOf(copiedRelay).Elem().Set(reflect.ValueOf(r).Elem())
	copiedChild := reflect.New(reflect.TypeOf(child).Elem()).Interface().(*DatagramPackets)
	reflect.ValueOf(copiedChild).Elem().Set(reflect.ValueOf(child).Elem())
	for _, tc := range []struct {
		name  string
		relay *TUNRelay
		child *DatagramPackets
	}{
		{"nil-relay", nil, child},
		{"zero-relay", &TUNRelay{}, child},
		{"copied-relay", copiedRelay, child},
		{"nil-child", r, nil},
		{"zero-child", r, &DatagramPackets{}},
		{"copied-child", r, copiedChild},
		{"unclaimed-pair", r, unclaimedChild},
		{"different-pair-same-tun-name", r, otherChild},
		{"different-relay-same-tun-name", other, child},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertPacketBindingRejected(t, tc.relay, context.Background(), tc.child, "mrd0")
			if tc.relay.CheckPacketBinding(tc.relay.Binding(), tc.child) == nil {
				t.Fatal("historical check accepted substituted endpoint or owner")
			}
		})
	}
	for _, b := range []TUNRelayBinding{{}, other.Binding(), {owner: copiedRelay}} {
		if r.CheckPacketBinding(b, child) == nil {
			t.Fatal("foreign or invalid binding accepted")
		}
	}
	if d.observeCalls != 2 || otherDevice.observeCalls != 2 || d.closeCalls != 0 || otherDevice.closeCalls != 0 {
		t.Fatal("identity rejection touched a TUN")
	}
	if tun.relay != r || otherTUN.relay != other || child.relayClaim.owner != r || otherChild.relayClaim.owner != other || unclaimedChild.relayClaim.owner != nil {
		t.Fatal("identity rejection stole or consumed endpoint ownership")
	}
	for _, owner := range []struct {
		relay *TUNRelay
		child *DatagramPackets
	}{{r, child}, {other, otherChild}} {
		if _, _, err := owner.relay.ObservePacketBinding(context.Background(), owner.child, "mrd0"); err != nil {
			t.Fatal("rejected pairing damaged an original owner", err)
		}
	}
	if err := unclaimedChild.raw.Control(func(uintptr) {}); err != nil {
		t.Fatal("rejection closed the unclaimed pair", err)
	}
	// A private fake PacketIO is not sufficient for the public provenance API.
	fakeOwner, _, _, _, _ := fakeTUNRelay(t)
	assertPacketBindingRejected(t, fakeOwner, context.Background(), child, "mrd0")
}

func TestTUNRelayPacketBindingRejectsWithoutCleanupOrStart(t *testing.T) {
	for _, reason := range []string{"nil-context", "canceled", "empty-name", "wrong-name", "invalid-name", "name-drift", "flag-drift", "observation-error", "canceled-during-observation"} {
		t.Run(reason, func(t *testing.T) {
			r, tun, d, _, child := packetBindingRelay(t)
			binding := r.Binding()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			name, wantCalls := "mrd0", 2
			var wantErr error
			switch reason {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
				wantErr = context.Canceled
			case "empty-name":
				name = ""
			case "wrong-name":
				name = "other"
			case "invalid-name":
				name = "mrd0\x00"
			case "name-drift":
				d.value.Name = "replacement"
				wantCalls++
			case "flag-drift":
				d.value.Flags = 0
				wantCalls++
			case "observation-error":
				d.observeErr = io.ErrUnexpectedEOF
				wantErr = io.ErrUnexpectedEOF
				wantCalls++
			case "canceled-during-observation":
				d.onObserve = cancel
				wantErr = context.Canceled
				wantCalls++
			}
			err := assertPacketBindingRejected(t, r, ctx, child, name)
			if wantErr != nil && !errors.Is(err, wantErr) {
				t.Fatal("lost observation or cancellation failure", err)
			}
			if d.observeCalls != wantCalls || d.closeCalls != 0 || tun.closed || r.attempted {
				t.Fatal("non-owning rejection closed or consumed the relay")
			}
			if r.CheckPacketBinding(binding, child) != nil || r.Binding() != binding {
				t.Fatal("rejection erased historical identity")
			}
			if err = child.raw.Control(func(uintptr) {}); err != nil {
				t.Fatal("rejection closed the original child", err)
			}
			select {
			case <-r.done:
				t.Fatal("rejection completed the unstarted relay")
			default:
			}
		})
	}
}

func TestTUNRelayPacketBindingClosedAndFailedCleanup(t *testing.T) {
	for _, phase := range []string{"closed-tun", "closed-child", "stopped", "failed-start", "running-stop"} {
		for _, closeFailure := range []string{"none", "tun", "child", "both"} {
			t.Run(phase+"/"+closeFailure, func(t *testing.T) {
				r, tun, d, _, child := packetBindingRelay(t)
				binding, _, err := r.ObservePacketBinding(context.Background(), child, "mrd0")
				if err != nil {
					t.Fatal(err)
				}
				if closeFailure == "tun" || closeFailure == "both" {
					d.closeErr = io.ErrUnexpectedEOF
				}
				if phase == "running-stop" {
					if err = r.Start(context.Background(), policy(t)); err != nil {
						t.Fatal(err)
					}
				}
				if closeFailure == "child" || closeFailure == "both" {
					// Model a partial external close so the owned close fails. No
					// numeric descriptor close or retry is used in the test.
					if err = child.file.Close(); err != nil {
						t.Fatal(err)
					}
				}
				switch phase {
				case "closed-tun":
					_ = tun.Close()
				case "closed-child":
					_ = child.Close()
				case "stopped", "running-stop":
					_ = r.Stop(context.Background())
				case "failed-start":
					if err = r.Start(nil, policy(t)); err == nil {
						t.Fatal("nil-context start accepted")
					}
				}
				beforeObserve, beforeClose := d.observeCalls, d.closeCalls
				assertPacketBindingRejected(t, r, context.Background(), child, "mrd0")
				if d.observeCalls != beforeObserve || d.closeCalls != beforeClose {
					t.Fatal("failed observation touched or retried a closed resource")
				}
				if r.CheckPacketBinding(binding, child) != nil || binding != r.Binding() {
					t.Fatal("partial cleanup erased historical association")
				}
				stopErr := r.Stop(context.Background())
				if (closeFailure != "none") != errors.Is(stopErr, ErrCleanup) {
					t.Fatal("cleanup uncertainty missing or invented", stopErr)
				}
				if closeFailure == "tun" || closeFailure == "both" {
					if !errors.Is(stopErr, io.ErrUnexpectedEOF) {
						t.Fatal("original TUN cleanup failure lost", stopErr)
					}
				}
				assertPacketBindingRejected(t, r, context.Background(), child, "mrd0")
				if err = r.CheckPacketBinding(binding, child); err != nil || d.closeCalls != 1 {
					t.Fatal("historical check replayed cleanup or discarded identity", err)
				}
				if next := r.Stop(context.Background()); (closeFailure != "none") != errors.Is(next, ErrCleanup) || d.closeCalls != 1 {
					t.Fatal("repeated stop erased cleanup failure or repeated close", next)
				}
			})
		}
	}
}

func TestTUNRelayPacketBindingConcurrentLifecycle(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		r, tun, d, _, child := packetBindingRelay(t)
		binding := r.Binding()
		p := policy(t)
		var group sync.WaitGroup
		for i := 0; i < 20; i++ {
			group.Add(1)
			go func(i int) {
				defer group.Done()
				switch i % 5 {
				case 0:
					_ = r.Start(context.Background(), p)
				case 1:
					_ = r.Stop(context.Background())
				case 2:
					_, _, _ = r.ObservePacketBinding(context.Background(), child, "mrd0")
				case 3:
					if r.CheckPacketBinding(binding, child) != nil {
						t.Error("historical identity changed during lifecycle")
					}
				case 4:
					_ = tun.Close()
				}
			}(i)
		}
		joined := make(chan struct{})
		go func() { group.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Fatal("observation deadlocked a relay lifecycle operation")
		}
		_, _ = waitTUNRelay(t, r)
		if d.closeCalls != 1 || r.CheckPacketBinding(binding, child) != nil {
			t.Fatal("concurrent observation changed cleanup or historical identity")
		}
	}
}
