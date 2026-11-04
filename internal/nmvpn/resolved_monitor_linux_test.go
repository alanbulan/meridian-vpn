//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"mygo-vpn/internal/packetrelay"
)

func TestResolvedMonitorStickyRevocation(t *testing.T) {
	for _, mode := range []string{"policy drift", "read error", "owner revoked", "parent canceled", "explicit close", "cleanup error", "tick source closed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ticks := make(chan time.Time, 1)
			revoked := make(chan struct{})
			var calls, closes, stops atomic.Int32
			read := func(context.Context) (ResolvedObservationSnapshot, error) {
				n := calls.Add(1)
				value := ResolvedObservationSnapshot{BusID: "initial"}
				if n > 1 && mode == "policy drift" {
					value.BusID = "changed"
				}
				if n > 1 && mode == "read error" {
					return value, errors.New("injected")
				}
				return value, nil
			}
			cleanupErr := errors.New("cleanup uncertainty")
			m, err := startResolvedMonitor(ctx, read, revoked, func() error {
				closes.Add(1)
				if mode == "cleanup error" {
					return cleanupErr
				}
				return nil
			}, ticks, func() { stops.Add(1) })
			if err != nil || m == nil || calls.Load() != 1 {
				t.Fatal("monitor startup failed", err)
			}
			done := m.Done()
			if done != m.Done() {
				t.Fatal("unstable Done")
			}
			switch mode {
			case "policy drift", "read error":
				ticks <- time.Now()
			case "owner revoked":
				close(revoked)
			case "parent canceled", "cleanup error":
				cancel()
			case "explicit close":
				if err = m.Close(); err != nil {
					t.Fatal(err)
				}
			case "tick source closed":
				close(ticks)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("monitor did not join revocation")
			}
			first := m.Wait()
			if first == nil || m.Wait() != first {
				t.Fatal("terminal outcome is not sticky")
			}
			if mode == "cleanup error" && (!errors.Is(first, cleanupErr) || !errors.Is(m.Close(), cleanupErr)) {
				t.Fatal("cleanup uncertainty lost")
			}
			if mode != "cleanup error" && m.Close() != nil {
				t.Fatal("clean observation transport close failed")
			}
			if closes.Load() != 1 || stops.Load() != 1 {
				t.Fatal("observation teardown replayed")
			}
			copied := *m
			if copied.Done() != nil || copied.Close() == nil || copied.Wait() == nil {
				t.Fatal("copied monitor gained ownership")
			}
		})
	}
}

func TestResolvedMonitorJoinsInFlightRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time, 1)
	revoked := make(chan struct{})
	entered := make(chan struct{})
	joined := make(chan struct{})
	var calls atomic.Int32
	m, err := startResolvedMonitor(ctx, func(ctx context.Context) (ResolvedObservationSnapshot, error) {
		if calls.Add(1) == 1 {
			return ResolvedObservationSnapshot{}, nil
		}
		close(entered)
		<-ctx.Done()
		close(joined)
		return ResolvedObservationSnapshot{}, ctx.Err()
	}, revoked, func() error { return nil }, ticks, func() {})
	if err != nil {
		t.Fatal(err)
	}
	ticks <- time.Now()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("read not entered")
	}
	close(revoked)
	select {
	case <-m.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("owner revocation did not cancel read")
	}
	select {
	case <-joined:
	default:
		t.Fatal("Done escaped pending read")
	}
	if m.Wait() == nil || m.Close() != nil {
		t.Fatal("incorrect terminal state")
	}
}

func TestResolvedMonitorStartupFailureJoins(t *testing.T) {
	for _, mode := range []string{"canceled", "already revoked", "read error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			revoked := make(chan struct{})
			ticks := make(chan time.Time)
			if mode == "canceled" {
				cancel()
			}
			if mode == "already revoked" {
				close(revoked)
			}
			closes, stops, calls := 0, 0, 0
			m, err := startResolvedMonitor(ctx, func(context.Context) (ResolvedObservationSnapshot, error) {
				calls++
				return ResolvedObservationSnapshot{}, errors.New("injected")
			}, revoked, func() error { closes++; return nil }, ticks, func() { stops++ })
			if err == nil || m != nil || closes != 1 || stops != 1 {
				t.Fatal("failed admission retained worker/transport")
			}
			if mode != "read error" && calls != 0 {
				t.Fatal("revoked startup performed observation")
			}
		})
	}
	if m, err := StartResolvedPolicyMonitor(context.Background(), nil, packetrelay.KernelNamespaceIdentity{}); err == nil || m != nil {
		t.Fatal("nil observer accepted")
	}
}

func TestResolvedMonitorStablePollingAndConcurrentClose(t *testing.T) {
	ticks := make(chan time.Time, 1)
	revoked := make(chan struct{})
	observed := make(chan int32, 3)
	var calls, closes atomic.Int32
	m, err := startResolvedMonitor(context.Background(), func(context.Context) (ResolvedObservationSnapshot, error) {
		observed <- calls.Add(1)
		return ResolvedObservationSnapshot{BusID: "stable"}, nil
	}, revoked, func() error { closes.Add(1); return nil }, ticks, func() {})
	if err != nil {
		t.Fatal(err)
	}
	<-observed
	for i := 0; i < 2; i++ {
		ticks <- time.Now()
		select {
		case <-observed:
		case <-m.Done():
			t.Fatal("unchanged policy revoked")
		case <-time.After(2 * time.Second):
			t.Fatal("poll did not run")
		}
	}
	joined := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() { joined <- m.Close() }()
	}
	for i := 0; i < 4; i++ {
		select {
		case err := <-joined:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent close did not join")
		}
	}
	if calls.Load() != 3 || closes.Load() != 1 || m.Wait() == nil {
		t.Fatal("stable polling or close ownership lost")
	}
}
