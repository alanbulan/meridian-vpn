//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"reflect"
	"time"

	"mygo-vpn/internal/packetrelay"
)

// ResolvedPolicyMonitor detects changes from its first concrete observation.
// It never approves that baseline, supplies ServicePolicy/HostBinding or grants
// readiness. Polling cannot detect every transient silent change; publication
// still needs a fresh synchronous check and independent complete host authority.
// It owns only the supplied dedicated resolver observer, never network resources.
// Done closes after its worker and revocation watcher have joined; Close joins
// them too. In-flight filesystem/namespace syscalls inherit their read caveats.
type ResolvedPolicyMonitor struct {
	self     *ResolvedPolicyMonitor
	cancel   context.CancelFunc
	done     chan struct{}
	result   error
	closeErr error
}

// After validating non-nil inputs, StartResolvedPolicyMonitor takes ownership
// of observer for observation and
// closure, including startup failure. Keep the original observer for any sticky
// cleanup error. It samples every second and never rebaselines after a failure.
// This performs read-only I/O; it does not start or configure systemd-resolved.
func StartResolvedPolicyMonitor(ctx context.Context, observer *PinnedResolvedObserver, expected packetrelay.KernelNamespaceIdentity) (*ResolvedPolicyMonitor, error) {
	if ctx == nil || observer == nil || observer.Done() == nil {
		return nil, errResolvedObservation
	}
	ticker := time.NewTicker(time.Second)
	return startResolvedMonitor(ctx, func(ctx context.Context) (ResolvedObservationSnapshot, error) {
		observed, err := observer.ObserveAllLinks(ctx, expected)
		if err != nil {
			return ResolvedObservationSnapshot{}, err
		}
		return observed.Snapshot()
	}, observer.Done(), observer.Close, ticker.C, ticker.Stop)
}

// All alternate observations and timing are private fixture seams.
func startResolvedMonitor(ctx context.Context, observe func(context.Context) (ResolvedObservationSnapshot, error), revoked <-chan struct{}, closeObserver func() error, ticks <-chan time.Time, stopTicks func()) (*ResolvedPolicyMonitor, error) {
	if ctx == nil || observe == nil || revoked == nil || closeObserver == nil || ticks == nil || stopTicks == nil {
		return nil, errResolvedObservation
	}
	run, cancel := context.WithCancel(ctx)
	watchJoined := make(chan struct{})
	go func() {
		defer close(watchJoined)
		select {
		case <-revoked:
			cancel()
		case <-run.Done():
		}
	}()
	fail := func(err error) (*ResolvedPolicyMonitor, error) {
		cancel()
		<-watchJoined
		stopTicks()
		return nil, errors.Join(errResolvedObservation, err, closeObserver())
	}
	if run.Err() != nil {
		return fail(run.Err())
	}
	select {
	case <-revoked:
		return fail(errResolvedObservation)
	default:
	}
	baseline, err := observe(run)
	if err != nil || run.Err() != nil {
		return fail(errors.Join(err, run.Err()))
	}
	m := &ResolvedPolicyMonitor{cancel: cancel, done: make(chan struct{})}
	m.self = m
	go func() {
		var result error
		defer func() {
			cancel()
			<-watchJoined
			stopTicks()
			m.closeErr = closeObserver()
			m.result = errors.Join(errResolvedObservation, result, m.closeErr)
			close(m.done)
		}()
		for {
			select {
			case <-run.Done():
				result = run.Err()
				return
			case _, ok := <-ticks:
				if !ok {
					result = errResolvedObservation
					return
				}
				current, err := observe(run)
				if err != nil || run.Err() != nil || !reflect.DeepEqual(current, baseline) {
					result = errors.Join(err, run.Err())
					return
				}
			}
		}
	}()
	return m, nil
}

// Done is stable. Closure means observation was revoked/stopped, never success.
func (m *ResolvedPolicyMonitor) Done() <-chan struct{} {
	if m == nil || m.self != m {
		return nil
	}
	return m.done
}

// Wait reports the sticky terminal observation loss and any cleanup uncertainty.
func (m *ResolvedPolicyMonitor) Wait() error {
	if m == nil || m.self != m {
		return errResolvedObservation
	}
	<-m.done
	return m.result
}

// Close stops polling and joins both workers. Nil means only the dedicated
// observation transport closed cleanly; it never proves network cleanup.
func (m *ResolvedPolicyMonitor) Close() error {
	if m == nil {
		return nil
	}
	if m.self != m {
		return errResolvedObservation
	}
	m.cancel()
	<-m.done
	return m.closeErr
}
