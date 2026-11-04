package macosvpn

import (
	"context"
	"mygo-vpn/internal/core"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"
)

// ExistingNetworkPolicy is explicit expected policy, not observed configuration.
// IPv6 must be tunneled or independently blocked; an IPv4-only interface is not
// evidence that IPv6 cannot bypass it. No policy writes are performed here.
type ExistingNetworkPolicy struct {
	IPv4Prefixes, IPv6Prefixes []netip.Prefix
	DNSDomains                 []string
	DNSServers                 []netip.Addr
	IPv6Mode                   string // "tunnel" or "blocked"; neither is inferred.
}

func (p ExistingNetworkPolicy) valid() bool {
	if len(p.IPv4Prefixes) == 0 || len(p.IPv4Prefixes) > 64 || len(p.IPv6Prefixes) > 64 || len(p.DNSDomains) == 0 || len(p.DNSDomains) > 32 || len(p.DNSServers) == 0 || len(p.DNSServers) > 16 {
		return false
	}
	if p.IPv6Mode != "tunnel" && p.IPv6Mode != "blocked" {
		return false
	}
	if (p.IPv6Mode == "tunnel") != (len(p.IPv6Prefixes) > 0) {
		return false
	}
	seen := map[string]bool{}
	for family, prefixes := range [][]netip.Prefix{p.IPv4Prefixes, p.IPv6Prefixes} {
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Is4() != (family == 0) || seen[prefix.String()] {
				return false
			}
			seen[prefix.String()] = true
		}
	}
	for _, domain := range p.DNSDomains {
		if !dnsDomain(domain) || seen[domain] {
			return false
		}
		seen[domain] = true
	}
	for _, ip := range p.DNSServers {
		if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || seen[ip.String()] {
			return false
		}
		seen[ip.String()] = true
	}
	return true
}
func clonePolicy(p ExistingNetworkPolicy) ExistingNetworkPolicy {
	p.IPv4Prefixes = slices.Clone(p.IPv4Prefixes)
	p.IPv6Prefixes = slices.Clone(p.IPv6Prefixes)
	p.DNSDomains = slices.Clone(p.DNSDomains)
	p.DNSServers = slices.Clone(p.DNSServers)
	return p
}

// policyBaseline and policyVerifier are private trusted-broker boundaries.
// available means the implementation can independently prove installed routes,
// effective DNS selection, IPv6 enforcement and attributable restoration. A
// partial readback or configuration dictionary MUST NOT satisfy this contract.
// No production verifier currently meets it; native readback remains diagnostic.
type policyBaseline struct{ token uint64 }
type policyVerifier interface {
	available() bool
	capture(context.Context, ExistingNetworkPolicy) (policyBaseline, error)
	active(context.Context, policyBaseline, GenerationEvidence, ExistingNetworkPolicy) error
	restored(context.Context, policyBaseline, *GenerationEvidence, ExistingNetworkPolicy) error
}
type unavailablePolicyVerifier struct{}

func (unavailablePolicyVerifier) available() bool { return false }
func (unavailablePolicyVerifier) capture(context.Context, ExistingNetworkPolicy) (policyBaseline, error) {
	return policyBaseline{}, ErrExistingUnavailable
}
func (unavailablePolicyVerifier) active(context.Context, policyBaseline, GenerationEvidence, ExistingNetworkPolicy) error {
	return ErrExistingUnavailable
}
func (unavailablePolicyVerifier) restored(context.Context, policyBaseline, *GenerationEvidence, ExistingNetworkPolicy) error {
	return ErrExistingUnavailable
}

type existingControl interface {
	Connect(context.Context, *ExistingServiceSelection, ExistingServiceConsent) (ExistingServiceObservation, error)
	Check(context.Context) (ExistingServiceObservation, error)
	Stop(context.Context) (ExistingServiceStopObservation, error)
}

// ExistingCoreAdapter implements core.Adapter without weakening the generic
// password/PSK mode. Its profile token is deliberately a distinct, not-yet-enabled
// protocol; ordinary Engine/Profile validation does not silently accept it.
// Production Capability is unavailable until all independent policy proofs exist.
// The injectable constructor is private and used only by offline lifecycle tests.
type ExistingCoreAdapter struct {
	mu                sync.Mutex
	control           existingControl
	selection         *ExistingServiceSelection
	consent           ExistingServiceConsent
	policy            ExistingNetworkPolicy
	verifier          policyVerifier
	limited           *limitedServiceVerification
	profile           core.Profile
	used              bool
	session           *existingCoreSession
	poll, stopTimeout time.Duration
}

var _ core.Adapter = (*ExistingCoreAdapter)(nil)
var _ core.Session = (*existingCoreSession)(nil)

func NewExistingCoreAdapter(selection *ExistingServiceSelection, consent ExistingServiceConsent, policy ExistingNetworkPolicy) *ExistingCoreAdapter {
	var control existingControl
	if selection != nil && selection.state != nil {
		control = selection.state.owner
	}
	return newExistingCoreAdapter(control, selection, consent, policy, unavailablePolicyVerifier{})
}
func newExistingCoreAdapter(control existingControl, selection *ExistingServiceSelection, consent ExistingServiceConsent, policy ExistingNetworkPolicy, verifier policyVerifier) *ExistingCoreAdapter {
	c := selection.Configuration()
	return &ExistingCoreAdapter{control: control, selection: selection, consent: consent, policy: clonePolicy(policy), verifier: verifier, profile: core.Profile{ID: c.ServiceID, Name: "现有 macOS 系统服务", Protocol: "macos-system-l2tp", Gateway: c.Gateway}, poll: time.Second, stopTimeout: 30 * time.Second}
}
func (a *ExistingCoreAdapter) available() bool {
	if a == nil || a.control == nil || a.selection == nil || a.selection.state == nil || (a.limited == nil && (a.verifier == nil || !a.policy.valid())) {
		return false
	}
	c := a.consent
	if !c.NetworkChanges || !c.SavedSystemCredentials || !c.SharedSystemService || !c.LimitedVerification {
		return false
	}
	if a.limited != nil {
		return a.limited.available()
	}
	available := false
	if existingGuard(func() error { available = a.verifier.available(); return nil }) != nil {
		return false
	}
	return available
}
func (a *ExistingCoreAdapter) VerificationScope() string {
	if a != nil && a.limited != nil {
		return core.SystemServiceTargetRoutes
	}
	return ""
}
func (a *ExistingCoreAdapter) Capability() core.Capability {
	if a != nil && a.limited != nil {
		return core.Capability{Available: a.available(), Message: "有限系统服务模式：验证系统连接与指定目标路由，不提供全应用 DNS/IPv6 防泄漏保证"}
	}
	return core.Capability{Available: a.available(), Message: "现有系统服务模式需要独立路由、有效 DNS、IPv6 与清理证明；当前原生验证未完成"}
}
func (a *ExistingCoreAdapter) Start(ctx context.Context, p core.Profile, password []byte) (core.Session, error) {
	if ctx == nil || ctx.Err() != nil || len(password) != 0 || !a.available() {
		return nil, core.NewConnectionError(core.FailureBackendUnavailable)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used || !reflect.DeepEqual(p, a.profile) {
		return nil, core.NewConnectionError(core.FailureConfiguration)
	}
	a.used = true
	op, cancel := context.WithCancel(ctx)
	s := &existingCoreSession{adapter: a, ctx: op, cancel: cancel, ready: make(chan error, 1), done: make(chan error, 1), workerDone: make(chan struct{}), stopGate: make(chan struct{}, 1)}
	a.session = s // Retain the worker/native interest even if caller drops its handle.
	go s.run()
	return s, nil
}

type existingCoreSession struct {
	adapter                                               *ExistingCoreAdapter
	ctx                                                   context.Context
	cancel                                                context.CancelFunc
	ready, done                                           chan error
	readyOnce, doneOnce                                   sync.Once
	workerDone                                            chan struct{}
	stopGate                                              chan struct{}
	mu                                                    sync.Mutex
	retryDone                                             chan struct{}
	retryErr                                              error
	baseline                                              policyBaseline
	captured, activationEntered, cleanupPending, poisoned bool
	generation                                            *GenerationEvidence
}

func (s *existingCoreSession) VerificationScope() string { return s.adapter.VerificationScope() }
func (s *existingCoreSession) Ready() <-chan error       { return s.ready }
func (s *existingCoreSession) Done() <-chan error        { return s.done }
func (s *existingCoreSession) publishReady(err error)    { s.readyOnce.Do(func() { s.ready <- err }) }
func (s *existingCoreSession) publishDone(err error)     { s.doneOnce.Do(func() { s.done <- err }) }
func (s *existingCoreSession) run() {
	defer close(s.workerDone)
	a := s.adapter

	var err error
	if a.limited == nil {
		baseline := policyBaseline{}
		err = existingGuard(func() error { var e error; baseline, e = a.verifier.capture(s.ctx, clonePolicy(a.policy)); return e })
		if err != nil || s.ctx.Err() != nil || baseline.token == 0 {
			s.publishReady(core.NewConnectionError(core.FailureReadiness))
			s.publishDone(core.NewConnectionError(core.FailureReadiness))
			return
		}
		s.baseline, s.captured = baseline, true
	}
	if s.ctx.Err() != nil {
		s.publishReady(core.NewConnectionError(core.FailureReadiness))
		s.publishDone(nil)
		return
	}
	s.activationEntered = true
	var observed ExistingServiceObservation
	err = existingGuard(func() error { var e error; observed, e = a.control.Connect(s.ctx, a.selection, a.consent); return e })
	if err == errExistingPanic {
		s.poisoned = true
	}
	if err != nil || !observed.SystemConnected || !validExistingGeneration(observed.Generation, a.profile.ID) {
		s.finish(core.NewConnectionError(core.FailureStart))
		return
	}
	g := cloneGeneration(observed.Generation)
	s.generation = &g
	if s.verifyActive() != nil {
		s.finish(core.NewConnectionError(core.FailureReadiness))
		return
	}
	if s.ctx.Err() != nil {
		s.finish(core.NewConnectionError(core.FailureReadiness))
		return
	}
	s.publishReady(nil)
	ticker := time.NewTicker(a.poll)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.finish(nil)
			return
		case <-ticker.C:
			if s.verifyActive() != nil {
				s.finish(core.NewConnectionError(core.FailureConnectionLost))
				return
			}
		}
	}
}
func (s *existingCoreSession) verifyActive() error {
	if s.generation == nil || s.ctx.Err() != nil {
		return ErrExistingVerification
	}
	a := s.adapter
	if a.limited != nil {
		if s.verifyGeneration() != nil {
			return ErrExistingVerification
		}
		if existingGuard(func() error { return a.limited.active(s.ctx, cloneGeneration(*s.generation)) }) != nil {
			return ErrExistingVerification
		}
		return s.verifyGeneration()
	}
	err := existingGuard(func() error {
		return a.verifier.active(s.ctx, s.baseline, cloneGeneration(*s.generation), clonePolicy(a.policy))
	})
	if err != nil {
		return ErrExistingVerification
	}
	return s.verifyGeneration()
}
func (s *existingCoreSession) verifyGeneration() error {
	if s.generation == nil || s.ctx.Err() != nil {
		return ErrExistingVerification
	}
	var current ExistingServiceObservation
	err := existingGuard(func() error { var e error; current, e = s.adapter.control.Check(s.ctx); return e })
	if err == errExistingPanic {
		s.poisoned = true
	}
	if err != nil || s.ctx.Err() != nil || !current.SystemConnected || !sameGeneration(*s.generation, current.Generation) {
		return ErrExistingVerification
	}
	return nil
}
func (s *existingCoreSession) cleanup() error {
	if !s.activationEntered {
		return nil
	}
	if s.poisoned {
		return &core.CleanupError{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.adapter.stopTimeout)
	defer cancel()
	err := existingGuard(func() error { _, e := s.adapter.control.Stop(ctx); return e })
	if err == errExistingPanic {
		s.poisoned = true
	}
	if err != nil || ctx.Err() != nil {
		return &core.CleanupError{}
	}
	if s.adapter.limited != nil {
		if existingGuard(func() error { return s.adapter.limited.restored(ctx, s.generation) }) != nil || ctx.Err() != nil {
			return &core.CleanupError{}
		}
		return nil
	}
	if !s.captured {
		return &core.CleanupError{}
	}
	var g *GenerationEvidence
	if s.generation != nil {
		copy := cloneGeneration(*s.generation)
		g = &copy
	}
	if existingGuard(func() error { return s.adapter.verifier.restored(ctx, s.baseline, g, clonePolicy(s.adapter.policy)) }) != nil || ctx.Err() != nil {
		return &core.CleanupError{}
	}
	return nil
}
func (s *existingCoreSession) finish(cause error) {
	err := s.cleanup()
	if err != nil {
		s.mu.Lock()
		s.cleanupPending = true
		s.mu.Unlock()
		cause = &core.CleanupError{}
	}
	if cause == nil {
		s.publishReady(core.NewConnectionError(core.FailureReadiness))
	} else {
		s.publishReady(cause)
	}
	s.publishDone(cause)
}

// Stop cancels the single owned worker, waits for it, then retries only if its
// prior cleanup was unconfirmed. A timeout publishes CleanupFailed before return
// and retains the worker; it never pretends an unreturned native call has stopped.
func (s *existingCoreSession) Stop() error {
	return s.stopWithContext(context.Background())
}

// RetryCleanup opts into the Engine's retained-session retry contract. It never
// initiates a new disconnect on a live session. Cancellation bounds this caller's
// wait only: the original or retry worker remains owned and cannot be re-entered.
func (s *existingCoreSession) RetryCleanup(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.ctx.Err() == nil {
		return &core.CleanupError{}
	}
	return s.stopWithContext(ctx)
}

func (s *existingCoreSession) stopWithContext(parent context.Context) error {
	if parent.Err() != nil {
		return &core.CleanupError{}
	}
	s.cancel()
	ctx, cancel := context.WithTimeout(parent, s.adapter.stopTimeout)
	defer cancel()
	select {
	case s.stopGate <- struct{}{}:
	case <-ctx.Done():
		s.publishReady(&core.CleanupError{})
		s.publishDone(&core.CleanupError{})
		return &core.CleanupError{}
	}
	defer func() { <-s.stopGate }()
	select {
	case <-s.workerDone:
	case <-ctx.Done():
		s.publishReady(&core.CleanupError{})
		s.publishDone(&core.CleanupError{})
		return &core.CleanupError{}
	}
	if ctx.Err() != nil {
		return &core.CleanupError{}
	}
	s.mu.Lock()
	pending := s.cleanupPending
	s.mu.Unlock()
	if pending {
		// stopGate serializes retry creation. An unreturned native cleanup stays
		// owned by this session and is never re-entered by another Stop call.
		if s.retryDone == nil {
			s.retryDone = make(chan struct{})
			done := s.retryDone
			go func() {
				s.retryErr = s.cleanup()
				close(done)
			}()
		}
		select {
		case <-s.retryDone:
			err := s.retryErr
			s.retryDone = nil
			if err != nil {
				return err
			}
			s.mu.Lock()
			s.cleanupPending = false
			s.mu.Unlock()
		case <-ctx.Done():
			s.publishReady(&core.CleanupError{})
			s.publishDone(&core.CleanupError{})
			return &core.CleanupError{}
		}
	}
	return nil
}

var _ core.CleanupRetrySession = (*existingCoreSession)(nil)
