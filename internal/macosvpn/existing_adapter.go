package macosvpn

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

var ErrExistingVerification = errors.New("现有系统服务的配置或会话观测不匹配")
var ErrExistingUnavailable = errors.New("现有系统服务的受控连接暂不可用")
var errExistingPanic = errors.New("原生调用结果不确定；保留隔离且禁止重入")

// ExistingServiceConsent is per attempt, never a saved or inferred permission.
// LimitedVerification acknowledges that only allowlisted configuration and
// service/interface state are checked: routes, DNS, IPv6 and traffic are not.
type ExistingServiceConsent struct {
	NetworkChanges, SavedSystemCredentials, SharedSystemService, LimitedVerification bool
}

// ExistingServiceSelection is an adapter-issued, one-use selection. It cannot
// be manufactured from a display name or a normal password/PSK profile.
type ExistingServiceSelection struct{ state *existingSelectionState }
type existingSelectionState struct {
	owner    *ExistingServiceAdapter
	config   ServiceConfiguration
	consumed bool // Value copies share the same one-use state, protected by gate.
}

func (s *ExistingServiceSelection) Configuration() ServiceConfiguration {
	if s == nil || s.state == nil {
		return ServiceConfiguration{}
	}
	return cloneConfiguration(s.state.config)
}

// ExistingServiceObservation is deliberately not core.Session.Ready. A true
// SystemConnected value does NOT authorize traffic or imply a leak-safe tunnel.
type ExistingServiceObservation struct {
	SystemConnected      bool
	Generation           GenerationEvidence
	RouteDNSIPv6Verified bool // Always false until a separate verifier exists.
}

// ExistingServiceStopObservation does not claim global network restoration.
type ExistingServiceStopObservation struct {
	InterestReleased, ServiceDisconnected bool
	NetworkRestored                       bool // Always false: no route/DNS ownership proof exists.
}

type existingNativeSession interface {
	WaitConnected(context.Context) error
	Stop(context.Context) error
}

// existingOperations is a trusted internal boundary. A normal start return
// with nil session and nonnil error must mean no native interest was acquired.
// Panic/unknown return cannot make that guarantee and remains quarantined.
// observe must bind its evidence to the passed retained native session.
type existingOperations interface {
	inspect(context.Context, string) (ServiceInspection, error)
	start(context.Context, string) (existingNativeSession, error)
	observe(context.Context, existingNativeSession, string) (ServiceInspection, error)
}
type appleExistingOperations struct{}

func (appleExistingOperations) inspect(ctx context.Context, id string) (ServiceInspection, error) {
	return InspectExistingService(ctx, id)
}
func (appleExistingOperations) start(ctx context.Context, id string) (existingNativeSession, error) {
	s, err := StartExistingL2TP(ctx, id, true)
	if s == nil {
		return nil, err
	}
	return s, err
}
func (appleExistingOperations) observe(ctx context.Context, s existingNativeSession, id string) (ServiceInspection, error) {
	native, ok := s.(*Session)
	if !ok || native == nil {
		return ServiceInspection{}, ErrExistingUnavailable
	}
	return native.inspectGeneration(ctx, id)
}

type borrowedInspection struct{ inspectionConnection }

func (borrowedInspection) close() {} // Never release the active Session's reference.
func (s *Session) inspectGeneration(ctx context.Context, id string) (ServiceInspection, error) {
	return s.inspectGenerationWith(ctx, id, readInterface)
}
func (s *Session) inspectGenerationWith(ctx context.Context, id string, lookup func(string) (observedInterface, error)) (ServiceInspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native == nil || s.stopping {
		return ServiceInspection{}, ErrExistingVerification
	}
	reader, ok := s.native.(inspectionConnection)
	if !ok {
		return ServiceInspection{}, ErrExistingUnavailable
	}
	result, err := inspectExistingService(ctx, id, func(string) (inspectionConnection, error) { return borrowedInspection{reader}, nil }, lookup)
	if err != nil || result.Status != Connected || result.Generation == nil {
		return ServiceInspection{}, ErrExistingVerification
	}
	return result, nil
}

type existingAttempt struct {
	selected                                         ServiceConfiguration
	native                                           existingNativeSession
	startEntered, returnKnown, startFailed, released bool
	poisoned                                         bool
	generation                                       *GenerationEvidence
}

// ExistingServiceAdapter is an explicit experimental system-service mode, NOT
// core.Adapter. It retains the native interest and quarantines uncertain cleanup.
// Native calls are synchronous: contexts bound waits between calls, not Apple API
// execution. No detached goroutine can race Stop against an unreturned native call.
// Dropping this adapter while active is not supported: the owner must call Stop
// and retain it on uncertainty. There is no process-crash cleanup guarantee.
type ExistingServiceAdapter struct {
	gate     chan struct{}
	mu       sync.Mutex
	cancel   context.CancelFunc
	stopping int
	ops      existingOperations
	current  *existingAttempt
}

func NewExistingServiceAdapter() *ExistingServiceAdapter {
	return newExistingAdapter(appleExistingOperations{})
}
func newExistingAdapter(ops existingOperations) *ExistingServiceAdapter {
	return &ExistingServiceAdapter{gate: make(chan struct{}, 1), ops: ops}
}
func (a *ExistingServiceAdapter) acquire(ctx context.Context) error {
	if a == nil || a.gate == nil || ctx == nil {
		return ErrExistingUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case a.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a *ExistingServiceAdapter) unlock() { <-a.gate }
func cloneConfiguration(c ServiceConfiguration) ServiceConfiguration {
	c.PPPAuthentication = slices.Clone(c.PPPAuthentication)
	return c
}
func cloneGeneration(g GenerationEvidence) GenerationEvidence {
	g.Interface.IPv4Addresses = slices.Clone(g.Interface.IPv4Addresses)
	return g
}
func validExistingGeneration(g GenerationEvidence, id string) bool {
	name := g.Interface.InterfaceName
	if g.ConnectTime <= 0 || g.Interface.ServiceID != id || g.Interface.InterfaceIndex <= 0 || len(g.Interface.IPv4Addresses) == 0 || len(g.Interface.IPv4Addresses) > 16 || !strings.HasPrefix(name, "ppp") || len(name) < 4 || len(name) > 15 {
		return false
	}
	for _, c := range name[3:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	addresses := make([]string, len(g.Interface.IPv4Addresses))
	for i, ip := range g.Interface.IPv4Addresses {
		addresses[i] = ip.String()
	}
	_, err := ipv4Set(addresses)
	return err == nil
}
func sameGeneration(x, y GenerationEvidence) bool {
	return x.ConnectTime > 0 && x.ConnectTime == y.ConnectTime && x.Interface.ServiceID == y.Interface.ServiceID && x.Interface.InterfaceName == y.Interface.InterfaceName && x.Interface.InterfaceIndex == y.Interface.InterfaceIndex && slices.Equal(x.Interface.IPv4Addresses, y.Interface.IPv4Addresses)
}
func existingGuard(call func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errExistingPanic
		}
	}()
	return call()
}
func (a *ExistingServiceAdapter) inspect(ctx context.Context, id string) (out ServiceInspection, err error) {
	err = existingGuard(func() error { var e error; out, e = a.ops.inspect(ctx, id); return e })
	if err != nil {
		return ServiceInspection{}, ErrExistingVerification
	}
	return out, nil
}
func validExistingConfiguration(c ServiceConfiguration, id string) bool {
	return validateDiagnosticConfig(c, id) == nil && c.IPSecAuthentication == "SharedSecret" && slices.Equal(c.PPPAuthentication, []string{"MSCHAP2"})
}

// Select reads only the explicitly selected ID. Active/transitioning services
// are refused, rather than adopted. The summary is partial, not a profile lease.
func (a *ExistingServiceAdapter) Select(ctx context.Context, id string) (*ExistingServiceSelection, error) {
	if !validServiceID(id) {
		return nil, ErrExistingVerification
	}
	if err := a.acquire(ctx); err != nil {
		return nil, err
	}
	defer a.unlock()
	a.mu.Lock()
	busy := a.current != nil || a.stopping != 0
	a.mu.Unlock()
	if busy {
		return nil, ErrBusy
	}
	observed, err := a.inspect(ctx, id)
	if err != nil || ctx.Err() != nil || !validExistingConfiguration(observed.Configuration, id) {
		return nil, ErrExistingVerification
	}
	if observed.Status != Disconnected || observed.Generation != nil {
		return nil, ErrBusy
	}
	return &ExistingServiceSelection{state: &existingSelectionState{owner: a, config: cloneConfiguration(observed.Configuration)}}, nil
}

// Connect starts exactly the selected service using its system-managed secrets.
// This never writes credentials, creates profiles, forces disconnect, changes
// routes itself or produces Ready. Check must be called for later observations;
// there is no background readiness monitor in this experimental coordinator.
func (a *ExistingServiceAdapter) Connect(ctx context.Context, s *ExistingServiceSelection, consent ExistingServiceConsent) (ExistingServiceObservation, error) {
	var zero ExistingServiceObservation
	if !consent.NetworkChanges || !consent.SavedSystemCredentials || !consent.SharedSystemService || !consent.LimitedVerification {
		return zero, ErrAuthorization
	}
	if err := a.acquire(ctx); err != nil {
		return zero, err
	}
	defer a.unlock()
	if s == nil || s.state == nil || s.state.owner != a || s.state.consumed {
		return zero, ErrAuthorization
	}
	a.mu.Lock()
	if a.current != nil || a.stopping != 0 {
		a.mu.Unlock()
		return zero, ErrBusy
	}
	op, cancel := context.WithTimeout(ctx, 90*time.Second)
	a.cancel = cancel
	a.mu.Unlock()
	defer func() { cancel(); a.mu.Lock(); a.cancel = nil; a.mu.Unlock() }()
	before, err := a.inspect(op, s.state.config.ServiceID)
	if err != nil || op.Err() != nil || before.Status != Disconnected || before.Generation != nil || !sameDiagnosticConfig(s.state.config, before.Configuration) {
		return zero, ErrExistingVerification
	}
	s.state.consumed = true
	attempt := &existingAttempt{selected: cloneConfiguration(s.state.config)}
	a.current = attempt
	fail := func(cause error) (ExistingServiceObservation, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := a.cleanup(cleanup); err != nil {
			return zero, ErrCleanup
		}
		return zero, cause
	}
	if op.Err() != nil {
		return fail(op.Err())
	}
	attempt.startEntered = true
	err = existingGuard(func() error {
		var startError error
		attempt.native, startError = a.ops.start(op, attempt.selected.ServiceID)
		attempt.returnKnown = true
		attempt.startFailed = startError != nil
		return startError
	})
	if err != nil {
		return fail(ErrExistingUnavailable)
	}
	if attempt.native == nil {
		return fail(ErrExistingUnavailable)
	}
	waitErr := existingGuard(func() error { return attempt.native.WaitConnected(op) })
	if waitErr == errExistingPanic {
		attempt.poisoned = true
	}
	if waitErr != nil || op.Err() != nil {
		return fail(ErrExistingVerification)
	}
	observation, err := a.observe(op, attempt)
	if err != nil {
		return fail(err)
	}
	return observation, nil
}
func (a *ExistingServiceAdapter) observe(ctx context.Context, attempt *existingAttempt) (ExistingServiceObservation, error) {
	var out ServiceInspection
	err := existingGuard(func() error {
		var e error
		out, e = a.ops.observe(ctx, attempt.native, attempt.selected.ServiceID)
		return e
	})
	if err == errExistingPanic {
		attempt.poisoned = true
	}
	if err != nil || ctx.Err() != nil || out.Status != Connected || out.Generation == nil || !sameDiagnosticConfig(attempt.selected, out.Configuration) {
		return ExistingServiceObservation{}, ErrExistingVerification
	}
	g := out.Generation
	if !validExistingGeneration(*g, attempt.selected.ServiceID) {
		return ExistingServiceObservation{}, ErrExistingVerification
	}
	if attempt.generation != nil && !sameGeneration(*attempt.generation, *g) {
		return ExistingServiceObservation{}, ErrExistingVerification
	}
	snapshot := cloneGeneration(*g)
	attempt.generation = &snapshot
	return ExistingServiceObservation{SystemConnected: true, Generation: cloneGeneration(snapshot)}, nil
}
func (a *ExistingServiceAdapter) Check(ctx context.Context) (ExistingServiceObservation, error) {
	if err := a.acquire(ctx); err != nil {
		return ExistingServiceObservation{}, err
	}
	defer a.unlock()
	a.mu.Lock()
	if a.stopping != 0 {
		a.mu.Unlock()
		return ExistingServiceObservation{}, ErrBusy
	}
	op, cancel := context.WithTimeout(ctx, 10*time.Second)
	a.cancel = cancel
	a.mu.Unlock()
	defer func() { cancel(); a.mu.Lock(); a.cancel = nil; a.mu.Unlock() }()
	if a.current == nil || a.current.generation == nil || a.current.released {
		return ExistingServiceObservation{}, ErrExistingVerification
	}
	result, err := a.observe(op, a.current)
	if err == nil {
		return result, nil
	}
	cleanup, cancelCleanup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelCleanup()
	if _, stopErr := a.cleanup(cleanup); stopErr != nil {
		return ExistingServiceObservation{}, ErrCleanup
	}
	return ExistingServiceObservation{}, err
}
func (a *ExistingServiceAdapter) Stop(ctx context.Context) (ExistingServiceStopObservation, error) {
	if a == nil || ctx == nil {
		return ExistingServiceStopObservation{}, ErrCleanup
	}
	a.mu.Lock()
	a.stopping++
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.stopping--; a.mu.Unlock() }()
	if a.acquire(ctx) != nil {
		return ExistingServiceStopObservation{}, ErrCleanup
	}
	defer a.unlock()
	return a.cleanup(ctx)
}
func (a *ExistingServiceAdapter) cleanup(ctx context.Context) (ExistingServiceStopObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var zero ExistingServiceStopObservation
	attempt := a.current
	if attempt == nil {
		return zero, nil
	}
	if ctx.Err() != nil {
		return zero, ErrCleanup
	}
	attempt.generation = nil
	if attempt.poisoned {
		return zero, ErrCleanup
	}
	if !attempt.startEntered || (attempt.returnKnown && attempt.startFailed && attempt.native == nil) {
		a.current = nil
		return zero, nil
	}
	if !attempt.returnKnown || attempt.native == nil {
		return zero, ErrCleanup
	}
	if !attempt.released {
		stopErr := existingGuard(func() error { return attempt.native.Stop(ctx) })
		if stopErr == errExistingPanic {
			attempt.poisoned = true
		}
		if stopErr != nil {
			return zero, ErrCleanup
		}
		attempt.released = true
		if ctx.Err() != nil {
			return zero, ErrCleanup
		}
	}
	// The service read is independent after reference release. A surviving/shared
	// connection is never force-disconnected. A failed read retains quarantine.
	after, err := a.inspect(ctx, attempt.selected.ServiceID)
	if err != nil || ctx.Err() != nil || after.Status != Disconnected || after.Generation != nil {
		return zero, ErrCleanup
	}
	a.current = nil
	return ExistingServiceStopObservation{InterestReleased: true, ServiceDisconnected: true}, nil
}
