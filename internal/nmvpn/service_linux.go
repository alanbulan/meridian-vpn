//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
)

// ServiceBackend is one retained native/host generation. A non-nil result from
// ServiceFactory.Start transfers local teardown responsibility even on error.
// Done closes on loss of that generation; it is not a host-absence certificate.
// Close must join retained local handles and retain uncertainty without retries.
type ServiceBackend interface {
	Broker
	PublicationVerifier
	Binding() Binding
	Offer() Offer
	Done() <-chan struct{}
	Close(context.Context) error
}

// ServiceFactory is trusted code, not profile input or a runtime plugin loader.
// Preflight must reject missing native containment and host-authority providers
// before NM activation. Start receives the original correlated manager receipt;
// it must independently establish host authority before using any credential.
// Both methods must honor context. Start may not discard partially owned handles.
type ServiceFactory interface {
	Preflight(context.Context) error
	Start(context.Context, *ActivationReceipt, *Activation) (ServiceBackend, error)
}

// ServicePolicy is a REQUIRED independent deployment-policy boundary. Preflight
// verifies approved host/global/dispatcher policy before manager mutations.
// CheckPublication checks its continued applicability immediately before EACH
// configuration signal. The allowlist Policy and NM's cached IPv4 projection are
// not implementations of this interface. No production implementation is supplied.
// CheckPublication runs inside the pinned bus lock: it must not call NM, Plugin,
// Activation, or another operation on that bus. All methods must honor context.
type ServicePolicy interface {
	Preflight(context.Context) error
	CheckPublication(context.Context, Binding, Offer) error
	// Done is a stable non-nil revocation channel for the service lifetime.
	// Close it on policy loss or unprovable applicability, including after
	// publication. It is not a promise of atomic exclusion of privileged changes.
	Done() <-chan struct{}
}

// ServiceConfig is trusted provisioning. Bus must already have independently
// verified endpoint provenance. Journals are exclusively held, distinct durable
// stores and remain owned/open by the caller until Run returns. No bus discovery,
// journal path lookup, executable selection or policy loading occurs here.
type ServiceConfig struct {
	Bus                *PinnedBus
	Plan               PluginPlan
	Network            map[string]map[string]dbus.Variant
	Allowlist          Policy
	ActivationJournal  ActivationJournal
	PublicationJournal Journal
	Boot               BootIdentity
	Factory            ServiceFactory
	GlobalPolicy       ServicePolicy
}

// ServiceResult deliberately has no Ready field. Published is only local signal
// delivery. NetworkAbsent requires Controller's independent NM AND host proof.
// ReconciliationRequired remains true after any manager transaction: activation
// intent is retained even after verified shutdown, never automatically cleared.
type ServiceResult struct {
	Published              bool
	LocalStopped           bool
	NetworkAbsent          bool
	ReconciliationRequired bool
}

// Service composes the actual pinned plugin, manager, broker, peer and controller.
// It is single-use and retains its backend after failure. It is not an installed
// system service or a production HostAuthority. Copying it confers no authority.
type Service struct {
	self    *Service
	claimed atomic.Bool
	config  ServiceConfig
	backend ServiceBackend
}

var errService = errors.New("NM service admission or lifecycle failed")
var errServiceCleanup = errors.New("NM service stopped with unresolved cleanup")

// NewService performs no D-Bus, host or journal operation. Missing host or global
// policy dependencies fail closed; there is no permissive default or fallback.
// On success Run takes ownership of Bus; on constructor failure the caller keeps it.
func NewService(c ServiceConfig) (*Service, error) {
	if c.Bus == nil || !validServiceAllowlist(c.Allowlist) || !validPluginPlan(c.Plan) || nilValue(c.ActivationJournal) || nilValue(c.PublicationJournal) || c.Boot == nil || nilValue(c.Factory) || nilValue(c.GlobalPolicy) || ValidateProfile(c.Network, Identity{UUID: c.Plan.UUID, Interface: c.Plan.Interface}) != nil {
		return nil, errService
	}
	c.Network = cloneSafeProfile(c.Network)
	c.Allowlist = copyServicePolicy(c.Allowlist)
	s := &Service{config: c}
	s.self = s
	return s, nil
}

func copyServicePolicy(p Policy) Policy {
	return Policy{Addresses: append([]netip.Prefix(nil), p.Addresses...), Endpoints: append([]netip.Addr(nil), p.Endpoints...), Routes: append([]netip.Prefix(nil), p.Routes...)}
}

// Run serves one activation, then joins shutdown. Startup has a 60-second
// cancellation bound; trusted callbacks must still honor their context. Caller cancellation during the
// steady state does not close the plugin bus until withdrawal has been attempted.
// Cancellation during an uncertain in-flight D-Bus call still invalidates it.
// A failed Publish already performs its one cleanup transaction; Run never replays
// that transaction. Pre-publication failures retain activation intent rather than
// invent an authority to deactivate a generation that was never fully bound.
func (s *Service) Run(ctx context.Context) (result ServiceResult, resultErr error) {
	if s == nil || s.self != s || ctx == nil || !s.claimed.CompareAndSwap(false, true) {
		return result, errService
	}
	ctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	finishStartup := serviceStartupDeadline(60*time.Second, cancelRun)
	defer finishStartup()
	c := s.config
	defer c.Bus.Close()
	if ctx.Err() != nil {
		return result, errService
	}
	// No incoming ABI or manager mutation exists before both deployment gates
	// and both durable restart barriers have succeeded.
	if c.Factory.Preflight(ctx) != nil || c.GlobalPolicy.Preflight(ctx) != nil || ctx.Err() != nil {
		return result, errService
	}
	policyDone := c.GlobalPolicy.Done()
	if serviceGenerationEnded(policyDone) {
		return result, errService
	}
	// Join this sole watcher on every return. Revocation cancels forward work,
	// including a pending Receive, but never the fresh cleanup contexts.
	watchDone, stopWatch := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-policyDone:
			cancelRun()
		case <-stopWatch:
		}
	}()
	defer func() { close(stopWatch); <-watchDone }()
	oldActivation, aerr := c.ActivationJournal.LoadActivation()
	oldPublication, perr := c.PublicationJournal.Load()
	if aerr != nil || perr != nil || oldActivation != nil || oldPublication != nil {
		result.ReconciliationRequired = true
		return result, errService
	}
	if ctx.Err() != nil || serviceGenerationEnded(policyDone) {
		return result, errService
	}
	life, finish := context.WithCancel(context.WithoutCancel(ctx))
	defer finish()
	plugin, err := ServePlugin(life, c.Bus, c.Plan)
	if err != nil {
		return result, errService
	}
	defer plugin.Close()
	var manager *ActivationManager
	var activation *Activation
	var controller *Controller
	// Cleanup runs before closing the plugin. Never expose raw callback errors:
	// they may include credentials or environment details.
	defer func() {
		if result.Published {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if controller.Stop(cleanup) == nil {
				result.NetworkAbsent = true
			} else {
				resultErr = errServiceCleanup
			}
			cancel()
		}
		if !nilValue(s.backend) {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			result.LocalStopped = s.backend.Close(cleanup) == nil && cleanup.Err() == nil
			cancel()
			if !result.LocalStopped {
				result.NetworkAbsent = false
				resultErr = errServiceCleanup
			} else if activation != nil {
				cleanup, cancel = context.WithTimeout(context.Background(), 10*time.Second)
				// Outside Broker callbacks and therefore outside the bus lock.
				if activation.MarkStopped(cleanup) != nil {
					resultErr = errServiceCleanup
				}
				cancel()
			}
		}
		if manager != nil {
			manager.mu.Lock()
			if manager.started {
				result.ReconciliationRequired = true
				if manager.record.Version != 0 && manager.save("quarantine") != nil {
					resultErr = errServiceCleanup
				}
			}
			manager.mu.Unlock()
		}
	}()
	manager, err = NewActivationManager(ctx, c.Bus, plugin, c.ActivationJournal, c.Boot)
	if err != nil {
		result.ReconciliationRequired = true
		return result, errService
	}
	receipt, err := manager.Start(ctx, c.Network)
	if err != nil {
		return result, errService
	}
	activation, err = plugin.Receive(ctx)
	if err != nil {
		return result, errService
	}
	if _, err = receipt.Correlate(ctx, activation); err != nil {
		return result, errService
	}
	s.backend, err = c.Factory.Start(ctx, receipt, activation)
	if err != nil || nilValue(s.backend) || ctx.Err() != nil {
		return result, errService
	}
	binding, offer := s.backend.Binding(), copyOffer(s.backend.Offer())
	// This is an additional composition invariant, not a substitute for the
	// factory's independent host authority or the peer's provenance checks.
	if activation.VerifyBinding(binding, offer) != nil {
		return result, errService
	}
	done := s.backend.Done()
	if serviceGenerationEnded(done) {
		return result, errService
	}
	guard := &serviceBroker{ServiceBackend: s.backend, policy: c.GlobalPolicy, done: done, policyDone: policyDone}
	peer, err := NewDBusPeer(ctx, c.Bus, guard, binding, offer, c.Allowlist)
	if err != nil {
		return result, errService
	}
	controller, err = NewController(peer, c.PublicationJournal)
	if err != nil {
		return result, errService
	}
	if controller.Publish(ctx, binding.Identity, offer, c.Allowlist) != nil {
		return result, errService
	}
	result.Published = true
	if activation.MarkStarted(ctx) != nil {
		return result, errService
	}
	finishStartup()
	if ctx.Err() != nil {
		return result, errService
	}
	select {
	case <-ctx.Done():
		if serviceGenerationEnded(policyDone) {
			return result, errService
		}
		return result, nil
	case <-activation.Context().Done():
		return result, errService
	case <-done:
		return result, errService
	}
}

type serviceBroker struct {
	ServiceBackend
	policy     ServicePolicy
	done       <-chan struct{}
	policyDone <-chan struct{}
}

func (b *serviceBroker) VerifyPublish(ctx context.Context, binding Binding, offer Offer) error {
	if serviceGenerationEnded(b.done) || serviceGenerationEnded(b.policyDone) || b.ServiceBackend.VerifyPublish(ctx, binding, copyOffer(offer)) != nil || b.policy.CheckPublication(ctx, binding, copyOffer(offer)) != nil || ctx.Err() != nil || serviceGenerationEnded(b.done) || serviceGenerationEnded(b.policyDone) {
		return errService
	}
	if b.ServiceBackend.VerifyPublish(ctx, binding, copyOffer(offer)) != nil || ctx.Err() != nil || serviceGenerationEnded(b.done) || serviceGenerationEnded(b.policyDone) {
		return errService
	}
	return nil
}

func serviceGenerationEnded(done <-chan struct{}) bool {
	if done == nil {
		return true
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// Stop and join the startup timer without canceling a successful generation.
// A callback that wins the race cannot cancel a later operation after return.
func serviceStartupDeadline(delay time.Duration, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	timer := time.AfterFunc(delay, func() { cancel(); close(done) })
	var once sync.Once
	return func() {
		once.Do(func() {
			if !timer.Stop() {
				<-done
			}
		})
	}
}

func validServiceAllowlist(p Policy) bool {
	if len(p.Addresses) == 0 || len(p.Addresses) > 128 || len(p.Endpoints) == 0 || len(p.Endpoints) > 128 || len(p.Routes) > 128 {
		return false
	}
	addresses, endpoints, routes := map[netip.Prefix]bool{}, map[netip.Addr]bool{}, map[netip.Prefix]bool{}
	for _, address := range p.Addresses {
		if !address.IsValid() || address.Bits() < 1 || !validIP(address.Addr()) || addresses[address] {
			return false
		}
		addresses[address] = true
	}
	for _, endpoint := range p.Endpoints {
		if !validIP(endpoint) || endpoints[endpoint] {
			return false
		}
		endpoints[endpoint] = true
		for _, address := range p.Addresses {
			if address.Contains(endpoint) {
				return false
			}
		}
	}
	for _, route := range p.Routes {
		if !route.IsValid() || !route.Addr().Is4() || route.Bits() < 1 || route != route.Masked() || routes[route] {
			return false
		}
		routes[route] = true
		for _, endpoint := range p.Endpoints {
			if route.Contains(endpoint) {
				return false
			}
		}
	}
	return true
}
