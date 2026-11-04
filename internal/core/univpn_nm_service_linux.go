//go:build linux

package core

import (
	"context"
	"sync/atomic"

	"mygo-vpn/internal/nmvpn"
)

// UniVPNNMServiceHosts is independent trusted host provisioning for the service.
// Preflight must verify that actual host/resource authority and applied/global
// policy inspection are available, without acquiring networking or launching a
// worker. Authorize receives the ORIGINAL manager-correlated receipt and Connect;
// it must independently correlate them and return retained resource authority.
// A matching name, projection, no-op callback or caller-created Binding is not an
// implementation. Non-nil partial bindings transfer ownership even on error.
// There is intentionally no production implementation or default provider yet.
type UniVPNNMServiceHosts interface {
	Preflight(context.Context) error
	Authorize(context.Context, *nmvpn.ActivationReceipt, *nmvpn.Activation) (UniVPNNMHostBinding, error)
}

// UniVPNNMServiceNative contains administrator-selected native launch inputs.
// No field is loaded from the NM profile, command-line environment or gateway.
// Constructor snapshots mutable launch policy; providers must remain trusted and
// independently enforce their existing ownership/containment contracts.
type UniVPNNMServiceNative struct {
	Launcher *UniVPNExecLauncher
	Executable string
	Arguments []string
	Hosts UniVPNNMServiceHosts
}

// NewUniVPNNMService is the concrete service-composition entry. It wires the
// existing pinned native launcher/offer source into nmvpn's actual plugin,
// manager, peer and publication controller. Caller-supplied Factory is rejected.
// There is no alternative mock/process-provider injection on this path.
//
// Missing host authority or independent global policy fails before any activation.
// No system bus is discovered, service installed, TUN created, core.Session made
// Ready, or restart journal cleared by construction. Production deployment remains
// blocked until the independent authority implementations and acceptance exist.
func NewUniVPNNMService(c nmvpn.ServiceConfig, native UniVPNNMServiceNative) (*nmvpn.Service, error) {
	if !nilInterface(c.Factory) || nilInterface(c.GlobalPolicy) || nilInterface(native.Hosts) {
		return nil, errUniVPNNM
	}
	launcher, args, err := snapshotUniVPNNMLaunch(native.Launcher, native.Executable, native.Arguments, c.Plan.Username)
	if err != nil {
		return nil, errUniVPNNM
	}
	// Launch itself also requires rollback. Reject its absence before NM has
	// created an activation rather than only when credentials reach Launch.
	if _, ok := launcher.Isolation.(UniVPNLaunchRollback); !ok {
		return nil, errUniVPNNM
	}
	c.Factory = &uniVPNNMServiceFactory{launcher: launcher, executable: native.Executable, args: args, hosts: native.Hosts, policy: cloneUniVPNNMPolicy(c.Allowlist)}
	return nmvpn.NewService(c)
}

func cloneUniVPNNMPolicy(p nmvpn.Policy) nmvpn.Policy {
	return nmvpn.Policy{Addresses: append(p.Addresses[:0:0], p.Addresses...), Endpoints: append(p.Endpoints[:0:0], p.Endpoints...), Routes: append(p.Routes[:0:0], p.Routes...)}
}

type uniVPNNMServiceFactory struct {
	claimed atomic.Bool
	launcher *UniVPNExecLauncher
	executable string
	args []string
	hosts UniVPNNMServiceHosts
	policy nmvpn.Policy
}

func (f *uniVPNNMServiceFactory) Preflight(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || nilInterface(f.hosts) || f.launcher == nil || f.hosts.Preflight(ctx) != nil || ctx.Err() != nil {
		return errUniVPNNM
	}
	// Read existing trusted executable bytes only. The concrete launcher repeats
	// its own check immediately before launch; this is not an inode execution pin
	// or proof that privileged replacement is impossible. No file is executed here.
	if verifyUniVPNExecutable(f.executable, f.launcher.ExecutableSHA256) != nil || ctx.Err() != nil {
		return errUniVPNNM
	}
	return nil
}

func (f *uniVPNNMServiceFactory) Start(ctx context.Context, receipt *nmvpn.ActivationReceipt, activation *nmvpn.Activation) (nmvpn.ServiceBackend, error) {
	if ctx == nil || ctx.Err() != nil || receipt == nil || activation == nil || !f.claimed.CompareAndSwap(false, true) {
		return nil, errUniVPNNM
	}
	// Non-owning retained proof rejects a foreign/unbound receipt without
	// making an NM call or manufacturing a host binding.
	if _, err := receipt.RetainedCorrelation(ctx, activation); err != nil {
		return nil, errUniVPNNM
	}
	hosts := &uniVPNNMServiceAuthority{hosts: f.hosts, receipt: receipt, activation: activation}
	broker, err := StartUniVPNNMBroker(ctx, activation, f.launcher, f.executable, f.args, f.policy, hosts)
	if broker == nil {
		return nil, err
	}
	return broker, err // retain the concrete owner's partial acquisition on error
}

type uniVPNNMServiceAuthority struct {
	hosts UniVPNNMServiceHosts
	receipt *nmvpn.ActivationReceipt
	activation *nmvpn.Activation
}

func (h *uniVPNNMServiceAuthority) Authorize(ctx context.Context, activation *nmvpn.Activation) (UniVPNNMHostBinding, error) {
	if activation != h.activation {
		return nil, errUniVPNNM
	}
	return h.hosts.Authorize(ctx, h.receipt, activation)
}

var _ nmvpn.ServiceFactory = (*uniVPNNMServiceFactory)(nil)
var _ nmvpn.ServiceBackend = (*UniVPNNMBroker)(nil)
