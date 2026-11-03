//go:build linux

package core

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"mygo-vpn/internal/packetrelay"
)

// UniVPNHostLease is an exclusive broker-owned fresh TUN lease. Identity must be
// kernel-attested, contain no gateway-supplied ownership, and use the requested
// session alias. Packets never passes to the child. Release must roll back even
// partial acquisition and prove all lease handles/state absent, idempotently.
// Release must revalidate ownership and refuse destructive operations on any
// replacement or uncertain resource, even when preceding network cleanup failed.
// It also closes the host PacketIO if setup failed before Run took ownership.
// Providers must exclude concurrent link/route/resolver writers for the lifetime
// of the lease. A name/index/alias lookup alone is NOT an exclusive lease.
type UniVPNHostLease interface {
	Identity() UniVPNNetworkConfig
	Packets() packetrelay.PacketIO
	Release(context.Context) error
}

// Acquire must enforce that the process has verified whole-tree containment
// before creating anything. On any partial failure it must return the lease for
// rollback, or a CleanupError if absence cannot be established. No production
// provider is supplied here; missing providers must keep the backend disabled.
type UniVPNHostLeaseProvider interface {
	Acquire(context.Context, UniVPNNativeProcess, string) (UniVPNHostLease, error)
}

type UniVPNOfferController struct {
	mu           sync.Mutex
	source       UniVPNOfferSource
	leases       UniVPNHostLeaseProvider
	network      *UniVPNLinuxNetworkController
	adapter      *uniVPNLeaseSource
	packetConfig packetrelay.Config
	process      UniVPNNativeProcess
	lease        UniVPNHostLease
	child        packetrelay.PacketIO
	cancel       context.CancelFunc
	relayDone    chan struct{}
	relayErr     error
	poisoned     bool
}
type uniVPNLeaseSource struct {
	config UniVPNNetworkConfig
	source UniVPNOfferSource
}

func (s *uniVPNLeaseSource) WaitNetworkConfig(context.Context, UniVPNNativeProcess) (UniVPNNetworkConfig, error) {
	return cloneUniVPNNativeConfig(s.config), nil
}
func (s *uniVPNLeaseSource) ProveNetworkGone(ctx context.Context, p UniVPNNativeProcess) error {
	return s.source.ProveClosed(ctx, p)
}

// Packet policy is separate administrator input, copied and checked against the
// approved offer. Gateway metadata cannot expand packet permissions.
func NewUniVPNOfferController(source UniVPNOfferSource, leases UniVPNHostLeaseProvider, ops UniVPNNetworkOps, networkPolicy UniVPNNetworkPolicy, packets packetrelay.Config) (*UniVPNOfferController, error) {
	if nilInterface(source) || nilInterface(leases) {
		return nil, errors.New("trusted offer source and exclusive host lease provider required")
	}
	if _, err := packetrelay.NewPolicy(packets); err != nil {
		return nil, err
	}
	packets.RemotePrefixes = append(packets.RemotePrefixes[:0:0], packets.RemotePrefixes...)
	packets.Resolvers = append(packets.Resolvers[:0:0], packets.Resolvers...)
	a := &uniVPNLeaseSource{source: source}
	n, err := NewUniVPNLinuxNetworkController(a, ops, networkPolicy)
	if err != nil {
		return nil, err
	}
	return &UniVPNOfferController{source: source, leases: leases, network: n, adapter: a, packetConfig: packets}, nil
}
func (n *UniVPNOfferController) WaitReady(ctx context.Context, p UniVPNNativeProcess) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.process != nil || n.poisoned {
		return errors.New("offer controller busy or quarantined")
	}
	if nilInterface(p) || !reflect.TypeOf(p).Comparable() {
		return errors.New("invalid process identity")
	}
	n.process = p
	o, child, err := n.source.WaitOffer(ctx, p)
	n.child = child
	if err != nil {
		var ce *CleanupError
		if errors.As(err, &ce) {
			n.poisoned = true
		}
		return err
	}
	// Validate metadata before acquiring any host resources. This synthetic name
	// is only a validation placeholder and is never used for network operations.
	c := UniVPNNetworkConfig{Interface: "offercheck", Index: 1, Alias: "meridian-" + o.Session, Addresses: o.Addresses, Routes: o.Routes, DNS: o.DNS, Endpoint: o.Endpoint}
	if len(o.Session) != 32 {
		return errors.New("invalid session nonce")
	}
	for _, v := range o.Session {
		if !(v >= '0' && v <= '9' || v >= 'a' && v <= 'f') {
			return errors.New("invalid session nonce")
		}
	}
	if err = n.network.validate(c); err != nil {
		return err
	}
	if len(c.Addresses) != 1 || c.Addresses[0].Addr() != n.packetConfig.AssignedIPv4 || !sameUniVPNSet(c.Routes, n.packetConfig.RemotePrefixes) || !sameUniVPNSet(c.DNS, n.packetConfig.Resolvers) || nilInterface(child) {
		return errors.New("offer does not match administrator packet policy")
	}
	policy, err := packetrelay.NewPolicy(n.packetConfig)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	n.lease, err = n.leases.Acquire(ctx, p, c.Alias)
	if err != nil {
		var ce *CleanupError
		if errors.As(err, &ce) {
			n.poisoned = true
		}
		return err
	}
	if nilInterface(n.lease) {
		n.poisoned = true
		return &CleanupError{}
	}
	identity := n.lease.Identity()
	if identity.Alias != c.Alias || !safeUniVPNLink(identity.Interface) || identity.Index <= 0 {
		return errors.New("host lease identity mismatch")
	}
	c.Interface = identity.Interface
	c.Index = identity.Index
	host := n.lease.Packets()
	if nilInterface(host) || !reflect.TypeOf(host).Comparable() || !reflect.TypeOf(child).Comparable() || host == child {
		return errors.New("invalid exclusive relay endpoints")
	}
	n.adapter.config = cloneUniVPNNativeConfig(c)
	if err = n.network.WaitReady(ctx, p); err != nil {
		return err
	}
	run, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	n.relayDone = make(chan struct{})
	h := &uniVPNReadyPackets{PacketIO: host, ready: make(chan struct{})}
	d := &uniVPNReadyPackets{PacketIO: child, ready: make(chan struct{})}
	n.child = nil // Run now owns both endpoints, including failure cleanup.
	go func() { _, err := packetrelay.Run(run, policy, h, d); n.relayErr = err; close(n.relayDone); p.Stop() }()
	for _, ready := range []<-chan struct{}{h.ready, d.ready} {
		select {
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		case <-n.relayDone:
			return errors.New("packet relay stopped before readiness")
		case <-ready:
		}
	}
	select {
	case <-n.relayDone:
		return errors.New("packet relay stopped before readiness")
	default:
	}
	if err := n.source.CheckLive(ctx, p); err != nil {
		cancel()
		return err
	}
	return ctx.Err()
}

type uniVPNReadyPackets struct {
	packetrelay.PacketIO
	once  sync.Once
	ready chan struct{}
}

func (p *uniVPNReadyPackets) ReadPacket(b []byte) (int, error) {
	p.once.Do(func() { close(p.ready) })
	return p.PacketIO.ReadPacket(b)
}

func (n *UniVPNOfferController) Cleanup(ctx context.Context, p UniVPNNativeProcess) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.process == nil {
		if n.poisoned {
			return &CleanupError{}
		}
		return nil
	}
	if nilInterface(p) || !reflect.TypeOf(p).Comparable() || n.process != p {
		return &CleanupError{}
	}
	var errs []error
	if n.cancel != nil {
		n.cancel()
		select {
		case <-ctx.Done():
			n.poisoned = true
			return &CleanupError{}
		case <-n.relayDone:
		}
		if errors.Is(n.relayErr, packetrelay.ErrCleanup) {
			errs = append(errs, n.relayErr)
		}
	}
	if !nilInterface(n.child) {
		if err := n.child.Close(); err != nil {
			errs = append(errs, err)
		}
		n.child = nil
	}
	// The broker calls cleanup only after native Wait/containment. Enforce that
	// prerequisite before mutating host state, even for direct controller callers.
	if err := n.source.ProveClosed(ctx, p); err != nil {
		n.poisoned = true
		return &CleanupError{}
	}
	if n.network.process != nil {
		if err := n.network.Cleanup(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	if !nilInterface(n.lease) {
		if err := n.lease.Release(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 || n.poisoned || ctx.Err() != nil {
		n.poisoned = true
		return &CleanupError{}
	}
	n.process = nil
	n.lease = nil
	n.cancel = nil
	n.relayDone = nil
	n.relayErr = nil
	return nil
}
