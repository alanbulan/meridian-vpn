//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"mygo-vpn/internal/packetrelay"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const offerNonce = "0123456789abcdef0123456789abcdef"
const offerRecord = `{"version":2,"event":"offer","session":"0123456789abcdef0123456789abcdef","addresses":["10.70.0.2/24"],"routes":["10.80.0.0/16"],"dns":["10.80.0.53"],"endpoint":"198.51.100.5"}`
const offerClosed = `{"version":2,"event":"relay-closed","session":"0123456789abcdef0123456789abcdef"}`

func TestUniVPNOfferStrictRecord(t *testing.T) {
	o, terminal, err := decodeUniVPNOffer([]byte(offerRecord), offerNonce)
	if err != nil || terminal || o.Session != offerNonce {
		t.Fatal(o, terminal, err)
	}
	invalid := []string{
		strings.Replace(offerRecord, `"version":2`, `"version":1`, 1),
		strings.Replace(offerRecord, `"version":2`, `"version":2,"version":2`, 1),
		strings.Replace(offerRecord, `"routes":["10.80.0.0/16"]`, `"routes":null`, 1),
		strings.Replace(offerRecord, `"routes":["10.80.0.0/16"]`, `"routes":["0.0.0.0/0"]`, 1),
		strings.Replace(offerRecord, `"routes":["10.80.0.0/16"]`, `"routes":["10.80.0.1/16"]`, 1),
		strings.Replace(offerRecord, `"dns":["10.80.0.53"]`, `"dns":["10.80.0.53","10.80.0.53"]`, 1),
		strings.Replace(offerRecord, `"endpoint":"198.51.100.5"`, `"endpoint":"::1"`, 1),
		strings.Replace(offerRecord, `"endpoint":"198.51.100.5"`, `"endpoint":"198.51.100.5","interface":"tun0"`, 1),
		strings.Replace(offerClosed, `"version"`, `"Version"`, 1), offerRecord + `{}`,
	}
	for _, v := range invalid {
		if _, _, err := decodeUniVPNOffer([]byte(v), offerNonce); err == nil {
			t.Errorf("accepted %s", v)
		}
	}
	if _, _, err := decodeUniVPNOffer([]byte(offerRecord), strings.Repeat("a", 32)); err == nil {
		t.Fatal("accepted wrong session")
	}
}
func TestUniVPNOfferChannelLifecycle(t *testing.T) {
	for _, tt := range []struct {
		name, data string
		bad        bool
	}{
		{"complete", offerRecord + "\n" + offerClosed + "\n", false},
		{"auth-failure", offerClosed + "\n", false},
		{"missing-terminal", offerRecord + "\n", true},
		{"duplicate-offer", offerRecord + "\n" + offerRecord + "\n", true},
		{"after-terminal", offerClosed + "\n" + offerRecord + "\n", true},
		{"truncated", offerRecord, true}, {"oversize", strings.Repeat(" ", 32769) + "\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newUniVPNOfferChannel()
			failed := false
			s.read(strings.NewReader(tt.data), offerNonce, func() { failed = true })
			_ = failed
			if (s.err != nil) != tt.bad {
				t.Fatal("failure", failed)
			}
			select {
			case <-s.ready:
			default:
				t.Fatal("ready waiter blocked")
			}
			select {
			case <-s.done:
			default:
				t.Fatal("done waiter blocked")
			}
		})
	}
}

type offerTestPackets struct {
	closed   chan struct{}
	once     sync.Once
	closeErr error
	readErr  error
}

func newOfferPackets() *offerTestPackets { return &offerTestPackets{closed: make(chan struct{})} }
func (p *offerTestPackets) ReadPacket([]byte) (int, error) {
	if p.readErr != nil {
		return 0, p.readErr
	}
	<-p.closed
	return 0, io.EOF
}
func (p *offerTestPackets) WritePacket(b []byte) (int, error) { return len(b), nil }
func (p *offerTestPackets) Close() error                      { p.once.Do(func() { close(p.closed) }); return p.closeErr }

type offerTestSource struct {
	o                      UniVPNOffer
	child                  packetrelay.PacketIO
	err, proofErr, liveErr error
}

func (s *offerTestSource) WaitOffer(context.Context, UniVPNNativeProcess) (UniVPNOffer, packetrelay.PacketIO, error) {
	return cloneUniVPNOffer(s.o), s.child, s.err
}
func (s *offerTestSource) ProveClosed(context.Context, UniVPNNativeProcess) error { return s.proofErr }

func (s *offerTestSource) CheckLive(context.Context, UniVPNNativeProcess) error { return s.liveErr }

type offerTestLease struct {
	c        UniVPNNetworkConfig
	host     *offerTestPackets
	releases int
	err      error
}

func (l *offerTestLease) Identity() UniVPNNetworkConfig { return l.c }
func (l *offerTestLease) Packets() packetrelay.PacketIO { return l.host }
func (l *offerTestLease) Release(context.Context) error {
	l.releases++
	return errors.Join(l.host.Close(), l.err)
}

type offerTestProvider struct {
	lease UniVPNHostLease
	calls int
	err   error
}

func (p *offerTestProvider) Acquire(context.Context, UniVPNNativeProcess, string) (UniVPNHostLease, error) {
	p.calls++
	return p.lease, p.err
}
func offerFixture(t *testing.T) (*UniVPNOfferController, *offerTestSource, *offerTestProvider, *networkTestOps, *networkTestProcess) {
	n, s, ops, p := networkFixture(t)
	c := s.c
	c.Alias = "meridian-" + offerNonce
	ops.state.Alias = c.Alias
	source := &offerTestSource{o: UniVPNOffer{offerNonce, c.Addresses, c.Routes, c.DNS, c.Endpoint}, child: newOfferPackets()}
	provider := &offerTestProvider{lease: &offerTestLease{c: c, host: newOfferPackets()}}
	packets := packetrelay.Config{AssignedIPv4: c.Addresses[0].Addr(), RemotePrefixes: c.Routes, Resolvers: c.DNS, AllowTCP: true, AllowUDP: true, MaxPacketSize: 1500}
	controller, err := NewUniVPNOfferController(source, provider, ops, n.policy, packets)
	if err != nil {
		t.Fatal(err)
	}
	return controller, source, provider, ops, p
}
func TestUniVPNOfferControllerReadyCleanup(t *testing.T) {
	n, _, provider, ops, p := offerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := n.WaitReady(ctx, p); err != nil {
		t.Fatal(err)
	}
	cancel() // startup verification context must not terminate a live relay.
	select {
	case <-n.relayDone:
		t.Fatal("startup cancellation stopped live relay")
	default:
	}
	if err := n.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if ops.state.Exists || ops.escape || provider.lease.(*offerTestLease).releases != 1 {
		t.Fatal("resources remain")
	}
	if err := n.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}
func TestUniVPNOfferRejectBeforeAcquire(t *testing.T) {
	for _, mode := range []string{"route", "endpoint", "address", "dns", "nonce", "packet-policy"} {
		t.Run(mode, func(t *testing.T) {
			n, s, provider, ops, p := offerFixture(t)
			switch mode {
			case "route":
				s.o.Routes = []netip.Prefix{netip.MustParsePrefix("10.80.1.0/24")}
			case "endpoint":
				s.o.Endpoint = netip.MustParseAddr("198.51.100.6")
			case "address":
				s.o.Addresses[0] = netip.MustParsePrefix("10.70.0.3/24")
			case "dns":
				s.o.DNS = nil
			case "nonce":
				s.o.Session = "bad"
			case "packet-policy":
				n.packetConfig.RemotePrefixes = []netip.Prefix{netip.MustParsePrefix("10.90.0.0/16")}
			}
			if err := n.WaitReady(context.Background(), p); err == nil {
				t.Fatal("accepted unapproved offer")
			}
			if provider.calls != 0 || len(ops.calls) != 0 {
				t.Fatal("mutated before validation")
			}
			if err := n.Cleanup(context.Background(), p); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestUniVPNOfferFailureCleanup(t *testing.T) {
	for _, mode := range []string{"partial-acquire", "identity", "network", "relay-close", "proof", "release"} {
		t.Run(mode, func(t *testing.T) {
			n, s, provider, ops, p := offerFixture(t)
			lease := provider.lease.(*offerTestLease)
			switch mode {
			case "partial-acquire":
				provider.err = errors.New("partial")
			case "identity":
				lease.c.Alias = "wrong"
			case "network":
				ops.fail = "route"
			case "relay-close":
				lease.host.closeErr = errors.New("close")
			case "proof":
				s.proofErr = errors.New("containment")
			case "release":
				lease.err = errors.New("release")
			}
			err := n.WaitReady(context.Background(), p)
			if mode == "partial-acquire" || mode == "identity" || mode == "network" {
				if err == nil {
					t.Fatal("unexpected ready")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			cleanup := n.Cleanup(context.Background(), p)
			wantFail := mode == "relay-close" || mode == "proof" || mode == "release"
			if (cleanup != nil) != wantFail {
				t.Fatal("cleanup", cleanup)
			}
			if wantFail {
				if err := n.WaitReady(context.Background(), p); err == nil {
					t.Fatal("quarantine lost")
				}
			}
			if mode == "proof" && lease.releases != 0 {
				t.Fatal("released before containment proof")
			}
		})
	}
}
func TestUniVPNOfferMissingProvider(t *testing.T) {
	n, _, _, ops, _ := offerFixture(t)
	if _, err := NewUniVPNOfferController(&offerTestSource{}, nil, ops, n.network.policy, n.packetConfig); err == nil {
		t.Fatal("missing provider accepted")
	}
}

func TestUniVPNOfferSourceUncertaintyQuarantines(t *testing.T) {
	n, s, provider, _, p := offerFixture(t)
	s.err = &CleanupError{}
	if n.WaitReady(context.Background(), p) == nil {
		t.Fatal("source error lost")
	}
	if provider.calls != 0 {
		t.Fatal("lease acquired")
	}
	if n.Cleanup(context.Background(), p) == nil {
		t.Fatal("uncertainty cleared")
	}
}
func TestUniVPNOfferFinalLivenessCheck(t *testing.T) {
	n, s, _, _, p := offerFixture(t)
	s.liveErr = errors.New("native exited during readback")
	if n.WaitReady(context.Background(), p) == nil {
		t.Fatal("false readiness")
	}
	if err := n.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func TestUniVPNNativeOfferSourceIdentityAndSingleClaim(t *testing.T) {
	o, _, err := decodeUniVPNOffer([]byte(offerRecord), offerNonce)
	if err != nil {
		t.Fatal(err)
	}
	channel := newUniVPNOfferChannel()
	channel.offer = o
	close(channel.ready)
	packet := newOfferPackets()
	p := &uniVPNExecProcess{offer: channel, packet: packet, sessionID: offerNonce, exited: make(chan struct{}), contained: make(chan struct{})}
	source := UniVPNNativeOfferSource{}
	if _, _, err := source.WaitOffer(context.Background(), &networkTestProcess{}); err == nil {
		t.Fatal("foreign process accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := source.WaitOffer(ctx, p); err == nil {
		t.Fatal("canceled claim accepted")
	}
	var wg sync.WaitGroup
	results := make(chan packetrelay.PacketIO, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, endpoint, _ := source.WaitOffer(context.Background(), p)
			results <- endpoint
		}()
	}
	wg.Wait()
	close(results)
	claims := 0
	for endpoint := range results {
		if endpoint != nil {
			claims++
			endpoint.Close()
		}
	}
	if claims != 1 {
		t.Fatalf("claims %d", claims)
	}
	if err := source.CheckLive(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	channel.mu.Lock()
	channel.terminal = true
	channel.mu.Unlock()
	if err := source.CheckLive(context.Background(), p); err == nil {
		t.Fatal("terminal is live")
	}
	close(channel.done)
	close(p.contained)
	if err := source.ProveClosed(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.launchCleanupErr = &CleanupError{}
	if err := source.ProveClosed(context.Background(), p); err == nil {
		t.Fatal("launch uncertainty ignored")
	}
}

func TestUniVPNNativeOfferClaimSurvivesWait(t *testing.T) {
	o, _, _ := decodeUniVPNOffer([]byte(offerRecord), offerNonce)
	channel := newUniVPNOfferChannel()
	channel.offer = o
	close(channel.ready)
	packet := newOfferPackets()
	p := &uniVPNExecProcess{cmd: &exec.Cmd{}, isolation: &transportIsolation{}, offer: channel, packet: packet, sessionID: offerNonce, exited: make(chan struct{}), contained: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	_, owned, err := (UniVPNNativeOfferSource{}).WaitOffer(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	channel.mu.Lock()
	channel.terminal = true
	channel.mu.Unlock()
	close(channel.done)
	_ = p.Wait() // unstarted mock Cmd only; never launches a process
	select {
	case <-packet.closed:
		t.Fatal("Wait closed transferred packet endpoint")
	default:
	}
	if err := (UniVPNNativeOfferSource{}).CheckLive(context.Background(), p); err == nil {
		t.Fatal("exited process live")
	}
	owned.Close()
}
func TestUniVPNOfferWrongProcessCleanupPreservesLease(t *testing.T) {
	n, _, provider, ops, p := offerFixture(t)
	if err := n.WaitReady(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	calls := len(ops.calls)
	if err := n.Cleanup(context.Background(), &networkTestProcess{2}); err == nil {
		t.Fatal("wrong process cleaned")
	}
	if len(ops.calls) != calls || provider.lease.(*offerTestLease).releases != 0 {
		t.Fatal("foreign cleanup mutated resources")
	}
	if err := n.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}
func TestUniVPNOfferReplacementRefusesCleanup(t *testing.T) {
	n, _, provider, ops, p := offerFixture(t)
	if err := n.WaitReady(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	ops.state.Alias = "replacement-owned-by-someone-else"
	provider.lease.(*offerTestLease).err = errors.New("replacement ownership; release refuses mutation")
	if err := n.Cleanup(context.Background(), p); err == nil {
		t.Fatal("replacement uncertainty lost")
	}
	if !ops.state.Exists || ops.state.Alias != "replacement-owned-by-someone-else" {
		t.Fatal("replacement deleted")
	}
}

type offerAcquireFunc func(context.Context, UniVPNNativeProcess, string) (UniVPNHostLease, error)

func (f offerAcquireFunc) Acquire(ctx context.Context, p UniVPNNativeProcess, s string) (UniVPNHostLease, error) {
	return f(ctx, p, s)
}
func TestUniVPNOfferCancelDuringAcquire(t *testing.T) {
	n, _, provider, ops, p := offerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.leases = offerAcquireFunc(func(context.Context, UniVPNNativeProcess, string) (UniVPNHostLease, error) {
		cancel()
		return provider.lease, ctx.Err()
	})
	if err := n.WaitReady(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(ops.calls) != 0 {
		t.Fatal("network mutation after canceled acquisition")
	}
	if err := n.Cleanup(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if provider.lease.(*offerTestLease).releases != 1 {
		t.Fatal("partial lease leaked")
	}
}
