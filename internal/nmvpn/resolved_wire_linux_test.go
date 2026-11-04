//go:build linux && nmvpnintegration

package nmvpn

// Every service and socket here belongs to the existing isolated private-daemon
// fixture. Kernel membership is injected privately; no host resolver, namespace,
// privileged interface operation or production bus is accessed by these tests.
import (
	"context"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"mygo-vpn/internal/packetrelay"

	"github.com/godbus/dbus/v5"
)

type resolvedWireManagerDNS struct {
	Index, Family int32
	Address       []byte
}
type resolvedWireManagerDNSEx struct {
	Index, Family int32
	Address       []byte
	Port          uint16
	Name          string
}
type resolvedWireLinkDNS struct {
	Family  int32
	Address []byte
}
type resolvedWireLinkDNSEx struct {
	Family  int32
	Address []byte
	Port    uint16
	Name    string
}
type resolvedWireManagerDomain struct {
	Index int32
	Name  string
	Route bool
}
type resolvedWireLinkDomain struct {
	Name  string
	Route bool
}
type resolvedWireDelegate struct {
	Name string
	Path dbus.ObjectPath
}

func resolvedWireProperties(manager bool, index int32) map[string]dbus.Variant {
	p := resolvedCommonFixture()
	if manager {
		p["DNS"] = dbus.MakeVariant([]resolvedWireManagerDNS{{0, 2, []byte{192, 0, 2, 53}}, {2, 2, []byte{10, 0, 0, 53}}})
		p["DNSEx"] = dbus.MakeVariant([]resolvedWireManagerDNSEx{{0, 2, []byte{192, 0, 2, 53}, 853, "dns.example"}, {2, 2, []byte{10, 0, 0, 53}, 0, ""}})
		p["FallbackDNS"] = dbus.MakeVariant([]resolvedWireManagerDNS{{0, 2, []byte{198, 51, 100, 53}}})
		p["FallbackDNSEx"] = dbus.MakeVariant([]resolvedWireManagerDNSEx{{0, 2, []byte{198, 51, 100, 53}, 0, ""}})
		p["Domains"] = dbus.MakeVariant([]resolvedWireManagerDomain{{0, "example", false}, {2, "corp.example", true}, {2, ".", true}})
		p["DNSStubListener"], p["ResolvConfMode"] = dbus.MakeVariant("yes"), dbus.MakeVariant("stub")
		p["LLMNRHostname"] = dbus.MakeVariant("test-host")
		p["CurrentDNSServer"] = dbus.MakeVariant(resolvedWireManagerDNS{0, 0, []byte{}})
		p["CurrentDNSServerEx"] = dbus.MakeVariant(resolvedWireManagerDNSEx{0, 0, []byte{}, 0, ""})
		p["TransactionStatistics"] = dbus.MakeVariant(struct{ A, B uint64 }{0, 42})
		p["CacheStatistics"] = dbus.MakeVariant(struct{ A, B, C uint64 }{0, 42, 7})
		p["DNSSECStatistics"] = dbus.MakeVariant(struct{ A, B, C, D uint64 }{})
	} else {
		p["DNS"] = dbus.MakeVariant([]resolvedWireLinkDNS{})
		p["DNSEx"] = dbus.MakeVariant([]resolvedWireLinkDNSEx{})
		p["Domains"] = dbus.MakeVariant([]resolvedWireLinkDomain{})
		if index == 2 {
			p["DNS"] = dbus.MakeVariant([]resolvedWireLinkDNS{{2, []byte{10, 0, 0, 53}}})
			p["DNSEx"] = dbus.MakeVariant([]resolvedWireLinkDNSEx{{2, []byte{10, 0, 0, 53}, 0, ""}})
			p["Domains"] = dbus.MakeVariant([]resolvedWireLinkDomain{{"corp.example", true}, {".", true}})
		}
		p["DefaultRoute"], p["ScopesMask"] = dbus.MakeVariant(index == 2), dbus.MakeVariant(uint64(0))
		p["CurrentDNSServer"] = dbus.MakeVariant(resolvedWireLinkDNS{0, []byte{}})
		p["CurrentDNSServerEx"] = dbus.MakeVariant(resolvedWireLinkDNSEx{0, []byte{}, 0, ""})
	}
	return p
}

type resolvedWireService struct {
	mu                                 sync.Mutex
	conn                               *dbus.Conn
	owner, caller                      string
	properties                         map[dbus.ObjectPath]map[string]dbus.Variant
	delegates                          []resolvedWireDelegate
	gets, introspects, getLinks, lists int
	bad                                bool
	missing, wrongPath                 int32
	changeAfterRead                    bool
	block, entered, handlerDone        chan struct{}
}

// Socket traffic does not synchronize Go memory. Publish fixture identities
// under the same mutex used by exported handlers, even during initial setup.
func (s *resolvedWireService) setIdentity(owner, caller string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.owner, s.caller = owner, caller
}

// The caller holds s.mu.
func (s *resolvedWireService) verify(m dbus.Message) {
	if m.Headers[dbus.FieldSender].Value() != s.caller || m.Headers[dbus.FieldDestination].Value() != s.owner || m.Flags&dbus.FlagNoAutoStart == 0 {
		s.bad = true
	}
}

func (s *resolvedWireService) Introspect(m dbus.Message) (string, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verify(m)
	s.introspects++
	path, _ := m.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	properties, ok := s.properties[path]
	if !ok {
		return "", &dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}
	}
	manager := path == resolvedPath
	iface := resolvedLinkInterface
	if manager {
		iface = resolvedManagerInterface
	}
	var out strings.Builder
	out.WriteString(resolvedIntrospectionPreamble + "<node><interface name=\"" + iface + "\">")
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		signature, known := resolvedPropertySchema(manager)[name]
		if !known {
			signature = "b"
		}
		out.WriteString("<property name=\"" + name + "\" type=\"" + signature + "\" access=\"read\"/>")
	}
	out.WriteString("</interface></node>")
	return out.String(), nil
}

func (s *resolvedWireService) Get(m dbus.Message, iface, name string) (dbus.Variant, *dbus.Error) {
	s.mu.Lock()
	s.verify(m)
	s.gets++
	path, _ := m.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	if path == resolvedPath && iface != resolvedManagerInterface || path != resolvedPath && iface != resolvedLinkInterface {
		s.bad = true
	}
	p, ok := s.properties[path]
	if !ok {
		s.mu.Unlock()
		return dbus.Variant{}, &dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}
	}
	value, ok := p[name]
	if !ok {
		s.mu.Unlock()
		return dbus.Variant{}, &dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownProperty"}
	}
	if s.changeAfterRead && path == resolvedPath && name == "LLMNR" {
		p["LLMNR"] = dbus.MakeVariant("yes")
	}
	block, entered, done := s.block, s.entered, s.handlerDone
	s.block = nil
	s.mu.Unlock()
	if block != nil {
		close(entered)
		<-block
		defer close(done)
	}
	return value, nil
}

func (s *resolvedWireService) GetLink(m dbus.Message, index int32) (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verify(m)
	s.getLinks++
	if index == s.missing {
		return "/", &dbus.Error{Name: "org.freedesktop.resolve1.NoSuchLink"}
	}
	if index == s.wrongPath {
		return resolvedLinkPath(index + 1), nil
	}
	path := resolvedLinkPath(index)
	if _, ok := s.properties[path]; !ok {
		return "/", &dbus.Error{Name: "org.freedesktop.resolve1.NoSuchLink"}
	}
	return path, nil
}

func (s *resolvedWireService) ListDelegates(m dbus.Message) ([]resolvedWireDelegate, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verify(m)
	s.lists++
	return append([]resolvedWireDelegate{}, s.delegates...), nil
}

func newResolvedWireFixture(t *testing.T) (*PinnedResolvedObserver, *resolvedWireService, context.Context) {
	t.Helper()
	socket := nmPrivateBus(t)
	service := &resolvedWireService{conn: nmWireConn(t, socket), properties: map[dbus.ObjectPath]map[string]dbus.Variant{resolvedPath: resolvedWireProperties(true, 0), resolvedLinkPath(1): resolvedWireProperties(false, 1), resolvedLinkPath(2): resolvedWireProperties(false, 2)}}
	for path := range service.properties {
		if err := service.conn.ExportMethodTable(map[string]any{"Get": service.Get}, path, propertiesInterface); err != nil {
			t.Fatal(err)
		}
		if err := service.conn.ExportMethodTable(map[string]any{"Introspect": service.Introspect}, path, resolvedIntrospectInterface); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.conn.ExportMethodTable(map[string]any{"GetLink": service.GetLink, "ListDelegates": service.ListDelegates}, resolvedPath, resolvedManagerInterface); err != nil {
		t.Fatal(err)
	}
	if reply, err := service.conn.RequestName(resolvedName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal("private resolved name unavailable", err)
	}
	owner := service.conn.Names()[0]
	service.setIdentity(owner, "")
	var id string
	if err := service.conn.BusObject().Call(resolvedBusName+".GetId", 0).Store(&id); err != nil {
		t.Fatal(err)
	}
	ctx := nmContext(t)
	observer, err := OpenPinnedResolvedObserver(ctx, nmRawConn(t, socket), BusPin{BusID: id, Owner: owner, BusUID: uint32(os.Getuid()), OwnerUID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	service.setIdentity(owner, observer.conn.Names()[0])
	t.Cleanup(func() {
		if err := observer.Close(); err != nil {
			t.Error(err)
		}
	})
	return observer, service, ctx
}

func resolvedWireObserve(ctx context.Context, b *PinnedResolvedObserver) (*ResolvedObservation, error) {
	ns := packetrelay.KernelNamespaceIdentity{Device: 1, Inode: 2}
	var snapshot ResolvedObservationSnapshot
	err := b.run(ctx, func(ctx context.Context) error {
		var err error
		snapshot, err = b.observeAllWith(ctx, ns, resolvedObservationOps{check: b.check, read: b.readResolved, kernel: func(context.Context, packetrelay.KernelNamespaceIdentity) (packetrelay.KernelLinkSetSnapshot, error) {
			return packetrelay.KernelLinkSetSnapshot{Namespace: ns, Links: []packetrelay.KernelLinkIdentity{{Index: 1, Name: "lo"}, {Index: 2, Name: "eth0"}}}, nil
		}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &ResolvedObservation{snapshot: &snapshot}, nil
}

func TestNMVPNWireResolvedPinnedReadback(t *testing.T) {
	b, s, ctx := newResolvedWireFixture(t)
	observation, err := resolvedWireObserve(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := observation.Snapshot()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || out.Owner != s.owner || len(out.Links) != 2 || out.Links[0].Name != "lo" || out.Manager.DNS[0].Port != 853 || out.Links[1].DNS[0].Address.String() != "10.0.0.53" {
		t.Fatal("wire readback lost policy", err)
	}
	if s.bad || s.lists != 2 || s.getLinks != 4 || s.gets != 90 || s.introspects != 12 {
		t.Fatalf("read-only wire envelope/count mismatch: %+v", s)
	}
}

// This regression is deliberately socket-free: it can run under -race in the
// restricted executor while exercising the same setup and exported handler.
func TestNMVPNWireResolvedFixtureIdentitySynchronization(t *testing.T) {
	s := &resolvedWireService{}
	const owner, caller = ":1.42", ":1.43"
	s.setIdentity(owner, caller)
	message := dbus.Message{Flags: dbus.FlagNoAutoStart, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldSender: dbus.MakeVariant(caller), dbus.FieldDestination: dbus.MakeVariant(owner),
	}}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 1000 {
			s.setIdentity(owner, caller)
		}
	})
	workers.Go(func() {
		for range 1000 {
			if _, err := s.ListDelegates(message); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bad || s.lists != 1000 {
		t.Fatal("fixture identity publication was inconsistent")
	}
}

func TestNMVPNWireResolvedRejectsUnsupportedAndSilentDrift(t *testing.T) {
	for _, mode := range []string{"unknown-property", "missing-property", "delegates", "missing-link", "wrong-path", "silent-drift", "wrong-wire-type"} {
		t.Run(mode, func(t *testing.T) {
			b, s, ctx := newResolvedWireFixture(t)
			s.mu.Lock()
			switch mode {
			case "unknown-property":
				s.properties[resolvedPath]["FuturePolicy"] = dbus.MakeVariant(true)
			case "missing-property":
				delete(s.properties[resolvedLinkPath(1)], "DNSEx")
			case "delegates":
				s.delegates = []resolvedWireDelegate{{"extra", "/org/freedesktop/resolve1/delegate/extra"}}
			case "missing-link":
				s.missing = 1
			case "wrong-path":
				s.wrongPath = 2
			case "silent-drift":
				s.changeAfterRead = true
			case "wrong-wire-type":
				s.properties[resolvedPath]["DNSOverTLS"] = dbus.MakeVariant(true)
			}
			s.mu.Unlock()
			if _, err := resolvedWireObserve(ctx, b); err == nil {
				t.Fatal("unsupported/drifting resolver accepted")
			}
			if !b.invalid.Load() {
				t.Fatal("failure left reusable observer")
			}
			select {
			case <-b.Done():
			default:
				t.Fatal("failure did not invalidate")
			}
		})
	}
}

func TestNMVPNWireResolvedOwnerLossIsSticky(t *testing.T) {
	b, s, ctx := newResolvedWireFixture(t)
	if _, err := resolvedWireObserve(ctx, b); err != nil {
		t.Fatal(err)
	}
	if reply, err := s.conn.ReleaseName(resolvedName); err != nil || reply != dbus.ReleaseNameReplyReleased {
		t.Fatal(err)
	}
	select {
	case <-b.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("owner loss did not invalidate")
	}
	if _, err := s.conn.RequestName(resolvedName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvedWireObserve(ctx, b); err == nil {
		t.Fatal("owner rebound revived observation")
	}
}

func TestNMVPNWireResolvedCancellationClosesAndJoins(t *testing.T) {
	b, s, _ := newResolvedWireFixture(t)
	s.mu.Lock()
	block, entered, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.block, s.entered, s.handlerDone = block, entered, handlerDone
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan error, 1)
	go func() { _, err := resolvedWireObserve(ctx, b); returned <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(block)
		t.Fatal("read not entered")
	}
	cancel()
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("canceled read succeeded")
		}
	case <-time.After(2 * time.Second):
		close(block)
		t.Fatal("canceled read not joined")
	}
	close(block)
	<-handlerDone
	if b.conn.Connected() || !b.invalid.Load() {
		t.Fatal("canceled wire operation remained usable")
	}
	select {
	case <-b.watchDone:
	default:
		t.Fatal("transport watcher not joined")
	}
}
