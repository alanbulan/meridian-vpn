//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	resolvedName                = "org.freedesktop.resolve1"
	resolvedPath                = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedManagerInterface    = resolvedName + ".Manager"
	resolvedLinkInterface       = resolvedName + ".Link"
	resolvedBusName             = "org.freedesktop.DBus"
	resolvedBusPath             = dbus.ObjectPath("/org/freedesktop/DBus")
	resolvedIntrospectInterface = "org.freedesktop.DBus.Introspectable"
)

var errResolvedObservation = errors.New("resolved observation is unavailable or unverified")

// PinnedResolvedObserver owns a dedicated, read-only D-Bus connection. It cannot
// resolve names, change resolver settings, export services, discover a bus,
// reconnect, or confer network authority. Never copy an observer after use.
type PinnedResolvedObserver struct {
	self        *PinnedResolvedObserver
	raw         *net.UnixConn
	conn        *dbus.Conn
	pin         BusPin
	gate        chan struct{}
	invalid     atomic.Bool
	expected    atomic.Pointer[resolvedExpectedReply]
	closeOnce   sync.Once
	invalidated chan struct{}
	watchDone   chan struct{}
	closeErr    error
}

type resolvedExpectedReply struct {
	sender, signature string
	serial            atomic.Uint32
}

// OpenPinnedResolvedObserver takes ownership of a fresh, connected Unix stream,
// before any authentication bytes have been exchanged. Trusted provisioning must
// supply the socket's endpoint provenance, bus ID, resolved's UNIQUE owner and
// both peer UIDs. Production requires a trusted root-owned system bus; OwnerUID
// is the exact independently provisioned service UID (upstream systemd v258 runs
// resolved as systemd-resolve, not root). No UID is discovered or relaxed to make
// a connection succeed. Non-root BUS peer pins are only for isolated tests. No path,
// environment variable, address discovery, service activation or reconnect is
// used. All failures close the supplied stream, including authentication failure.
func OpenPinnedResolvedObserver(ctx context.Context, raw *net.UnixConn, pin BusPin) (*PinnedResolvedObserver, error) {
	if raw == nil {
		return nil, errResolvedObservation
	}
	b := &PinnedResolvedObserver{raw: raw, pin: pin, gate: make(chan struct{}, 1), invalidated: make(chan struct{})}
	b.self = b
	fail := func() (*PinnedResolvedObserver, error) { return nil, errors.Join(errResolvedObservation, b.Close()) }
	if ctx == nil || ctx.Err() != nil || !sessionPattern.MatchString(pin.BusID) || !validPluginOwner(pin.Owner) {
		return fail()
	}
	control, err := raw.SyscallConn()
	if err != nil {
		return fail()
	}
	var cred *syscall.Ucred
	var peerErr error
	var socketType int
	if err = control.Control(func(fd uintptr) {
		cred, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if peerErr == nil {
			socketType, peerErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		}
	}); err != nil || peerErr != nil || cred == nil || cred.Uid != pin.BusUID || socketType != syscall.SOCK_STREAM {
		return fail()
	}
	b.conn, err = dbus.NewConn(raw, dbus.WithIncomingInterceptor(b.observe), dbus.WithOutgoingInterceptor(b.outgoing))
	if err != nil {
		return fail()
	}
	b.watchDone = make(chan struct{})
	go func() { <-b.conn.Context().Done(); b.markInvalid(); close(b.watchDone) }()
	err = b.run(ctx, func(ctx context.Context) error {
		if err := b.conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
			return errResolvedObservation
		}
		b.expected.Store(&resolvedExpectedReply{sender: resolvedBusName, signature: "s"})
		err := b.conn.Hello()
		b.expected.Store(nil)
		if err != nil || b.invalid.Load() {
			return errResolvedObservation
		}
		if _, err = uniqueHelloName(b.conn.Names()); err != nil {
			return errResolvedObservation
		}
		for _, rule := range b.signalRules() {
			if b.call(ctx, resolvedBusName, resolvedBusPath, resolvedBusName+".AddMatch", []any{rule}, "") != nil {
				return errResolvedObservation
			}
		}
		return b.check(ctx)
	})
	if err != nil {
		return fail()
	}
	return b, nil
}

func (b *PinnedResolvedObserver) signalRules() []string {
	return []string{
		"type='signal',sender='org.freedesktop.DBus',path='/org/freedesktop/DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.freedesktop.resolve1'",
		"type='signal',sender='" + b.pin.Owner + "',path_namespace='/org/freedesktop/resolve1',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'",
	}
}

// Interceptors run synchronously before godbus releases replies. godbus 5.2.4
// correlates replies by serial alone, so additionally require the exact sender,
// serial and result signature of the single outstanding request. No locks or
// method calls are allowed in the incoming interceptor.
func (b *PinnedResolvedObserver) observe(m *dbus.Message) {
	if m == nil {
		b.markInvalid()
		return
	}
	sender, _ := m.Headers[dbus.FieldSender].Value().(string)
	if m.Type == dbus.TypeMethodReply || m.Type == dbus.TypeError {
		expected := b.expected.Load()
		serial, ok := m.Headers[dbus.FieldReplySerial].Value().(uint32)
		signature, _ := m.Headers[dbus.FieldSignature].Value().(dbus.Signature)
		if expected == nil || !ok || serial == 0 || serial != expected.serial.Load() || sender != expected.sender || m.Type == dbus.TypeError || signature.String() != expected.signature {
			b.markInvalid()
		}
		return
	}
	if m.Type == dbus.TypeMethodCall {
		b.markInvalid()
		return
	}
	if m.Type != dbus.TypeSignal {
		return
	}
	path, _ := m.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	iface, _ := m.Headers[dbus.FieldInterface].Value().(string)
	member, _ := m.Headers[dbus.FieldMember].Value().(string)
	if sender == resolvedBusName && path == resolvedBusPath && iface == resolvedBusName && member == "NameOwnerChanged" {
		if len(m.Body) != 3 {
			b.markInvalid()
			return
		}
		name, a := m.Body[0].(string)
		_, c := m.Body[1].(string)
		_, d := m.Body[2].(string)
		if !a || !c || !d || name == resolvedName {
			b.markInvalid()
		}
	}
	if sender == b.pin.Owner && iface == propertiesInterface && member == "PropertiesChanged" && (path == resolvedPath || strings.HasPrefix(string(path), string(resolvedPath)+"/")) {
		// A signal is useful negative evidence only. Many resolver policy
		// fields explicitly do not emit signals; silence proves nothing.
		b.markInvalid()
	}
}

func (b *PinnedResolvedObserver) outgoing(m *dbus.Message) {
	if m.Type != dbus.TypeMethodCall {
		return
	}
	expected := b.expected.Load()
	dest, _ := m.Headers[dbus.FieldDestination].Value().(string)
	if expected == nil || dest != expected.sender || !b.permittedCall(m) || !expected.serial.CompareAndSwap(0, m.Serial()) {
		b.markInvalid()
		// Never call Conn.Close under godbus's output path. Closing the raw
		// stream prevents an unexpected method from reaching the broker.
		if b.raw != nil {
			_ = b.raw.Close()
		}
	}
}

// Defense in depth: even internal programming errors cannot send a resolver
// setter, Resolve*, arbitrary destination, caller-selected property or path.
func (b *PinnedResolvedObserver) permittedCall(m *dbus.Message) bool {
	dest, _ := m.Headers[dbus.FieldDestination].Value().(string)
	path, _ := m.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
	iface, _ := m.Headers[dbus.FieldInterface].Value().(string)
	member, _ := m.Headers[dbus.FieldMember].Value().(string)
	if dest == resolvedBusName && path == resolvedBusPath && iface == resolvedBusName {
		switch member {
		case "Hello", "GetId":
			return len(m.Body) == 0
		case "GetNameOwner":
			return len(m.Body) == 1 && m.Body[0] == resolvedName
		case "GetConnectionUnixUser":
			return len(m.Body) == 1 && m.Body[0] == b.pin.Owner
		case "AddMatch":
			if len(m.Body) != 1 {
				return false
			}
			for _, rule := range b.signalRules() {
				if m.Body[0] == rule {
					return true
				}
			}
		}
		return false
	}
	if dest != b.pin.Owner || m.Flags&dbus.FlagNoAutoStart == 0 {
		return false
	}
	if path == resolvedPath && iface == resolvedManagerInterface && member == "GetLink" && len(m.Body) == 1 {
		index, ok := m.Body[0].(int32)
		return ok && index > 0
	}
	if path == resolvedPath && iface == resolvedManagerInterface && member == "ListDelegates" {
		return len(m.Body) == 0
	}
	if iface == resolvedIntrospectInterface && member == "Introspect" && len(m.Body) == 0 {
		return path == resolvedPath || resolvedValidLinkPath(path)
	}
	if iface != propertiesInterface || member != "Get" || len(m.Body) != 2 {
		return false
	}
	propertyIface, ok := m.Body[0].(string)
	property, named := m.Body[1].(string)
	if !ok || !named {
		return false
	}
	if path == resolvedPath && propertyIface == resolvedManagerInterface {
		_, ok := resolvedPropertySchema(true)[property]
		return ok
	}
	if propertyIface == resolvedLinkInterface && resolvedValidLinkPath(path) {
		_, ok := resolvedPropertySchema(false)[property]
		return ok
	}
	return false
}

func (b *PinnedResolvedObserver) run(ctx context.Context, fn func(context.Context) error) error {
	if b == nil || b.self != b || ctx == nil || b.gate == nil {
		return errResolvedObservation
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case b.gate <- struct{}{}:
		defer func() { <-b.gate }()
	case <-ctx.Done():
		return errors.Join(errResolvedObservation, b.Close())
	}
	if ctx.Err() != nil || b.invalid.Load() {
		return errors.Join(errResolvedObservation, b.Close())
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = b.Close(); close(done) })
	err := fn(ctx)
	if !stop() {
		<-done
	}
	if err != nil || ctx.Err() != nil || b.invalid.Load() {
		return errors.Join(errResolvedObservation, err, b.Close())
	}
	return nil
}

func (b *PinnedResolvedObserver) call(ctx context.Context, dest string, path dbus.ObjectPath, method string, args []any, signature string, out ...any) error {
	if ctx.Err() != nil || b.invalid.Load() || b.conn == nil || !b.conn.Connected() {
		return errResolvedObservation
	}
	b.expected.Store(&resolvedExpectedReply{sender: dest, signature: signature})
	err := b.conn.Object(dest, path).CallWithContext(ctx, method, dbus.FlagNoAutoStart, args...).Store(out...)
	b.expected.Store(nil)
	if err != nil || ctx.Err() != nil || b.invalid.Load() {
		return errResolvedObservation
	}
	return nil
}

func (b *PinnedResolvedObserver) check(ctx context.Context) error {
	var id, owner string
	var uid uint32
	if b.call(ctx, resolvedBusName, resolvedBusPath, resolvedBusName+".GetId", nil, "s", &id) != nil || id != b.pin.BusID {
		return errResolvedObservation
	}
	if b.call(ctx, resolvedBusName, resolvedBusPath, resolvedBusName+".GetNameOwner", []any{resolvedName}, "s", &owner) != nil || owner != b.pin.Owner {
		return errResolvedObservation
	}
	if b.call(ctx, resolvedBusName, resolvedBusPath, resolvedBusName+".GetConnectionUnixUser", []any{b.pin.Owner}, "u", &uid) != nil || uid != b.pin.OwnerUID {
		return errResolvedObservation
	}
	return nil
}

// Close revokes only this observer's transport. It changes no resolver or NM
// networking. Raw close comes first to unblock both authentication and writes;
// the operation's cancellation callback is always joined before run returns.
func (b *PinnedResolvedObserver) Close() error {
	if b == nil {
		return nil
	}
	if b.self != b {
		return errResolvedObservation
	}
	b.closeOnce.Do(func() {
		b.markInvalid()
		retain := func(err error) {
			if err != nil && !errors.Is(err, net.ErrClosed) {
				b.closeErr = errors.Join(b.closeErr, err)
			}
		}
		if b.raw != nil {
			retain(b.raw.Close())
		}
		if b.conn != nil {
			retain(b.conn.Close())
		}
		if b.watchDone != nil {
			<-b.watchDone
		}
	})
	return b.closeErr
}

func (b *PinnedResolvedObserver) markInvalid() {
	if b.invalid.CompareAndSwap(false, true) && b.invalidated != nil {
		close(b.invalidated)
	}
}

var resolvedInvalidDone = func() <-chan struct{} { ch := make(chan struct{}); close(ch); return ch }()

// Done is stable and closes on observed owner/property change, transport loss,
// failed observation or Close. Silence does not establish unchanged policy.
func (b *PinnedResolvedObserver) Done() <-chan struct{} {
	if b == nil || b.self != b || b.invalidated == nil {
		return resolvedInvalidDone
	}
	return b.invalidated
}
