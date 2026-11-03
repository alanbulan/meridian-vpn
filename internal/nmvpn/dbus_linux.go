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

const NMName = "org.freedesktop.NetworkManager"
const NMPath = dbus.ObjectPath("/org/freedesktop/NetworkManager")
const ActiveInterface = "org.freedesktop.NetworkManager.Connection.Active"
const SettingsInterface = "org.freedesktop.NetworkManager.Settings.Connection"
const PluginService = "org.freedesktop.NetworkManager.meridian"
const propertiesInterface = "org.freedesktop.DBus.Properties"

var errPeer = errors.New("NM peer identity, policy or operation is unverified")

// BusPin comes from trusted provisioning, not environment variables or a remote
// offer. BusUID authenticates the Unix socket peer; OwnerUID authenticates NM.
// Production requires a trusted system-bus path and both UIDs zero. A caller may
// explicitly supply fixture UIDs only for an isolated bus, never as a fallback.
type BusPin struct {
	BusID, Owner string
	BusUID, OwnerUID uint32
}

// PinnedBus owns a dedicated connection. It never discovers a host bus, loads
// credentials, auto-starts a service, reconnects, or exposes the underlying Conn.
// The incoming interceptor invalidates in the reader before replies are released.
// The outgoing interceptor adds a fixed destination to the two permitted signals.
// This deliberately depends on audited godbus v5.2.2 interceptor/Emit behavior.
type PinnedBus struct {
	mu sync.Mutex
	raw *net.UnixConn
	conn *dbus.Conn
	pin BusPin
	unique string
	claimed bool
	invalid atomic.Bool
	pluginArmed atomic.Bool
	initialClaim atomic.Bool
	closeOnce sync.Once
}

// OpenPinnedBus takes ownership of a fresh connected Unix stream, before any
// D-Bus authentication bytes have been exchanged. The broker must establish its
// trusted endpoint provenance. This function performs EXTERNAL Auth and Hello;
// passing an already-authenticated stream is unsupported. Even on error the
// supplied stream is closed. There is intentionally no system/session convenience
// constructor and no production wiring from the application's entry points.
func OpenPinnedBus(ctx context.Context, raw *net.UnixConn, pin BusPin) (*PinnedBus, error) {
	if raw == nil { return nil, errPeer }
	b := &PinnedBus{raw:raw,pin:pin}
	fail := func()(*PinnedBus,error){ _=b.Close();return nil,errPeer }
	if !sessionPattern.MatchString(pin.BusID) || !ownerPattern.MatchString(pin.Owner) || len(pin.Owner)>64 || ctx.Err()!=nil { return fail() }
	control,err:=raw.SyscallConn()
	if err!=nil{return fail()}
	var cred *syscall.Ucred
	var peerErr error
	if err=control.Control(func(fd uintptr){cred,peerErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});err!=nil || peerErr!=nil || cred==nil || cred.Uid!=pin.BusUID{return fail()}
	b.conn,err=dbus.NewConn(raw,dbus.WithIncomingInterceptor(b.observe),dbus.WithOutgoingInterceptor(b.direct))
	if err!=nil{return fail()}
	err=b.run(ctx,func(ctx context.Context)error{
		if err:=b.conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))});err!=nil{return errPeer}
		if err:=b.conn.Hello();err!=nil{return errPeer}
		for _,name:=range b.conn.Names(){if ownerPattern.MatchString(name){if b.unique!=""{return errPeer};b.unique=name}}
		if b.unique==""{return errPeer}
		for _,name:=range []string{NMName,PluginService}{
			if err:=b.conn.AddMatchSignalContext(ctx,dbus.WithMatchSender("org.freedesktop.DBus"),dbus.WithMatchObjectPath("/org/freedesktop/DBus"),dbus.WithMatchInterface("org.freedesktop.DBus"),dbus.WithMatchMember("NameOwnerChanged"),dbus.WithMatchArg(0,name));err!=nil{return errPeer}
		}
		return b.check(ctx,false)
	})
	if err!=nil{return fail()}
	return b,nil
}

// observe must remain synchronous, nonblocking and free of method calls/locks.
func(b *PinnedBus)observe(m *dbus.Message){
	if m.Type!=dbus.TypeSignal || m.Headers[dbus.FieldSender].Value()!="org.freedesktop.DBus" || m.Headers[dbus.FieldPath].Value()!=dbus.ObjectPath("/org/freedesktop/DBus") || m.Headers[dbus.FieldInterface].Value()!="org.freedesktop.DBus" || m.Headers[dbus.FieldMember].Value()!="NameOwnerChanged"{return}
	if len(m.Body)!=3{b.invalid.Store(true);return}
	name,ok:=m.Body[0].(string);old,oldOK:=m.Body[1].(string);next,nextOK:=m.Body[2].(string)
	if !ok || !oldOK || !nextOK{b.invalid.Store(true);return}
	if name==NMName{b.invalid.Store(true);return}
	if name==PluginService && b.pluginArmed.Load(){
		if old=="" && next==b.unique && b.initialClaim.CompareAndSwap(false,true){return}
		b.invalid.Store(true)
	}
}

func(b *PinnedBus)direct(m *dbus.Message){
	if m.Type==dbus.TypeSignal && m.Headers[dbus.FieldPath].Value()==PluginPath && m.Headers[dbus.FieldInterface].Value()==PluginInterface {
		member,_:=m.Headers[dbus.FieldMember].Value().(string)
		if member=="Config" || member=="Ip4Config"{m.Headers[dbus.FieldDestination]=dbus.MakeVariant(b.pin.Owner)}
	}
}

// run never detaches a mutation. Cancellation closes the raw socket BEFORE Conn:
// godbus Close alone waits for its output lock and can deadlock behind Emit.
// The callback is joined, so it cannot later close a subsequent operation's bus.
func(b *PinnedBus)run(ctx context.Context,fn func(context.Context)error)error{
	b.mu.Lock();defer b.mu.Unlock()
	ctx,cancel:=context.WithTimeout(ctx,10*time.Second);defer cancel()
	if ctx.Err()!=nil || b.invalid.Load(){return errPeer}
	done:=make(chan struct{})
	stop:=context.AfterFunc(ctx,func(){b.invalid.Store(true);_=b.raw.Close();if b.conn!=nil{_=b.conn.Close()};close(done)})
	err:=fn(ctx)
	if !stop(){<-done}
	// Cancellation can win while stopping an as-yet-unscheduled callback.
	// Close synchronously too: no canceled request leaves a reusable transport.
	if ctx.Err()!=nil{_=b.Close();return errPeer}
	if err!=nil || b.invalid.Load(){return errPeer}
	return nil
}

func(b *PinnedBus)call(ctx context.Context,dest string,path dbus.ObjectPath,method string,args []any,out ...any)error{
	if ctx.Err()!=nil || b.invalid.Load() || !b.conn.Connected(){return errPeer}
	if err:=b.conn.Object(dest,path).CallWithContext(ctx,method,dbus.FlagNoAutoStart,args...).Store(out...);err!=nil{return errPeer}
	if ctx.Err()!=nil || b.invalid.Load(){return errPeer}
	return nil
}

func(b *PinnedBus)check(ctx context.Context,plugin bool)error{
	var id,owner string
	var uid uint32
	if b.call(ctx,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus.GetId",nil,&id)!=nil || id!=b.pin.BusID{return errPeer}
	if b.call(ctx,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus.GetNameOwner",[]any{NMName},&owner)!=nil || owner!=b.pin.Owner{return errPeer}
	if b.call(ctx,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus.GetConnectionUnixUser",[]any{b.pin.Owner},&uid)!=nil || uid!=b.pin.OwnerUID{return errPeer}
	if plugin {
		if b.call(ctx,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus.GetNameOwner",[]any{PluginService},&owner)!=nil || owner!=b.unique{return errPeer}
	}
	if b.invalid.Load() || ctx.Err()!=nil{return errPeer}
	return nil
}

// ClaimPluginName claims only the fixed plugin service, never replacing/queuing
// another owner. It does not install a service or implement Connect/NeedSecrets.
// A real broker must export/authenticate those methods on this same connection
// and bind the activation's immutable incoming Connect before constructing Peer.
func(b *PinnedBus)ClaimPluginName(ctx context.Context)error{
	return b.run(ctx,func(ctx context.Context)error{
		if b.claimed || b.check(ctx,false)!=nil{return errPeer}
		b.pluginArmed.Store(true)
		reply,err:=b.conn.RequestName(PluginService,dbus.NameFlagDoNotQueue)
		if err!=nil || reply!=dbus.RequestNameReplyPrimaryOwner{b.invalid.Store(true);return errPeer}
		if b.check(ctx,true)!=nil{return errPeer}
		b.claimed=true
		return nil
	})
}
func(b *PinnedBus)UniqueName()string{return b.unique}
func(b *PinnedBus)Close()error{
	b.closeOnce.Do(func(){b.invalid.Store(true);if b.raw!=nil{_=b.raw.Close()};if b.conn!=nil{_=b.conn.Close()}})
	return nil
}

// No method lets callers select another destination, emit arbitrary members or
// supply a sender. Emit returns encoding/transport failures; raw SendWithContext
// on a signal does NOT in godbus v5.2.2. A successful Emit is still not NM receipt.
func(b *PinnedBus)emit(ctx context.Context,member string,values map[string]dbus.Variant)error{
	if ctx.Err()!=nil || b.invalid.Load() || (member!="Config" && member!="Ip4Config"){return errPeer}
	if err:=b.conn.Emit(PluginPath,PluginInterface+"."+member,values);err!=nil{b.invalid.Store(true);return errPeer}
	if ctx.Err()!=nil || b.invalid.Load(){return errPeer}
	return nil
}

// Keep arbitrary text out of bus-name selection, including accidental whitespace.
func validPluginOwner(s string)bool{return len(s)<=64 && !strings.ContainsAny(s," \t\n") && ownerPattern.MatchString(s)}
