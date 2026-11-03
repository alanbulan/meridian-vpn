//go:build linux

package nmvpn

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// This is not a D-Bus service: the accepted Unix stream deliberately never reads.
// A large local signal fills its socket buffers, exercising the real Emit write
// lock and raw-socket-first cancellation path without any system-bus access.
func TestPinnedBusCancellationUnblocksSaturatedEmit(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"blocked.sock")
	listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:path,Net:"unix"})
	if err!=nil{t.Fatal(err)}
	defer listener.Close()
	accepted:=make(chan *net.UnixConn,1)
	go func(){conn,_:=listener.AcceptUnix();accepted<-conn}()
	raw,err:=net.DialUnix("unix",nil,&net.UnixAddr{Name:path,Net:"unix"})
	if err!=nil{t.Fatal(err)}
	defer raw.Close()
	remote:=<-accepted
	if remote==nil{t.Fatal("fixture accept failed")}
	defer remote.Close()
	if err:=raw.SetWriteBuffer(4096);err!=nil{t.Fatal(err)}
	if err:=remote.SetReadBuffer(4096);err!=nil{t.Fatal(err)}
	b:=&PinnedBus{raw:raw,pin:BusPin{Owner:":1.42"}}
	b.conn,err=dbus.NewConn(raw,dbus.WithOutgoingInterceptor(b.direct))
	if err!=nil{t.Fatal(err)}
	defer b.Close()
	ctx,cancel:=context.WithTimeout(context.Background(),100*time.Millisecond)
	defer cancel()
	returned:=make(chan error,1)
	go func(){returned<-b.run(ctx,func(ctx context.Context)error{return b.emit(ctx,"Config",map[string]dbus.Variant{"synthetic-padding":dbus.MakeVariant(make([]byte,1<<20))})})}()
	select{
	case err:=<-returned:
		if err==nil || !b.invalid.Load(){t.Fatal("canceled saturated emit returned success")}
	case <-time.After(3*time.Second):
		// Unblock/join before failing so this regression never leaves a writer.
		_=raw.Close()
		select{case <-returned:case <-time.After(time.Second):}
		t.Fatal("cancellation deadlocked behind the signal write")
	}
	if _,err:=raw.Write([]byte{0});err==nil{t.Fatal("canceled operation left socket reusable")}
}

func TestPinnedBusOrderedInvalidationAndDirectedHeaders(t *testing.T){
	b:=&PinnedBus{pin:BusPin{Owner:":1.42"},unique:":1.9"}
	b.pluginArmed.Store(true)
	signal:=func(sender,name,old,next string)*dbus.Message{return &dbus.Message{Type:dbus.TypeSignal,Headers:map[dbus.HeaderField]dbus.Variant{
		dbus.FieldSender:dbus.MakeVariant(sender),dbus.FieldPath:dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/DBus")),dbus.FieldInterface:dbus.MakeVariant("org.freedesktop.DBus"),dbus.FieldMember:dbus.MakeVariant("NameOwnerChanged"),
	},Body:[]any{name,old,next}}}
	b.observe(signal(":1.7",NMName,":1.42",":1.5"))
	if b.invalid.Load(){t.Fatal("untrusted sender forged invalidation")}
	b.observe(signal("org.freedesktop.DBus",PluginService,"",b.unique))
	if b.invalid.Load(){t.Fatal("initial own claim invalidated connection")}
	b.observe(signal("org.freedesktop.DBus",PluginService,b.unique,""))
	b.observe(signal("org.freedesktop.DBus",PluginService,"",b.unique))
	if !b.invalid.Load(){t.Fatal("release/reacquire was not permanent")}
	for _,member:=range []string{"Config","Ip4Config"}{
		m:=&dbus.Message{Type:dbus.TypeSignal,Headers:map[dbus.HeaderField]dbus.Variant{dbus.FieldPath:dbus.MakeVariant(PluginPath),dbus.FieldInterface:dbus.MakeVariant(PluginInterface),dbus.FieldMember:dbus.MakeVariant(member)}}
		b.direct(m)
		if m.Headers[dbus.FieldDestination].Value()!=b.pin.Owner{t.Fatal("missing fixed destination")}
		if _,ok:=m.Headers[dbus.FieldSender];ok{t.Fatal("forged sender header")}
	}
}

func TestPinnedBusRejectsNilSocket(t *testing.T){
	if b,err:=OpenPinnedBus(context.Background(),nil,BusPin{BusUID:uint32(os.Geteuid())});err==nil || b!=nil{t.Fatal("nil socket accepted")}
}
