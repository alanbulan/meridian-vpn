//go:build linux && nmvpnintegration

package nmvpn

// This fixture has no dependency on, or access to, NetworkManager or a host bus.
// All service state is synthetic and every connection uses the socket created here.
import (
 "bufio"
 "context"
 "errors"
 "io"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "reflect"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/godbus/dbus/v5"
)

const wireUUID = "12345678-1234-1234-1234-123456789abc"
const wireActive = dbus.ObjectPath("/org/freedesktop/NetworkManager/ActiveConnection/1")
const wireSettings = dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings/1")

func nmPrivateBus(t *testing.T) string {
 t.Helper()
 if os.Getenv("MERIDIAN_NMVPN_WIRE_TESTS") != "1" { t.Fatal("explicit MERIDIAN_NMVPN_WIRE_TESTS=1 opt-in required") }
 executable,err:=exec.LookPath("dbus-daemon");if err!=nil {t.Fatal("official dbus-daemon is required, not skipped")}
 dir,err:=os.MkdirTemp("","meridian-nmvpn-wire-");if err!=nil {t.Fatal(err)}
 t.Cleanup(func(){_ = os.RemoveAll(dir)})
 socket:=filepath.Join(dir,"bus")
 // No includes, service directories, activation helper, standard configuration,
 // TCP listeners or inherited bus addresses. EXTERNAL is the sole mechanism.
 config:=`<busconfig><type>session</type><listen>unix:path=`+socket+`</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>
<limit name="max_message_size">65536</limit><limit name="max_incoming_bytes">262144</limit><limit name="max_outgoing_bytes">262144</limit>
</busconfig>`
 path:=filepath.Join(dir,"bus.conf");if err=os.WriteFile(path,[]byte(config),0600);err!=nil {t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
 cmd:=exec.CommandContext(ctx,executable,"--nofork","--nopidfile","--nosyslog","--config-file="+path,"--print-address=1")
 cmd.Env=[]string{"PATH=/usr/bin:/bin","LANG=C","HOME="+dir};cmd.Stderr=io.Discard
 stdout,err:=cmd.StdoutPipe();if err!=nil {cancel();t.Fatal(err)}
 if err=cmd.Start();err!=nil {cancel();t.Fatal(err)}
 // Kill only the exact child process we own; never pkill, a pidfile or a name.
 t.Cleanup(func(){cancel();_ = cmd.Process.Kill();_ = cmd.Wait()})
 ready:=make(chan string,1);go func(){line,_:=bufio.NewReader(stdout).ReadString('\n');ready<-line}()
 select {case line:=<-ready:if !strings.HasPrefix(line,"unix:path="+socket){t.Fatal("private daemon readiness failed")};case <-time.After(5*time.Second):t.Fatal("private daemon readiness timed out")}
 return socket
}

func nmWireConn(t *testing.T,socket string)*dbus.Conn {
 t.Helper();ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second)
 c,err:=dbus.Connect("unix:path="+socket,dbus.WithContext(ctx));if err!=nil {cancel();t.Fatal(err)}
 t.Cleanup(func(){_ = c.Close();cancel()});return c
}
func nmRawConn(t *testing.T,socket string)*net.UnixConn {
 t.Helper();c,err:=net.DialUnix("unix",nil,&net.UnixAddr{Name:socket,Net:"unix"});if err!=nil {t.Fatal(err)};return c
}
func nmContext(t *testing.T)context.Context {t.Helper();ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);t.Cleanup(cancel);return ctx}

func nmSafeSettings()map[string]map[string]dbus.Variant {
 return map[string]map[string]dbus.Variant{
 "connection":{"uuid":dbus.MakeVariant(wireUUID),"type":dbus.MakeVariant("vpn")},
 "vpn":{"service-type":dbus.MakeVariant(PluginService)},
 "ipv4":{"method":dbus.MakeVariant("auto"),"never-default":dbus.MakeVariant(true),"ignore-auto-dns":dbus.MakeVariant(true)},
 "ipv6":{"method":dbus.MakeVariant("disabled")},
 }
}

type nmWireService struct {
 mu sync.Mutex
 conn *dbus.Conn
 profile map[string]map[string]dbus.Variant
 uuid string
 active,retain bool
 deactivations int
 caller string
}
type nmWireProperties struct{s *nmWireService;active bool}
func(p *nmWireProperties)GetAll(iface string)(map[string]dbus.Variant,*dbus.Error){
 p.s.mu.Lock();defer p.s.mu.Unlock()
 if p.active && iface==ActiveInterface && p.s.active {return map[string]dbus.Variant{"Uuid":dbus.MakeVariant(p.s.uuid),"Type":dbus.MakeVariant("vpn"),"Vpn":dbus.MakeVariant(true),"Connection":dbus.MakeVariant(wireSettings)},nil}
 if !p.active && iface==NMName {paths:=[]dbus.ObjectPath{};if p.s.active {paths=append(paths,wireActive)};return map[string]dbus.Variant{"ActiveConnections":dbus.MakeVariant(paths)},nil}
 return nil,&dbus.Error{Name:"org.freedesktop.DBus.Error.UnknownObject"}
}
func(p *nmWireProperties)Get(iface,property string)(dbus.Variant,*dbus.Error){m,e:=p.GetAll(iface);if e!=nil{return dbus.MakeVariant(""),e};v,ok:=m[property];if !ok{return dbus.MakeVariant(""),&dbus.Error{Name:"org.freedesktop.DBus.Error.InvalidArgs"}};return v,nil}
type nmWireSettingsService struct{s *nmWireService}
func(p *nmWireSettingsService)GetSettings()(map[string]map[string]dbus.Variant,*dbus.Error){p.s.mu.Lock();defer p.s.mu.Unlock();out:=map[string]map[string]dbus.Variant{};for k,m:=range p.s.profile {out[k]=map[string]dbus.Variant{};for n,v:=range m {out[k][n]=v}};return out,nil}
func(s *nmWireService)DeactivateConnection(sender dbus.Sender,path dbus.ObjectPath)*dbus.Error {
 s.mu.Lock();defer s.mu.Unlock();if path!=wireActive {return &dbus.Error{Name:"org.freedesktop.DBus.Error.InvalidArgs"}};s.deactivations++;s.caller=string(sender);if !s.retain{s.active=false};return nil
}
func nmInstallService(t *testing.T,socket string)*nmWireService {
 t.Helper();s:=&nmWireService{conn:nmWireConn(t,socket),profile:nmSafeSettings(),uuid:wireUUID,active:true}
 for _,e:=range []struct{obj any;path dbus.ObjectPath;iface string}{{s,NMPath,NMName},{&nmWireProperties{s,false},NMPath,"org.freedesktop.DBus.Properties"},{&nmWireProperties{s,true},wireActive,"org.freedesktop.DBus.Properties"},{&nmWireSettingsService{s},wireSettings,SettingsInterface}} {if err:=s.conn.Export(e.obj,e.path,e.iface);err!=nil{t.Fatal(err)}}
 reply,err:=s.conn.RequestName(NMName,dbus.NameFlagDoNotQueue);if err!=nil || reply!=dbus.RequestNameReplyPrimaryOwner {t.Fatal("cannot own private fixture NM name",err)};return s
}

type nmWireBroker struct {binding Binding;offer Offer;unsafe,residual,stopped bool; stopErr error}
func(b *nmWireBroker)Verify(ctx context.Context,binding Binding,o Offer)error {if err:=ctx.Err();err!=nil{return err};if b.unsafe || !reflect.DeepEqual(b.binding,binding) || !reflect.DeepEqual(b.offer,o){return errors.New("broker binding or applied profile rejected")};return nil}
func(b *nmWireBroker)Stop(ctx context.Context,binding Binding)error {if err:=b.Verify(ctx,binding,b.offer);err!=nil{return err};b.stopped=true;return b.stopErr}
func(b *nmWireBroker)ProveAbsent(ctx context.Context,binding Binding)error {if err:=b.Verify(ctx,binding,b.offer);err!=nil{return err};if !b.stopped || b.residual {return errors.New("broker worker/link/routes/DNS absence unproven")};return nil}

type nmWireFixture struct {socket string;service *nmWireService;pin BusPin;bus *PinnedBus;binding Binding;broker *nmWireBroker;offer Offer;policy Policy;ctx context.Context}
func nmFixture(t *testing.T)*nmWireFixture {
 t.Helper();f:=&nmWireFixture{socket:nmPrivateBus(t),ctx:nmContext(t)};f.service=nmInstallService(t,f.socket)
 if err:=f.service.conn.BusObject().Call("org.freedesktop.DBus.GetId",0).Store(&f.pin.BusID);err!=nil{t.Fatal(err)}
 if err:=f.service.conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner",0,NMName).Store(&f.pin.Owner);err!=nil{t.Fatal(err)}
 f.pin.BusUID=uint32(os.Geteuid());f.pin.OwnerUID=uint32(os.Geteuid())
 var err error;f.bus,err=OpenPinnedBus(f.ctx,nmRawConn(t,f.socket),f.pin);if err!=nil{t.Fatal(err)};t.Cleanup(func(){_ = f.bus.Close()})
 if err=f.bus.ClaimPluginName(f.ctx);err!=nil{t.Fatal(err)}
 f.offer,f.policy=configFixture()
 f.binding=Binding{Identity:Identity{BootID:"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",BusID:f.pin.BusID,Owner:f.pin.Owner,UUID:wireUUID,ActivePath:string(wireActive),Session:f.offer.Session,Interface:f.offer.Interface},ConnectionPath:wireSettings,PluginOwner:f.bus.UniqueName()}
 f.broker=&nmWireBroker{binding:f.binding,offer:f.offer};return f
}
func(f *nmWireFixture)peer(t *testing.T)*DBusPeer {t.Helper();p,err:=NewDBusPeer(f.ctx,f.bus,f.broker,f.binding,f.offer,f.policy);if err!=nil{t.Fatal(err)};return p}
func nmSignals(t *testing.T,c *dbus.Conn)chan *dbus.Signal {t.Helper();ch:=make(chan *dbus.Signal,16);c.Signal(ch);if err:=c.AddMatchSignal(dbus.WithMatchInterface(PluginInterface));err!=nil{t.Fatal(err)};t.Cleanup(func(){c.RemoveSignal(ch)});return ch}

func TestNMVPNWireDirectedLifecycle(t *testing.T){
 f:=nmFixture(t);received:=nmSignals(t,f.service.conn);observed:=nmSignals(t,nmWireConn(t,f.socket));p:=f.peer(t)
 j:=&memoryJournal{trace: new([]string)};controller,err:=NewController(p,j);if err!=nil{t.Fatal(err)}
 if err=controller.Publish(f.ctx,f.binding.Identity,f.offer,f.policy);err!=nil{t.Fatal(err)}
 config,_:=Encode(f.offer,f.policy)
 for _,want:=range []struct{name string;payload map[string]dbus.Variant}{{"Config",config.General},{"Ip4Config",config.IPv4}} {
 select{case sig:=<-received:if sig.Sender!=f.bus.UniqueName() || sig.Path!=PluginPath || sig.Name!=PluginInterface+"."+want.name || len(sig.Body)!=1 || !reflect.DeepEqual(sig.Body[0],want.payload){t.Fatalf("incorrect directed signal: %#v",sig)};case <-f.ctx.Done():t.Fatal("missing directed signal")}
 }
 select{case sig:=<-observed:t.Fatalf("plugin payload leaked to ordinary observer: %s",sig.Name);case <-time.After(100*time.Millisecond):}
 if err=controller.Stop(f.ctx);err!=nil{t.Fatal(err)}
 f.service.mu.Lock();defer f.service.mu.Unlock();if f.service.deactivations!=1 || f.service.caller!=f.bus.UniqueName() || f.service.active || !f.broker.stopped {t.Fatal("withdrawal did not target pinned generation")}
 if record,err:=j.Load();err!=nil || record!=nil{t.Fatal("verified cleanup did not clear journal")}
}

func TestNMVPNWirePinRejections(t *testing.T){
 f:=nmFixture(t)
 for name,mutate:=range map[string]func(*BusPin){"bus ID":func(p *BusPin){p.BusID=strings.Repeat("0",32)},"bus UID":func(p *BusPin){p.BusUID++},"owner UID":func(p *BusPin){p.OwnerUID++},"owner":func(p *BusPin){p.Owner=":999.999"}} {t.Run(name,func(t *testing.T){pin:=f.pin;mutate(&pin);b,err:=OpenPinnedBus(f.ctx,nmRawConn(t,f.socket),pin);if b!=nil{_ = b.Close()};if err==nil{t.Fatal("incorrect pin accepted")}})}
 competitor,err:=OpenPinnedBus(f.ctx,nmRawConn(t,f.socket),f.pin);if err!=nil{t.Fatal(err)};defer competitor.Close();if competitor.ClaimPluginName(f.ctx)==nil{t.Fatal("contended plugin name accepted")}
}

func TestNMVPNWireBindingAndProfile(t *testing.T){
 for name,mutate:=range map[string]func(*nmWireFixture){
 "uuid":func(f *nmWireFixture){f.binding.Identity.UUID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
 "session":func(f *nmWireFixture){f.binding.Identity.Session=strings.Repeat("1",32)},
 "boot":func(f *nmWireFixture){f.binding.Identity.BootID="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"},
 "plugin owner":func(f *nmWireFixture){f.binding.PluginOwner=":999.999"},
 "applied unsafe":func(f *nmWireFixture){f.broker.unsafe=true},
 "profile default":func(f *nmWireFixture){f.service.profile["ipv4"]["never-default"]=dbus.MakeVariant(false)},
 "profile DNS":func(f *nmWireFixture){f.service.profile["ipv4"]["dns"]=dbus.MakeVariant([]uint32{1})},
 "profile IPv6":func(f *nmWireFixture){f.service.profile["ipv6"]["method"]=dbus.MakeVariant("auto")},
 }{t.Run(name,func(t *testing.T){f:=nmFixture(t);f.service.mu.Lock();mutate(f);f.service.mu.Unlock();if _,err:=NewDBusPeer(f.ctx,f.bus,f.broker,f.binding,f.offer,f.policy);err==nil{t.Fatal("unsafe binding/profile accepted")}})}
 t.Run("current profile changed",func(t *testing.T){f:=nmFixture(t);p:=f.peer(t);f.service.mu.Lock();f.service.profile["ipv4"]["never-default"]=dbus.MakeVariant(false);f.service.mu.Unlock();if p.Check(f.ctx,f.binding.Identity)==nil{t.Fatal("current profile mutation ignored")}})
}

func TestNMVPNWirePayloadAndOrder(t *testing.T){
 for _,mode:=range []string{"mutated","nested routes","out of order","duplicate"}{t.Run(mode,func(t *testing.T){f:=nmFixture(t);p:=f.peer(t);config,_:=Encode(f.offer,f.policy);switch mode {
 case "mutated":config.General["has-ip6"]=dbus.MakeVariant(true);if p.Publish(f.ctx,f.binding.Identity,"Config",config.General)==nil{t.Fatal("mutated payload accepted")}
 case "nested routes":
 if err:=p.Publish(f.ctx,f.binding.Identity,"Config",config.General);err!=nil{t.Fatal(err)}
 config.IPv4["routes"].Value().([][]uint32)[0][2]=1
 if p.Publish(f.ctx,f.binding.Identity,"Ip4Config",config.IPv4)==nil{t.Fatal("nested route mutation accepted")}
 // Rejection must not modify the frozen payload or consume its publication slot.
 fresh,err:=Encode(f.offer,f.policy);if err!=nil{t.Fatal(err)}
 if err=p.Publish(f.ctx,f.binding.Identity,"Ip4Config",fresh.IPv4);err!=nil{t.Fatal("caller mutation changed frozen plan",err)}
 case "out of order":if p.Publish(f.ctx,f.binding.Identity,"Ip4Config",config.IPv4)==nil{t.Fatal("out of order signal accepted")}
 case "duplicate":if err:=p.Publish(f.ctx,f.binding.Identity,"Config",config.General);err!=nil{t.Fatal(err)};if p.Publish(f.ctx,f.binding.Identity,"Config",config.General)==nil{t.Fatal("duplicate signal accepted")}
 }})}
}

func TestNMVPNWireOwnerLossAndCancellation(t *testing.T){
 for _,mode:=range []string{"reacquire","replacement","plugin reacquire","disconnect","cancelled"}{t.Run(mode,func(t *testing.T){f:=nmFixture(t);p:=f.peer(t);ctx:=f.ctx
 switch mode {case "reacquire","replacement":if _,err:=f.service.conn.ReleaseName(NMName);err!=nil{t.Fatal(err)};owner:=f.service.conn;if mode=="replacement"{owner=nmWireConn(t,f.socket)};if reply,err:=owner.RequestName(NMName,dbus.NameFlagDoNotQueue);err!=nil || reply!=dbus.RequestNameReplyPrimaryOwner{t.Fatal("fixture ownership change failed")}
 deadline:=time.After(2*time.Second);for !f.bus.invalid.Load(){select{case <-deadline:t.Fatal("owner loss did not permanently invalidate bus");case <-time.After(time.Millisecond):}}
 case "plugin reacquire":
 if _,err:=f.bus.conn.ReleaseName(PluginService);err!=nil{t.Fatal(err)}
 if reply,err:=f.bus.conn.RequestName(PluginService,dbus.NameFlagDoNotQueue);err!=nil || reply!=dbus.RequestNameReplyPrimaryOwner{t.Fatal("fixture plugin reacquisition failed")}
 deadline:=time.After(2*time.Second);for !f.bus.invalid.Load(){select{case <-deadline:t.Fatal("plugin release/reacquire did not permanently invalidate bus");case <-time.After(time.Millisecond):}}
 case "disconnect":_ = f.bus.Close()
 case "cancelled":var cancel context.CancelFunc;ctx,cancel=context.WithCancel(ctx);cancel()
 }
 if p.Check(ctx,f.binding.Identity)==nil{t.Fatal("invalid owner/connection/context accepted")}
 config,_:=Encode(f.offer,f.policy);if p.Publish(ctx,f.binding.Identity,"Config",config.General)==nil{t.Fatal("published after invalidation")}
 })}
}

func TestNMVPNWireAbsenceRequiresBothProofs(t *testing.T){
 for _,mode:=range []string{"NM retained","broker residual"}{t.Run(mode,func(t *testing.T){f:=nmFixture(t);p:=f.peer(t);j:=&memoryJournal{trace: new([]string)};controller,err:=NewController(p,j);if err!=nil{t.Fatal(err)};if err=controller.Publish(f.ctx,f.binding.Identity,f.offer,f.policy);err!=nil{t.Fatal(err)}
 f.service.mu.Lock();f.service.retain=mode=="NM retained";f.service.mu.Unlock();f.broker.residual=mode=="broker residual"
 if controller.Stop(f.ctx)==nil{t.Fatal("false cleanup proof accepted")};record,err:=j.Load();if err!=nil || record==nil || record.Phase!="quarantine"{t.Fatal("uncertain cleanup did not preserve quarantine")}
 })}
}

// A socket peer with the correct kernel UID but no SASL response must not leave
// OpenPinnedBus blocked, or leave an authentication worker owning its socket.
func TestNMVPNWireBlockedAuthCancellation(t *testing.T){
 if os.Getenv("MERIDIAN_NMVPN_WIRE_TESTS")!="1"{t.Fatal("explicit wire opt-in required")}
 if _,err:=exec.LookPath("dbus-daemon");err!=nil{t.Fatal("dbus-daemon is required, not skipped")}
 dir,err:=os.MkdirTemp("","meridian-nmvpn-auth-");if err!=nil{t.Fatal(err)}
 defer os.RemoveAll(dir)
 socket:=filepath.Join(dir,"stall")
 listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:socket,Net:"unix"});if err!=nil{t.Fatal(err)}
 defer listener.Close()
 // The Unix listener backlog allows connect then accept without any fixture
 // goroutine. The accepted end intentionally sends no SASL bytes at all.
 raw:=nmRawConn(t,socket);defer raw.Close()
 if err=listener.SetDeadline(time.Now().Add(3*time.Second));err!=nil{t.Fatal(err)}
 server,err:=listener.AcceptUnix();if err!=nil{t.Fatal(err)};defer server.Close()
 // This independent deadline prevents a broken cancellation implementation
 // hanging the suite; returning only at this fallback deadline is a failure.
 if err=raw.SetDeadline(time.Now().Add(3*time.Second));err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),100*time.Millisecond);defer cancel()
 start:=time.Now()
 bus,openErr:=OpenPinnedBus(ctx,raw,BusPin{BusID:strings.Repeat("a",32),Owner:":1.1",BusUID:uint32(os.Geteuid()),OwnerUID:uint32(os.Geteuid())})
 if bus!=nil{_ = bus.Close()}
 if openErr==nil || time.Since(start)>time.Second || ctx.Err()!=context.DeadlineExceeded{t.Fatal("blocked authentication was not cancelled promptly")}
 if _,err=raw.Write([]byte("must-not-send"));!errors.Is(err,net.ErrClosed){t.Fatal("OpenPinnedBus did not close owned socket",err)}
 if err=server.SetReadDeadline(time.Now().Add(time.Second));err!=nil{t.Fatal(err)}
 n,err:=io.Copy(io.Discard,server)
 if err!=nil || n==0{t.Fatal("authentication did not start or peer did not observe EOF",n,err)}
}

func TestNMVPNWireOwnerLossStopsOnlyLocalGeneration(t *testing.T) {
 f:=nmFixture(t);p:=f.peer(t);j:=&memoryJournal{trace:new([]string)}
 controller,err:=NewController(p,j);if err!=nil{t.Fatal(err)}
 if err=controller.Publish(f.ctx,f.binding.Identity,f.offer,f.policy);err!=nil{t.Fatal(err)}
 if _,err=f.service.conn.ReleaseName(NMName);err!=nil{t.Fatal(err)}
 // A synchronous bus round trip orders the owner-change notification before
 // its reply on the plugin connection; the interceptor already latched loss.
 var busID string
 _=f.bus.conn.BusObject().Call("org.freedesktop.DBus.GetId",0).Store(&busID)
 if !f.bus.invalid.Load(){t.Fatal("owner loss not observed")}
 if controller.Stop(f.ctx)==nil{t.Fatal("owner loss reported clean networking")}
 if !f.broker.stopped{t.Fatal("independent generation-bound worker stop omitted")}
 f.service.mu.Lock();count:=f.service.deactivations;f.service.mu.Unlock()
 if count!=0{t.Fatal("NM mutation after owner loss")}
 record,err:=j.Load();if err!=nil || record==nil || record.Phase!="quarantine"{t.Fatal("lost-owner journal not retained")}
}

func TestNMVPNWireUncertainLocalStopForbidsPublication(t *testing.T) {
 f:=nmFixture(t);p:=f.peer(t);f.broker.stopErr=errors.New("synthetic partial local shutdown")
 if p.StopLocal(f.ctx,f.binding.Identity)==nil{t.Fatal("uncertain stop reported success")}
 config,_:=Encode(f.offer,f.policy)
 if p.Publish(f.ctx,f.binding.Identity,"Config",config.General)==nil{t.Fatal("published after uncertain local stop")}
 if p.ProveAbsent(f.ctx,f.binding.Identity)==nil{t.Fatal("local stop alone proved network absence")}
}
