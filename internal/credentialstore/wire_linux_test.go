//go:build linux && credentialintegration

package credentialstore

// These tests use a real private D-Bus daemon and an in-memory protocol fixture.
// They never connect to a login session bus or an installed keyring service.
import (
 "bufio"
 "bytes"
 "context"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/godbus/dbus/v5"
)

func privateWireBus(t *testing.T) string {
 t.Helper()
 if os.Getenv("MERIDIAN_CREDENTIAL_WIRE_TESTS") != "1" { t.Fatal("wire tests require explicit runner opt-in") }
 executable, err := exec.LookPath("dbus-daemon")
 if err != nil { t.Fatal("dbus-daemon is required, not a skipped acceptance test") }
 dir, err := os.MkdirTemp("", "meridian-secret-wire-")
 if err != nil { t.Fatal("cannot create isolated fixture directory") }
 t.Cleanup(func(){ _ = os.RemoveAll(dir) })
 address := "unix:path="+filepath.Join(dir,"bus")
 // No standard_session_servicedirs, include, servicehelper, or TCP listener.
 config := `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>`+address+`</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>
<limit name="max_message_size">65536</limit><limit name="max_incoming_bytes">262144</limit><limit name="max_outgoing_bytes">262144</limit>
</busconfig>`
 path := filepath.Join(dir,"bus.conf")
 if err=os.WriteFile(path,[]byte(config),0600);err!=nil { t.Fatal("cannot write fixture-only bus config") }
 cmd:=exec.Command(executable,"--nofork","--nopidfile","--nosyslog","--config-file="+path,"--print-address=1")
 cmd.Env=[]string{"PATH=/usr/bin:/bin","LANG=C","HOME="+dir}
 cmd.Stderr=io.Discard
 stdout,err:=cmd.StdoutPipe();if err!=nil { t.Fatal("cannot open daemon readiness pipe") }
 if err=cmd.Start();err!=nil { t.Fatal("cannot start isolated dbus-daemon") }
 t.Cleanup(func(){ _=cmd.Process.Kill(); _=cmd.Wait() })
 ready:=make(chan string,1)
 go func(){ line,_:=bufio.NewReader(stdout).ReadString('\n');ready<-line }()
 select {
 case line:=<-ready:
  if !strings.HasPrefix(line,address) { t.Fatal("isolated daemon failed readiness") }
 case <-time.After(5*time.Second): t.Fatal("isolated daemon startup timed out")
 }
 return address
}

func wireConnection(t *testing.T,address string)*dbus.Conn {
 t.Helper()
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 conn,err:=dbus.Connect(address,dbus.WithContext(ctx))
 if err!=nil { cancel();t.Fatal("cannot connect to private fixture bus") }
 t.Cleanup(func(){ _=conn.Close();cancel() })
 return conn
}

type wireRecord struct { attrs map[string]string; value []byte; locked bool }
type wireService struct {
 mu sync.Mutex
 conn *dbus.Conn
 records map[dbus.ObjectPath]*wireRecord
 next int
 collectionLocked bool
 searches int
 entered chan struct{}
 unblock chan struct{}
}

func installWireService(t *testing.T,address string)*wireService {
 t.Helper()
 s:=&wireService{conn:wireConnection(t,address),records:map[dbus.ObjectPath]*wireRecord{}}
 for _,entry:=range []struct{object any;path dbus.ObjectPath;iface string}{
  {s,servicePath,serviceInterface},
  {&wireCollection{s},"/collection",collectionInterface},
  {&wireCollection{s},"/collection","org.freedesktop.DBus.Properties"},
  {&wireSession{},"/session","org.freedesktop.Secret.Session"},
 } { if err:=s.conn.Export(entry.object,entry.path,entry.iface);err!=nil { t.Fatal("cannot export fixture protocol") } }
 reply,err:=s.conn.RequestName("org.freedesktop.secrets",dbus.NameFlagDoNotQueue)
 if err!=nil || reply!=dbus.RequestNameReplyPrimaryOwner { t.Fatal("fixture cannot own isolated service name") }
 t.Cleanup(func(){s.mu.Lock();defer s.mu.Unlock();for _,r:=range s.records{clear(r.value)}})
 return s
}

func (s *wireService) SearchItems(attrs map[string]string)([]dbus.ObjectPath,[]dbus.ObjectPath,*dbus.Error) {
 s.mu.Lock();defer s.mu.Unlock();s.searches++
 unlocked,locked:=[]dbus.ObjectPath{},[]dbus.ObjectPath{}
 for path,r:=range s.records {
  match:=true;for k,v:=range attrs {if r.attrs[k]!=v {match=false;break}}
  if match {if r.locked {locked=append(locked,path)} else {unlocked=append(unlocked,path)}}
 }
 return unlocked,locked,nil
}
func(s *wireService)ReadAlias(alias string)(dbus.ObjectPath,*dbus.Error){if alias!="default"{return "/",nil};return "/collection",nil}
func(s *wireService)OpenSession(algorithm string,input dbus.Variant)(dbus.Variant,dbus.ObjectPath,*dbus.Error){
 if algorithm!="plain" || input.Value()!="" {return dbus.MakeVariant(""),"/",&dbus.Error{Name:"org.freedesktop.DBus.Error.NotSupported"}}
 return dbus.MakeVariant(""),"/session",nil
}
type wireSession struct{}
func(*wireSession)Close()*dbus.Error{return nil}
type wireCollection struct{s *wireService}
func(c *wireCollection)Get(iface,property string)(dbus.Variant,*dbus.Error){
 c.s.mu.Lock();defer c.s.mu.Unlock()
 if iface!=collectionInterface || property!="Locked" {return dbus.MakeVariant(false),&dbus.Error{Name:"org.freedesktop.DBus.Error.InvalidArgs"}}
 return dbus.MakeVariant(c.s.collectionLocked),nil
}
func(c *wireCollection)CreateItem(props map[string]dbus.Variant,value secret,replace bool)(dbus.ObjectPath,dbus.ObjectPath,*dbus.Error){
 c.s.mu.Lock();defer c.s.mu.Unlock();defer clear(value.Value)
 if c.s.collectionLocked{return "/","/",&dbus.Error{Name:"org.freedesktop.Secret.Error.IsLocked"}}
 attrs,ok:=props[itemInterface+".Attributes"].Value().(map[string]string)
 if !ok || replace || value.Session!="/session" {return "/","/",&dbus.Error{Name:"org.freedesktop.DBus.Error.InvalidArgs"}}
 c.s.next++;path:=dbus.ObjectPath(fmt.Sprintf("/item/%d",c.s.next))
 r:=&wireRecord{attrs:attrs,value:append([]byte(nil),value.Value...)}
 if err:=c.s.conn.Export(&wireItem{c.s,path},path,itemInterface);err!=nil{clear(r.value);return "/","/",&dbus.Error{Name:"org.freedesktop.DBus.Error.Failed"}}
 c.s.records[path]=r
 return path,"/",nil
}
type wireItem struct{s *wireService;path dbus.ObjectPath}
func(i *wireItem)GetSecret(session dbus.ObjectPath)(secret,*dbus.Error){
 i.s.mu.Lock()
 entered,unblock:=i.s.entered,i.s.unblock
 i.s.mu.Unlock()
 if entered!=nil {select{case entered<-struct{}{}:default:};<-unblock}
 i.s.mu.Lock();defer i.s.mu.Unlock()
 r,ok:=i.s.records[i.path];if !ok{return secret{},&dbus.Error{Name:"org.freedesktop.Secret.Error.NoSuchObject"}}
 if r.locked{return secret{},&dbus.Error{Name:"org.freedesktop.Secret.Error.IsLocked"}}
 return secret{session,[]byte{},append([]byte(nil),r.value...),"application/octet-stream"},nil
}
func(i *wireItem)SetSecret(value secret)*dbus.Error{
 i.s.mu.Lock();defer i.s.mu.Unlock();defer clear(value.Value)
 r,ok:=i.s.records[i.path];if !ok{return &dbus.Error{Name:"org.freedesktop.Secret.Error.NoSuchObject"}}
 if r.locked{return &dbus.Error{Name:"org.freedesktop.Secret.Error.IsLocked"}}
 clear(r.value);r.value=append([]byte(nil),value.Value...);return nil
}
func(i *wireItem)Delete()(dbus.ObjectPath,*dbus.Error){
 i.s.mu.Lock();defer i.s.mu.Unlock()
 r,ok:=i.s.records[i.path];if !ok{return "/",&dbus.Error{Name:"org.freedesktop.Secret.Error.NoSuchObject"}}
 if r.locked{return "/",&dbus.Error{Name:"org.freedesktop.Secret.Error.IsLocked"}}
 clear(r.value);delete(i.s.records,i.path);return "/",nil
}
func wireProvider(t *testing.T,address string)systemBus{
 t.Helper();conn:=wireConnection(t,address);var owner string
 if err:=conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner",0,"org.freedesktop.secrets").Store(&owner);err!=nil{t.Fatal("cannot resolve fixture owner")}
 return systemBus{conn,owner}
}
func wireStore(b systemBus)Store{return Store{run:func(ctx context.Context,op operation,key string,value []byte)([]byte,error){return execute(ctx,b,op,key,value)}}}

func TestCredentialWireLifecycleAndStates(t *testing.T){
 address:=privateWireBus(t);service:=installWireService(t,address);store:=wireStore(wireProvider(t,address));ctx:=context.Background();r:=reference()
 if _,err:=store.Load(ctx,r,UsePassword);err!=ErrNotFound{t.Fatal("missing record state incorrect")}
 if err:=store.Save(ctx,r,[]byte("synthetic-wire-password"),SavePassword);err!=nil{t.Fatal("wire create failed",err)}
 out,err:=store.Load(ctx,r,UsePassword);if err!=nil || !bytes.Equal(out,[]byte("synthetic-wire-password")){t.Fatal("wire round trip failed")};clear(out)
 if err=store.Save(ctx,r,[]byte("synthetic-wire-replacement"),SavePassword);err!=nil{t.Fatal("wire replace failed",err)}
 out,err=store.Load(ctx,r,UsePassword);if err!=nil || !bytes.Equal(out,[]byte("synthetic-wire-replacement")){t.Fatal("wire replacement round trip failed")};clear(out)
 service.mu.Lock();for _,record:=range service.records{record.locked=true};service.mu.Unlock()
 if _,err=store.Load(ctx,r,UsePassword);err!=ErrLocked{t.Fatal("locked item state incorrect")}
 if err=store.Save(ctx,r,[]byte("synthetic"),SavePassword);err!=ErrLocked{t.Fatal("locked item overwritten")}
 service.mu.Lock();for _,record:=range service.records{record.locked=false};service.mu.Unlock()
 if err=store.Delete(ctx,r,DeletePassword);err!=nil{t.Fatal("wire delete failed")}
 if _,err=store.Load(ctx,r,UsePassword);err!=ErrNotFound{t.Fatal("deleted item still found")}
 service.mu.Lock();service.collectionLocked=true;service.mu.Unlock()
 if err=store.Save(ctx,r,[]byte("synthetic"),SavePassword);err!=ErrLocked{t.Fatal("locked collection accepted create")}
}

func TestCredentialWireDuplicateAndUnknownObject(t *testing.T){
 address:=privateWireBus(t);s:=installWireService(t,address);b:=wireProvider(t,address);store:=wireStore(b);ctx:=context.Background();r:=reference()
 if err:=store.Save(ctx,r,[]byte("synthetic"),SavePassword);err!=nil{t.Fatal(err)}
 s.mu.Lock();for _,record:=range s.records{s.records["/duplicate"]=&wireRecord{attrs:record.attrs,value:[]byte("synthetic-duplicate")};break};s.mu.Unlock()
 if _,err:=store.Load(ctx,r,UsePassword);err!=ErrAmbiguous{t.Fatal("duplicate was guessed")}
 s.mu.Lock();delete(s.records,"/duplicate");s.mu.Unlock()
 var result secret
 err:=b.call(ctx,"/item/1",itemInterface+".GetSecret",[]any{dbus.ObjectPath("/session")},&result)
 clear(result.Value);if err!=nil{t.Fatal("known object failed")}
 if err=store.Delete(ctx,r,DeletePassword);err!=nil{t.Fatal(err)}
 if err=b.call(ctx,"/item/1",itemInterface+".GetSecret",[]any{dbus.ObjectPath("/session")},&result);err!=ErrNotFound{t.Fatal("unknown object not classified")}
}

func TestCredentialWireCancellation(t *testing.T){
 address:=privateWireBus(t);s:=installWireService(t,address);store:=wireStore(wireProvider(t,address));r:=reference()
 if err:=store.Save(context.Background(),r,[]byte("synthetic"),SavePassword);err!=nil{t.Fatal(err)}
 entered,unblock:=make(chan struct{},1),make(chan struct{})
 s.mu.Lock();s.entered=entered;s.unblock=unblock;s.mu.Unlock()
 defer close(unblock)
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
 done:=make(chan error,1)
 go func(){out,err:=store.Load(ctx,r,UsePassword);clear(out);done<-err}()
 select{case <-entered:case <-time.After(3*time.Second):t.Fatal("fixture did not receive read")}
 select{case err:=<-done:if err!=context.DeadlineExceeded{t.Fatal("deadline not preserved")};case <-time.After(3*time.Second):t.Fatal("wire read did not cancel")}
}

func TestCredentialWireOwnerReplacement(t *testing.T){
 address:=privateWireBus(t);old:=installWireService(t,address);pinned:=wireProvider(t,address)
 if _,err:=old.conn.ReleaseName("org.freedesktop.secrets");err!=nil{t.Fatal("cannot release fixture owner")}
 replacement:=installWireService(t,address)
 // A live pinned owner stays pinned even when the well-known name changes.
 if _,err:=execute(context.Background(),pinned,load,"digest",nil);err!=ErrNotFound{t.Fatal("pinned original owner no longer reached")}
 replacement.mu.Lock();calls:=replacement.searches;replacement.mu.Unlock();if calls!=0{t.Fatal("secret operation followed replacement owner")}
 _=old.conn.Close()
 if _,err:=execute(context.Background(),pinned,load,"digest",nil);err!=ErrUnavailable{t.Fatal("departed owner did not fail closed")}
 replacement.mu.Lock();calls=replacement.searches;replacement.mu.Unlock();if calls!=0{t.Fatal("departed owner operation reached replacement")}
}
