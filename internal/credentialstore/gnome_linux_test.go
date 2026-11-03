//go:build linux && credentialintegration && credentialgnome

package credentialstore

// Real GNOME Keyring compatibility tests, deliberately limited to an explicitly
// authorized disposable CI container. Only synthetic secrets are ever supplied.
import (
 "bytes"
 "context"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "sync"
 "syscall"
 "testing"
 "time"

 "github.com/godbus/dbus/v5"
)

func requireGNOMEContainer(t *testing.T) {
 t.Helper()
 if os.Getenv("MERIDIAN_GNOME_CONTAINER_TESTS") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" { t.Fatal("GNOME tests require explicit disposable GitHub CI container opt-in") }
 if _,err:=os.Stat("/.dockerenv");err!=nil { t.Fatal("GNOME test requires a disposable Docker job container") }
 if os.Getuid()==0 { t.Fatal("GNOME integration tests must run as an unprivileged fixture user") }
}

type gnomeFixture struct { t *testing.T; address,root string; client *dbus.Conn }
type gnomeChild struct { cmd *exec.Cmd; done chan error; once sync.Once }
func(p *gnomeChild)stop(){
 p.once.Do(func(){
  _=p.cmd.Process.Signal(syscall.SIGTERM)
  select{case <-p.done:return;case <-time.After(3*time.Second):}
  _=p.cmd.Process.Kill()
  <-p.done // Wait reaps only this child's PID, never a process-name match.
 })
}
func newGNOMEFixture(t *testing.T)*gnomeFixture{
 t.Helper();requireGNOMEContainer(t)
 address:=privateWireBus(t)
 root,err:=os.MkdirTemp("","meridian-gnome-");if err!=nil{t.Fatal("cannot create isolated keyring directory")}
 t.Cleanup(func(){_=os.RemoveAll(root)})
 for _,dir:=range []string{"home","data","config","cache","runtime","control"}{if err=os.Mkdir(filepath.Join(root,dir),0700);err!=nil{t.Fatal("cannot create isolated keyring paths")}}
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
 client,err:=dbus.Connect(address,dbus.WithContext(ctx));if err!=nil{cancel();t.Fatal("cannot connect to private test bus")}
 t.Cleanup(func(){_=client.Close();cancel()})
 return &gnomeFixture{t,address,root,client}
}
func(f *gnomeFixture)start()*gnomeChild{
 f.t.Helper()
 const executable="/usr/bin/gnome-keyring-daemon"
 if _,err:=os.Stat(executable);err!=nil{f.t.Fatal("official gnome-keyring package is required; no acceptance skip")}
 cmd:=exec.Command(executable,"--foreground","--components=secrets","--control-directory="+filepath.Join(f.root,"control"),"--unlock")
 // The nonempty fixture master password is pipe-only, never an argument,
 // environment variable, config, log, or inherited user credential.
 master:=[]byte("meridian-synthetic-container-master-v1")
 defer clear(master)
 stdin,err:=cmd.StdinPipe();if err!=nil{f.t.Fatal("cannot create fixture master-password pipe")}
 cmd.Stdout=io.Discard;cmd.Stderr=io.Discard
 cmd.Env=[]string{
  "PATH=/usr/bin:/bin","LANG=C.UTF-8",
  "HOME="+filepath.Join(f.root,"home"),
  "XDG_DATA_HOME="+filepath.Join(f.root,"data"),
  "XDG_CONFIG_HOME="+filepath.Join(f.root,"config"),
  "XDG_CACHE_HOME="+filepath.Join(f.root,"cache"),
  "XDG_RUNTIME_DIR="+filepath.Join(f.root,"runtime"),
  "DBUS_SESSION_BUS_ADDRESS="+f.address,
  "DBUS_SYSTEM_BUS_ADDRESS=unix:path="+filepath.Join(f.root,"absent-system-bus"),
 }
 if err:=cmd.Start();err!=nil{f.t.Fatal("cannot start isolated GNOME daemon")}
 child:=&gnomeChild{cmd:cmd,done:make(chan error,1)}
 go func(){child.done<-cmd.Wait()}()
 f.t.Cleanup(child.stop)
 if _,err=stdin.Write(master);err!=nil{_=stdin.Close();f.t.Fatal("cannot pass synthetic master password")};if err=stdin.Close();err!=nil{f.t.Fatal("cannot finish synthetic master password") }
 // Wait for an unlocked default collection, not merely a process or bus name.
 deadline:=time.Now().Add(10*time.Second)
 for time.Now().Before(deadline){
  ctx,cancel:=context.WithTimeout(context.Background(),500*time.Millisecond)
  var owner string
  err:=f.client.BusObject().CallWithContext(ctx,"org.freedesktop.DBus.GetNameOwner",0,"org.freedesktop.secrets").Store(&owner)
  var collection dbus.ObjectPath
  var locked dbus.Variant
  if err==nil{err=f.client.Object(owner,servicePath).CallWithContext(ctx,serviceInterface+".ReadAlias",dbus.FlagNoAutoStart,"default").Store(&collection)}
  if err==nil && collection!="/" && collection.IsValid(){err=f.client.Object(owner,collection).CallWithContext(ctx,"org.freedesktop.DBus.Properties.Get",dbus.FlagNoAutoStart,collectionInterface,"Locked").Store(&locked)}else{err=ErrUnavailable}
  cancel()
  if err==nil && locked.Value()==false{return child}
  time.Sleep(25*time.Millisecond)
 }
 f.t.Fatal("isolated GNOME service did not expose an unlocked default collection")
 return nil
}
func(f *gnomeFixture)provider()systemBus{
 f.t.Helper();ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second);defer cancel();var owner string
 if err:=f.client.BusObject().CallWithContext(ctx,"org.freedesktop.DBus.GetNameOwner",0,"org.freedesktop.secrets").Store(&owner);err!=nil{f.t.Fatal("isolated GNOME owner missing")}
 return systemBus{f.client,owner}
}
func(f *gnomeFixture)restart(child *gnomeChild)*gnomeChild{
 f.t.Helper();child.stop()
 // NameHasOwner must become false before starting another daemon. Never use
 // --replace or connect to a previous daemon's control environment.
 deadline:=time.Now().Add(3*time.Second)
 for time.Now().Before(deadline){
  ctx,cancel:=context.WithTimeout(context.Background(),250*time.Millisecond);var owned bool
  err:=f.client.BusObject().CallWithContext(ctx,"org.freedesktop.DBus.NameHasOwner",0,"org.freedesktop.secrets").Store(&owned);cancel()
  if err==nil && !owned{return f.start()};time.Sleep(20*time.Millisecond)
 }
 f.t.Fatal("previous isolated GNOME owner did not leave the private bus");return nil
}
func gnomeCollection(t *testing.T,b systemBus)dbus.ObjectPath{
 t.Helper();var path dbus.ObjectPath
 if err:=b.call(context.Background(),servicePath,serviceInterface+".ReadAlias",[]any{"default"},&path);err!=nil || path=="/" || !path.IsValid(){t.Fatal("default collection unavailable")};return path
}
// Diagnostics contain only boolean/size metadata, never secret bytes or raw errors.
type gnomeDiagnosticBus struct { systemBus; t *testing.T }
func (b gnomeDiagnosticBus) call(ctx context.Context,path dbus.ObjectPath,method string,args []any,out ...any) error {
 err:=b.systemBus.call(ctx,path,method,args,out...)
 if method==itemInterface+".GetSecret" && err==nil && len(out)==1 {
  if got,ok:=out[0].(*secret);ok {
   b.t.Logf("fixture GetSecret metadata: session_match=%t parameters=%d value_size=%d octet_stream=%t text_plain=%t",got.Session==args[0],len(got.Parameters),len(got.Value),got.ContentType=="application/octet-stream",got.ContentType=="text/plain")
  }
 }
 return err
}
func diagnosticGNOMEStore(t *testing.T,b systemBus)Store{return Store{run:func(ctx context.Context,op operation,key string,value []byte)([]byte,error){return execute(ctx,gnomeDiagnosticBus{b,t},op,key,value)}}}

func assertGNOMEValue(t *testing.T,store Store,r Reference,want []byte){
 t.Helper();out,err:=store.Load(context.Background(),r,UsePassword);defer clear(out)
 if err!=nil || !bytes.Equal(out,want){t.Fatalf("real-provider round trip failed: unavailable=%t not_found=%t locked=%t value_size=%d",err==ErrUnavailable,err==ErrNotFound,err==ErrLocked,len(out))}
}

func TestCredentialGNOMERealLifecycle(t *testing.T){
 f:=newGNOMEFixture(t);child:=f.start();b:=f.provider();store:=diagnosticGNOMEStore(t,b);r:=reference();ctx:=context.Background()
 if _,err:=store.Load(ctx,r,UsePassword);err!=ErrNotFound{t.Fatal("missing GNOME item not classified")}
 first:=[]byte("synthetic-real-provider-password");replacement:=[]byte("synthetic-real-provider-replacement");defer clear(first);defer clear(replacement)
 if err:=store.Save(ctx,r,first,SavePassword);err!=nil{t.Fatal("GNOME create failed",err)}
 assertGNOMEValue(t,store,r,first)
 if err:=store.Save(ctx,r,replacement,SavePassword);err!=nil{t.Fatal("GNOME replacement failed",err)}
 assertGNOMEValue(t,store,r,replacement)
 child=f.restart(child);b=f.provider();store=diagnosticGNOMEStore(t,b)
 assertGNOMEValue(t,store,r,replacement) // Actual provider disk/restart path; not proof of its encryption policy.

 // Deliberately create a second synthetic item using the real provider API,
 // then verify that application lookup refuses to choose between duplicates.
 var output dbus.Variant;var session dbus.ObjectPath
 if err:=b.call(ctx,servicePath,serviceInterface+".OpenSession",[]any{"plain",dbus.MakeVariant("")},&output,&session);err!=nil{t.Fatal("fixture session failed")}
 key,_:=r.key();attrs:=map[string]string{"application":"meridian-vpn","kind":"login-password-v1","reference":key}
 props:=map[string]dbus.Variant{itemInterface+".Label":dbus.MakeVariant("Meridian synthetic integration item"),itemInterface+".Attributes":dbus.MakeVariant(attrs)}
 var duplicate,prompt dbus.ObjectPath
 if err:=b.call(ctx,gnomeCollection(t,b),collectionInterface+".CreateItem",[]any{props,secret{session,[]byte{},first,"application/octet-stream"},false},&duplicate,&prompt);err!=nil || prompt!="/"{t.Fatal("real-provider duplicate fixture failed")}
 _=b.call(ctx,session,"org.freedesktop.Secret.Session.Close",nil)
 if _,err:=store.Load(ctx,r,UsePassword);err!=ErrAmbiguous{t.Fatal("real-provider duplicate was guessed")}
 if err:=b.call(ctx,duplicate,itemInterface+".Delete",nil,&prompt);err!=nil || prompt!="/"{t.Fatal("synthetic duplicate cleanup failed")}
 assertGNOMEValue(t,store,r,replacement)

 collection:=gnomeCollection(t,b);var locked []dbus.ObjectPath
 if err:=b.call(ctx,servicePath,serviceInterface+".Lock",[]any{[]dbus.ObjectPath{collection}},&locked,&prompt);err!=nil || prompt!="/"{t.Fatal("real-provider fixture lock failed")}
 if _,err:=store.Load(ctx,r,UsePassword);err!=ErrLocked{t.Fatal("real locked keyring did not fail closed")}
 if err:=store.Save(ctx,r,first,SavePassword);err!=ErrLocked{t.Fatal("locked real password was overwritten")}
 child=f.restart(child);store=diagnosticGNOMEStore(t,f.provider());assertGNOMEValue(t,store,r,replacement)
 if err:=store.Delete(ctx,r,DeletePassword);err!=nil{t.Fatal("real-provider delete failed",err)}
 if _,err:=store.Load(ctx,r,UsePassword);err!=ErrNotFound{t.Fatal("real-provider deleted item remained")}
 child=f.restart(child);store=diagnosticGNOMEStore(t,f.provider())
 if _,err:=store.Load(ctx,r,UsePassword);err!=ErrNotFound{t.Fatal("real-provider deletion did not persist across restart")}
 child.stop()
}
