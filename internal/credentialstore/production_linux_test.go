//go:build linux && credentialintegration && credentialgnome && credentialproduction

package credentialstore

// This suite is deliberately separate from the portable fixture. It exercises
// the hard-coded production bus path only inside a freshly provisioned container.
import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strconv"
 "syscall"
 "testing"
)

func TestCredentialProductionEntry(t *testing.T){
 requireGNOMEContainer(t)
 if os.Getenv("MERIDIAN_PRODUCTION_CONTAINER_TESTS")!="1" || os.Getenv("MERIDIAN_FIXTURE_UID")!=strconv.Itoa(os.Getuid()){
  t.Fatal("production entry requires its dedicated disposable-container runner")
 }
 runtimeDir:="/run/user/"+strconv.Itoa(os.Getuid())
 info,err:=os.Lstat(runtimeDir)
 if err!=nil || !info.IsDir() || info.Mode().Perm()!=0700{t.Fatal("runner did not provision a private runtime directory")}
 stat,ok:=info.Sys().(*syscall.Stat_t)
 if !ok || stat.Uid!=uint32(os.Getuid()){t.Fatal("runtime directory has an unexpected owner")}
 entries,err:=os.ReadDir(runtimeDir)
 if err!=nil || len(entries)!=0{t.Fatal("fixture runtime must start empty; never use an existing session")}
 // Even misleading inherited selectors must not redirect the production entry.
 absent:="unix:path="+filepath.Join(t.TempDir(),"absent-bus")
 t.Setenv("DBUS_SESSION_BUS_ADDRESS",absent)
 t.Setenv("DBUS_SYSTEM_BUS_ADDRESS",absent)
 t.Setenv("XDG_RUNTIME_DIR",t.TempDir())
 store:=NewSystem()
 reference:=Reference{ProfileID:"synthetic-production-entry",Gateway:"https://synthetic.example",Protocol:"anyconnect",Account:"synthetic-account"}
 unavailable:=func(stage string){
  t.Helper()
  value,loadErr:=store.Load(context.Background(),reference,UsePassword)
  defer clear(value)
  if !errors.Is(loadErr,ErrUnavailable) || len(value)!=0{t.Fatalf("production entry did not fail closed at %s",stage)}
 }
 unavailable("missing bus")
 // Configuration lives in a different temporary directory. Only the socket is
 // created in /run/user/<fixture uid>; no activation directories are configured.
 socketPath:=filepath.Join(runtimeDir,"bus")
 var socketInfo os.FileInfo
 // Registered before the bus cleanup, so its exact child is stopped/reaped
 // first. SIGKILL may leave a socket entry; unlink only the inode we created.
 t.Cleanup(func(){
  current,statErr:=os.Lstat(socketPath)
  if os.IsNotExist(statErr){return}
  if statErr!=nil || socketInfo==nil || current.Mode()&os.ModeSocket==0 || !os.SameFile(socketInfo,current){t.Error("refusing cleanup of unexpected fixture socket");return}
  if removeErr:=os.Remove(socketPath);removeErr!=nil{t.Error("cannot unlink fixture socket")}
 })
 address:=privateWireBusAt(t,"unix:path="+socketPath,t.TempDir())
 socketInfo,err=os.Lstat(socketPath)
 if err!=nil || socketInfo.Mode()&os.ModeSocket==0{t.Fatal("fixture bus did not create its socket")}
 unavailable("missing Secret Service owner")
 f:=newGNOMEFixtureAt(t,address)
 child:=f.start()
 value,err:=store.Load(context.Background(),reference,UsePassword);clear(value)
 if !errors.Is(err,ErrNotFound){t.Fatal("production entry did not reach the fresh GNOME service")}
 password:=[]byte("synthetic-production-entry-password")
 defer clear(password)
 if err=store.Save(context.Background(),reference,password,SavePassword);err!=nil{t.Fatal("production entry save failed")}
 assertGNOMEValue(t,store,reference,password)
 // The real socket and service remain available during these checks. Therefore
 // rejection is attributable to the production directory permission guard.
 for _,mode:=range []os.FileMode{0750,0755,0770,0777}{
  func(){
   if err=os.Chmod(runtimeDir,mode);err!=nil{t.Fatal("cannot set fixture-only directory mode")}
   defer func(){if restoreErr:=os.Chmod(runtimeDir,0700);restoreErr!=nil{t.Error("cannot restore fixture-only directory mode")}}()
   unavailable("unsafe directory permissions")
   if saveErr:=store.Save(context.Background(),reference,[]byte("synthetic-must-not-replace"),SavePassword);!errors.Is(saveErr,ErrUnavailable){t.Fatal("unsafe directory allowed a write")}
   if deleteErr:=store.Delete(context.Background(),reference,DeletePassword);!errors.Is(deleteErr,ErrUnavailable){t.Fatal("unsafe directory allowed a deletion")}
  }()
  assertGNOMEValue(t,store,reference,password)
 }
 if err=store.Delete(context.Background(),reference,DeletePassword);err!=nil{t.Fatal("production entry delete failed")}
 value,err=store.Load(context.Background(),reference,UsePassword);clear(value)
 if !errors.Is(err,ErrNotFound){t.Fatal("production entry deletion did not persist")}
 child.stop()
 unavailable("departed service owner")
}
