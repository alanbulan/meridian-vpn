//go:build linux && credentialintegration && credentialcrossuid

package credentialstore

import (
 "bufio"
 "context"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "sync/atomic"
 "syscall"
 "testing"
 "time"

 "github.com/godbus/dbus/v5"
)

type crossUIDIdentity struct{ uid,gid uint32 }
func crossUIDGuard(t *testing.T){
 t.Helper()
 if os.Getenv("GITHUB_ACTIONS")!="true" || os.Getenv("MERIDIAN_CROSS_UID_TESTS")!="1"{t.Fatal("cross-UID test requires disposable-container opt-in")}
 if _,err:=os.Stat("/.dockerenv");err!=nil{t.Fatal("cross-UID test requires a disposable Docker container")}
}
func crossUIDNumber(t *testing.T,key string)uint32{
 t.Helper();n,err:=strconv.ParseUint(os.Getenv(key),10,32)
 if err!=nil || n==0{t.Fatal("invalid non-root fixture identity")};return uint32(n)
}
func crossUIDIdentityFromEnv(t *testing.T,prefix string)crossUIDIdentity{return crossUIDIdentity{crossUIDNumber(t,prefix+"_UID"),crossUIDNumber(t,prefix+"_GID")}}
func crossUIDDirectory(t *testing.T,path string,uid uint32,mode os.FileMode)os.FileInfo{
 t.Helper();info,err:=os.Lstat(path)
 if err!=nil || !info.IsDir() || info.Mode().Perm()!=mode{t.Fatal("unexpected fixture directory mode")}
 stat,ok:=info.Sys().(*syscall.Stat_t);if !ok || stat.Uid!=uid{t.Fatal("unexpected fixture directory owner")};return info
}

type crossUIDProcess struct{cmd *exec.Cmd;done chan error;reader *bufio.Reader;input io.WriteCloser;once sync.Once}
func(p *crossUIDProcess)stop(){p.once.Do(func(){
 _=p.cmd.Process.Signal(syscall.SIGTERM)
 select{case <-p.done:return;case <-time.After(2*time.Second):}
 _=p.cmd.Process.Kill();<-p.done
})}
func(p *crossUIDProcess)line(t *testing.T)string{
 t.Helper();ready:=make(chan string,1)
 go func(){line,_:=p.reader.ReadString('\n');ready<-strings.TrimSpace(line)}()
 select{case line:=<-ready:return line;case <-time.After(10*time.Second):t.Fatal("fixture control pipe timed out");return ""}
}
func startCrossUIDProcess(t *testing.T,identity crossUIDIdentity,path string,args,env []string)*crossUIDProcess{
 t.Helper();cmd:=exec.Command(path,args...)
 cmd.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:identity.uid,Gid:identity.gid,Groups:[]uint32{}}}
 cmd.Env=env;cmd.Dir="/";cmd.Stderr=io.Discard
 input,err:=cmd.StdinPipe();if err!=nil{t.Fatal("cannot create fixture command pipe")}
 output,err:=cmd.StdoutPipe();if err!=nil{t.Fatal("cannot create fixture response pipe")}
 if err=cmd.Start();err!=nil{t.Fatal("cannot launch unprivileged fixture process")}
 p:=&crossUIDProcess{cmd:cmd,done:make(chan error,1),reader:bufio.NewReader(output),input:input}
 go func(){p.done<-cmd.Wait()}();t.Cleanup(p.stop);return p
}
func crossUIDChildEnv(identity crossUIDIdentity,role,address string,busUID,ownerUID uint32)[]string{
 return []string{"PATH=/usr/bin:/bin","LANG=C.UTF-8","HOME=/nonexistent",
  "GITHUB_ACTIONS=true","MERIDIAN_CROSS_UID_TESTS=1","MERIDIAN_CROSS_UID_ROLE="+role,
  "MERIDIAN_CHILD_UID="+strconv.FormatUint(uint64(identity.uid),10),"MERIDIAN_CHILD_GID="+strconv.FormatUint(uint64(identity.gid),10),
  "MERIDIAN_EXPECT_BUS_UID="+strconv.FormatUint(uint64(busUID),10),"MERIDIAN_EXPECT_OWNER_UID="+strconv.FormatUint(uint64(ownerUID),10),
  "MERIDIAN_CROSS_UID_ADDRESS="+address}
}
func assertRootExecutable(t *testing.T,path string){
 t.Helper()
 for current:=path; ;current=filepath.Dir(current){
  info,err:=os.Lstat(current);if err!=nil || info.Mode()&os.ModeSymlink!=0 || info.Mode().Perm()&0022!=0{t.Fatal("root test executable path must not be writable by fixture users")}
  stat,ok:=info.Sys().(*syscall.Stat_t);if !ok || stat.Uid!=0{t.Fatal("root test executable path must be root-owned")}
  if current=="/"{break}
 }
}
func TestCredentialCrossUIDSupervisor(t *testing.T){
 crossUIDGuard(t)
 if os.Getuid()!=0 || os.Geteuid()!=0 || os.Getenv("MERIDIAN_CROSS_UID_ROLE")!="supervisor"{t.Fatal("cross-UID supervisor requires the root container runner")}
 a,b:=crossUIDIdentityFromEnv(t,"MERIDIAN_A"),crossUIDIdentityFromEnv(t,"MERIDIAN_B")
 if a.uid==b.uid || a.gid==b.gid{t.Fatal("fixture users and primary groups must differ")}
 executable,err:=os.Executable();if err!=nil{t.Fatal("cannot resolve test executable")};assertRootExecutable(t,executable)
 crossUIDDirectory(t,"/run",0,0755);crossUIDDirectory(t,"/run/user",0,0755)
 for _,scenario:=range []struct{name string;bus,owner crossUIDIdentity;positive bool}{
  {"same_uid_control",a,a,true},{"wrong_socket_peer",b,a,false},{"wrong_service_owner",a,b,false},
 }{t.Run(scenario.name,func(t *testing.T){
  runtimeDir:="/run/user/"+strconv.FormatUint(uint64(a.uid),10)
  // Exclusive mkdir is mandatory for every case; existing entries are untouched.
  if err:=os.Mkdir(runtimeDir,0700);err!=nil{t.Fatal("fixture runtime already exists or cannot be created")}
  directoryInfo:=crossUIDDirectory(t,runtimeDir,0,0700)
  socketPath:=filepath.Join(runtimeDir,"bus");var socketInfo os.FileInfo
  t.Cleanup(func(){
   current,err:=os.Lstat(runtimeDir)
   if err!=nil || !os.SameFile(directoryInfo,current){t.Error("refusing cleanup of changed runtime directory");return}
   if socket,err:=os.Lstat(socketPath);err==nil{
    if socketInfo==nil || socket.Mode()&os.ModeSocket==0 || !os.SameFile(socketInfo,socket){t.Error("refusing cleanup of changed socket");return}
    if err=os.Remove(socketPath);err!=nil{t.Error("cannot remove recorded fixture socket");return}
   }else if !os.IsNotExist(err){t.Error("cannot inspect fixture socket");return}
   if err=os.Remove(runtimeDir);err!=nil{t.Error("fixture runtime is not empty; require container disposal")}
  })
  // Root-owned config directory is readable/traversable but never writable by A/B.
  control,err:=os.MkdirTemp("/run","meridian-crossuid-control-");if err!=nil{t.Fatal("cannot create private fixture config")}
  t.Cleanup(func(){_=os.RemoveAll(control)})
  if err=os.Chmod(control,0755);err!=nil{t.Fatal("cannot prepare fixture config directory")}
  address:="unix:path="+socketPath
  config:=fmt.Sprintf(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>%s</listen><auth>EXTERNAL</auth>
<policy context="default"><deny user="*"/><allow user="%d"/><allow user="%d"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy>
<limit name="max_message_size">65536</limit><limit name="max_incoming_bytes">262144</limit><limit name="max_outgoing_bytes">262144</limit></busconfig>`,address,a.uid,b.uid)
  configPath:=filepath.Join(control,"bus.conf")
  if err=os.WriteFile(configPath,[]byte(config),0444);err!=nil{t.Fatal("cannot write isolated bus configuration")}
  // The root runner retains umask 077; explicitly grant fixture read access.
  if err=os.Chmod(configPath,0444);err!=nil{t.Fatal("cannot expose read-only fixture bus configuration")}
  if err=os.Chown(runtimeDir,int(scenario.bus.uid),int(scenario.bus.gid));err!=nil{t.Fatal("cannot prepare fixture bus directory")}
  daemon:=startCrossUIDProcess(t,scenario.bus,"/usr/bin/dbus-daemon",[]string{"--nofork","--nopidfile","--nosyslog","--config-file="+configPath,"--print-address=1"},[]string{"PATH=/usr/bin:/bin","LANG=C","HOME=/nonexistent"})
  if !strings.HasPrefix(daemon.line(t),address){t.Fatal("private cross-UID bus failed readiness")}
  socketInfo,err=os.Lstat(socketPath);if err!=nil || socketInfo.Mode()&os.ModeSocket==0{t.Fatal("fixture bus socket missing")}
  if err=os.Chown(socketPath,int(a.uid),int(b.gid));err!=nil{t.Fatal("cannot assign fixture socket group")}
  if err=os.Chmod(socketPath,0660);err!=nil{t.Fatal("cannot constrain fixture socket")}
  if err=os.Chown(runtimeDir,int(a.uid),int(b.gid));err!=nil{t.Fatal("cannot assign fixture runtime group")}
  if err=os.Chmod(runtimeDir,0710);err!=nil{t.Fatal("cannot open temporary fixture group traversal")}
  service:=startCrossUIDProcess(t,scenario.owner,executable,[]string{"-test.run=^TestCredentialCrossUIDHelper$"},crossUIDChildEnv(scenario.owner,"service",address,scenario.bus.uid,scenario.owner.uid))
  if service.line(t)!="ready"{t.Fatal("cross-UID Secret Service fixture failed readiness")}
  if err=os.Chmod(runtimeDir,0700);err!=nil{t.Fatal("cannot close fixture group traversal")}
  if err=os.Chown(runtimeDir,int(a.uid),int(a.gid));err!=nil{t.Fatal("cannot restore fixture runtime group")}
  crossUIDDirectory(t,runtimeDir,a.uid,0700)
  role:="negative";want:="0";if scenario.positive{role="positive";want="1"}
  client:=startCrossUIDProcess(t,a,executable,[]string{"-test.run=^TestCredentialCrossUIDHelper$"},crossUIDChildEnv(a,role,address,scenario.bus.uid,scenario.owner.uid))
  if client.line(t)!="checked"{t.Fatal("client identity preconditions or rejection checks failed")}
  // Store calls complete before this acknowledgement, then count is read from
  // the already-running service's private control pipe, not another bus session.
  if _,err=io.WriteString(service.input,"count\n");err!=nil{t.Fatal("cannot query fixture call count")}
  if service.line(t)!=want{t.Fatal("unexpected Secret Service call count")}
 })}
}

type crossUIDService struct{calls atomic.Int32}
func(s *crossUIDService)SearchItems(map[string]string)([]dbus.ObjectPath,[]dbus.ObjectPath,*dbus.Error){s.calls.Add(1);return []dbus.ObjectPath{},[]dbus.ObjectPath{},nil}
func TestCredentialCrossUIDHelper(t *testing.T){
 crossUIDGuard(t)
 identity:=crossUIDIdentityFromEnv(t,"MERIDIAN_CHILD")
 groups,err:=os.Getgroups()
 if err!=nil || len(groups)!=0 || os.Getuid()!=int(identity.uid) || os.Geteuid()!=int(identity.uid) || os.Getgid()!=int(identity.gid) || os.Getegid()!=int(identity.gid){t.Fatal("fixture child did not drop all supplementary privileges")}
 role:=os.Getenv("MERIDIAN_CROSS_UID_ROLE")
 if role!="service" && role!="positive" && role!="negative"{t.Fatal("unknown cross-UID fixture role")}
 address:=os.Getenv("MERIDIAN_CROSS_UID_ADDRESS")
 expectedBus:=crossUIDNumber(t,"MERIDIAN_EXPECT_BUS_UID");expectedOwner:=crossUIDNumber(t,"MERIDIAN_EXPECT_OWNER_UID")
 ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second);defer cancel()
 conn,err:=dbus.Connect(address,dbus.WithContext(ctx));if err!=nil{t.Fatal("fixture must authenticate before testing guards")};defer conn.Close()
 if role=="service"{
  service:=&crossUIDService{}
  if err=conn.Export(service,servicePath,serviceInterface);err!=nil{t.Fatal("cannot export counting service")}
  reply,err:=conn.RequestName("org.freedesktop.secrets",dbus.NameFlagDoNotQueue);if err!=nil || reply!=dbus.RequestNameReplyPrimaryOwner{t.Fatal("cannot own fixture service name")}
  fmt.Println("ready")
  scanner:=bufio.NewScanner(os.Stdin)
  for scanner.Scan(){if scanner.Text()!="count"{t.Fatal("unknown fixture control command")};fmt.Println(service.calls.Load())}
  return
 }
 socketPath:="/run/user/"+strconv.Itoa(os.Getuid())+"/bus"
 if address!="unix:path="+socketPath{t.Fatal("client address must be its isolated production path")}
 crossUIDDirectory(t,filepath.Dir(socketPath),identity.uid,0700)
 rawConn,err:=net.DialTimeout("unix",socketPath,3*time.Second);if err!=nil{t.Fatal("cannot independently inspect fixture socket")}
 defer rawConn.Close();unix,ok:=rawConn.(*net.UnixConn);if !ok{t.Fatal("fixture socket is not Unix")}
 raw,err:=unix.SyscallConn();if err!=nil{t.Fatal("cannot inspect fixture peer")}
 var peer *syscall.Ucred;var peerErr error
 if err=raw.Control(func(fd uintptr){peer,peerErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)});err!=nil || peerErr!=nil || peer==nil || peer.Uid!=expectedBus{t.Fatal("fixture socket peer UID did not match the scenario")}
 var owner string;var ownerUID uint32
 if err=conn.BusObject().CallWithContext(ctx,"org.freedesktop.DBus.GetNameOwner",0,"org.freedesktop.secrets").Store(&owner);err!=nil{t.Fatal("fixture service owner is not ready")}
 if err=conn.BusObject().CallWithContext(ctx,"org.freedesktop.DBus.GetConnectionUnixUser",0,owner).Store(&ownerUID);err!=nil || ownerUID!=expectedOwner{t.Fatal("fixture service owner UID did not match the scenario")}
 store:=NewSystem();reference:=Reference{ProfileID:"synthetic-cross-uid",Gateway:"https://synthetic.example",Protocol:"anyconnect",Account:"synthetic"}
 value,err:=store.Load(ctx,reference,UsePassword);defer clear(value)
 if role=="positive"{
  if expectedBus!=identity.uid || expectedOwner!=identity.uid || !errors.Is(err,ErrNotFound) || len(value)!=0{t.Fatal("same-UID positive control failed")}
 }else{
  if expectedBus==identity.uid && expectedOwner==identity.uid{t.Fatal("negative scenario has no mismatched UID")}
  if !errors.Is(err,ErrUnavailable) || len(value)!=0{t.Fatal("cross-UID load was not rejected without data")}
  password:=[]byte("synthetic-cross-uid-never-sent");defer clear(password)
  if err=store.Save(ctx,reference,password,SavePassword);!errors.Is(err,ErrUnavailable){t.Fatal("cross-UID save was not rejected")}
  if err=store.Delete(ctx,reference,DeletePassword);!errors.Is(err,ErrUnavailable){t.Fatal("cross-UID delete was not rejected")}
 }
 fmt.Println("checked")
 // Parent owns termination; keep the process alive so all cleanup paths use
 // the exact process handle instead of risking a reused numeric PID.
 _,_=io.Copy(io.Discard,os.Stdin)
}
