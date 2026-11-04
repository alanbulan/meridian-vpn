package macosvpn

import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"
)

type fakeConnection struct { state Status; startErr,stopErr error; starts,stops,closes int; disconnectOnStop bool; deferredStart bool; afterStart []Status }
func (f *fakeConnection) status() Status {
 if f.starts > 0 && len(f.afterStart) > 0 { f.state=f.afterStart[0]; f.afterStart=f.afterStart[1:] }
 return f.state
}
func (f *fakeConnection) start() error { f.starts++; if f.startErr==nil && !f.deferredStart { f.state=Connecting }; return f.startErr }
func (f *fakeConnection) stop() error { f.stops++; if f.disconnectOnStop && f.stopErr==nil { f.state=Disconnected }; return f.stopErr }
func (f *fakeConnection) close() { f.closes++ }
func fakeOpen(f *fakeConnection) func(string)(connection,error) { return func(string)(connection,error){return f,nil} }
func TestAuthorizationBeforeOpening(t *testing.T) {
 f:=&fakeConnection{}
 _,err:=startExisting(context.Background(),"service-id",false,func(string)(connection,error){t.Fatal("opened without approval");return f,nil})
 if !errors.Is(err,ErrAuthorization) {t.Fatal(err)}
}
func TestRejectInvalidIDs(t *testing.T) {
 for _,id:=range []string{"","service name","../vpn","vpn\x00tail","VPN\n","你好"} {
  _,err:=startExisting(context.Background(),id,true,func(string)(connection,error){t.Fatal("opened invalid ID");return nil,nil})
  if err==nil {t.Fatalf("accepted %q",id)}
 }
}
func TestRefuseAdoptingActiveServices(t *testing.T) {
 for _,state:=range []Status{Invalid,Connecting,Connected,Disconnecting,99} {
  f:=&fakeConnection{state:state}
  _,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f))
  if !errors.Is(err,ErrBusy)||f.starts!=0||f.stops!=0||f.closes!=1 {t.Fatalf("state=%d err=%v fake=%+v",state,err,f)}
 }
}
func TestStartIsNotConnected(t *testing.T) {
 f:=&fakeConnection{}
 s,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));if err!=nil {t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Millisecond);defer cancel()
 if err=s.WaitConnected(ctx);!errors.Is(err,context.DeadlineExceeded) {t.Fatal(err)}
 if f.closes!=0 {t.Fatal("lost native reference on timeout")}
 f.state=Connected
 if err=s.WaitConnected(context.Background());err!=nil {t.Fatal(err)}
 f.disconnectOnStop=true
 if err=s.Stop(context.Background());err!=nil {t.Fatal(err)}
 if f.closes!=1 {t.Fatal("did not release disconnected reference")}
 if _,err=s.Status();!errors.Is(err,ErrClosed) {t.Fatal(err)}
 if err=s.Stop(context.Background());err!=nil||f.closes!=1 {t.Fatal("stop is not idempotent")}
}
func TestCleanupUncertainRetainsReference(t *testing.T) {
 f:=&fakeConnection{}
 s,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));if err!=nil {t.Fatal(err)}
 f.state=Connected
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 if err=s.Stop(ctx);!errors.Is(err,ErrCleanup)||!errors.Is(err,context.Canceled) {t.Fatal(err)}
 if f.closes!=0 {t.Fatal("released unconfirmed connection")}
 if err=s.WaitConnected(context.Background());err==nil {t.Fatal("reported connected after stop")}
 f.disconnectOnStop=true
 if err=s.Stop(context.Background());err!=nil {t.Fatal(err)}
 if f.closes!=1 {t.Fatal("retry did not close")}
}
func TestStartAndStopFailures(t *testing.T) {
 f:=&fakeConnection{startErr:errors.New("denied")}
 if _,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));err==nil||f.closes!=1 {t.Fatal("start failure leaked reference")}
 f=&fakeConnection{stopErr:errors.New("denied")}
 s,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));if err!=nil {t.Fatal(err)}
 if err=s.Stop(context.Background());!errors.Is(err,ErrCleanup)||f.closes!=0 {t.Fatal("stop failure did not retain uncertainty")}
}
func TestCanceledStartNeverOpens(t *testing.T) {
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 _,err:=startExisting(ctx,"service-id",true,func(string)(connection,error){t.Fatal("opened for canceled request");return nil,nil})
 if !errors.Is(err,context.Canceled) {t.Fatal(err)}
}

// The scripted status sequence deterministically models asynchronous OS state
// propagation; start returns while the service is still Disconnected. No real
// system service or timing-dependent background mutation is involved.
func TestAsyncStartAllowsInitialDisconnected(t *testing.T) {
 for _,states:=range [][]Status{
  {Disconnected,Disconnected,Connecting,Connected},
  {Disconnected,Disconnected,Connected}, // polling may miss Connecting
 } {
  f:=&fakeConnection{deferredStart:true,afterStart:states,disconnectOnStop:true}
  s,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));if err!=nil {t.Fatal(err)}
  s.poll=time.Microsecond
  ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
  err=s.WaitConnected(ctx);cancel()
  if err!=nil {t.Fatalf("async start incorrectly rejected: %v",err)}
  if f.state!=Connected||f.closes!=0 {t.Fatal("reported success without Connected or lost reference")}
  if err=s.Stop(context.Background());err!=nil {t.Fatal(err)}
 }
}
func TestAsyncStartNeverAdvancesTimesOut(t *testing.T) {
 f:=&fakeConnection{deferredStart:true,disconnectOnStop:true}
 s,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));if err!=nil {t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Millisecond);defer cancel()
 if err=s.WaitConnected(ctx);!errors.Is(err,context.DeadlineExceeded) {t.Fatalf("expected bounded wait, got %v",err)}
 if f.closes!=0 {t.Fatal("timeout discarded cleanup reference")}
 if err=s.Stop(context.Background());err!=nil {t.Fatal(err)}
}
func TestAsyncStartRegressionAfterProgressFails(t *testing.T) {
 f:=&fakeConnection{deferredStart:true,afterStart:[]Status{Disconnected,Connecting,Disconnected},disconnectOnStop:true}
 s,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));if err!=nil {t.Fatal(err)}
 s.poll=time.Microsecond
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
 if err=s.WaitConnected(ctx);err==nil||errors.Is(err,context.DeadlineExceeded) {t.Fatalf("missed failure after progress: %v",err)}
 // A retry must not reset knowledge that this attempt already progressed.
 if err=s.WaitConnected(ctx);err==nil||errors.Is(err,context.DeadlineExceeded) {t.Fatalf("retry lost progress: %v",err)}
 if err=s.Stop(context.Background());err!=nil {t.Fatal(err)}
}
func TestStatusObservationPreservesAsyncProgress(t *testing.T) {
 f:=&fakeConnection{deferredStart:true,afterStart:[]Status{Connecting,Disconnected},disconnectOnStop:true}
 s,err:=startExisting(context.Background(),"service-id",true,fakeOpen(f));if err!=nil {t.Fatal(err)}
 if state,err:=s.Status();err!=nil||state!=Connecting {t.Fatal("expected progress from Status")}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
 if err=s.WaitConnected(ctx);err==nil||errors.Is(err,context.DeadlineExceeded) {t.Fatalf("forgot observed progress: %v",err)}
 if err=s.Stop(context.Background());err!=nil {t.Fatal(err)}
}

func TestServiceIDMatchesNativeCStringBoundary(t *testing.T) {
 f:=&fakeConnection{disconnectOnStop:true}
 s,err:=startExisting(context.Background(),strings.Repeat("a",maxServiceIDBytes),true,fakeOpen(f))
 if err!=nil {t.Fatalf("127-byte service ID rejected: %v",err)}
 if err=s.Stop(context.Background());err!=nil {t.Fatal(err)}
 _,err=startExisting(context.Background(),strings.Repeat("a",maxServiceIDBytes+1),true,func(string)(connection,error){t.Fatal("opened service ID without space for native terminator");return nil,nil})
 if err==nil {t.Fatal("128-byte service ID accepted")}
}
