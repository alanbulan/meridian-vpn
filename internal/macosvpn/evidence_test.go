package macosvpn

import (
 "context"
 "errors"
 "fmt"
 "net"
 "net/netip"
 "testing"
 "time"
)
func validEvidence() systemEvidence {return systemEvidence{requestedID:"service-id",actualID:"service-id",interfaceName:"ppp7",extendedAddresses:[]string{"10.8.0.2"},serviceAddresses:[]string{"10.8.0.2"}}}
func validInterface(string)(observedInterface,error) {return observedInterface{index:8,flags:net.FlagUp|net.FlagPointToPoint,addresses:[]netip.Addr{netip.MustParseAddr("10.8.0.2")}},nil}
func TestVerifyInterfaceEvidence(t *testing.T) {
 out,err:=verifyEvidence(validEvidence(),validInterface)
 if err!=nil||out.InterfaceIndex!=8||out.InterfaceName!="ppp7"||out.ServiceID!="service-id"||len(out.IPv4Addresses)!=1 {t.Fatalf("unexpected evidence: %+v %v",out,err)}
}
func TestRejectMismatchedServiceEvidence(t *testing.T) {
 changes:=[]func(*systemEvidence){
  func(e *systemEvidence){e.actualID="another-service"},
  func(e *systemEvidence){e.requestedID=""},
  func(e *systemEvidence){e.interfaceName="en0"},
  func(e *systemEvidence){e.interfaceName="ppp7/../../"},
  func(e *systemEvidence){e.serviceAddresses=[]string{"10.8.0.3"}},
  func(e *systemEvidence){e.extendedAddresses=nil},
  func(e *systemEvidence){e.serviceAddresses=[]string{"10.8.0.2","10.8.0.2"}},
  func(e *systemEvidence){e.extendedAddresses=[]string{"::ffff:10.8.0.2"}},
  func(e *systemEvidence){e.extendedAddresses=[]string{"127.0.0.1"}},
 }
 for i,change:=range changes {raw:=validEvidence();change(&raw);if _,err:=verifyEvidence(raw,validInterface);err==nil {t.Fatalf("accepted mismatch %d",i)}}
}
func TestRejectMissingOrWrongActualInterface(t *testing.T) {
 cases:=[]observedInterface{
  {index:0,flags:net.FlagUp|net.FlagPointToPoint,addresses:[]netip.Addr{netip.MustParseAddr("10.8.0.2")}},
  {index:8,flags:net.FlagPointToPoint,addresses:[]netip.Addr{netip.MustParseAddr("10.8.0.2")}},
  {index:8,flags:net.FlagUp,addresses:[]netip.Addr{netip.MustParseAddr("10.8.0.2")}},
  {index:8,flags:net.FlagUp|net.FlagPointToPoint,addresses:[]netip.Addr{netip.MustParseAddr("10.8.0.3")}},
 }
 for _,actual:=range cases {if _,err:=verifyEvidence(validEvidence(),func(string)(observedInterface,error){return actual,nil});err==nil {t.Fatal("accepted wrong interface")}}
 if _,err:=verifyEvidence(validEvidence(),func(string)(observedInterface,error){return observedInterface{},errors.New("gone")});err==nil {t.Fatal("accepted missing interface")}
}
type fakeEvidenceConnection struct {fakeConnection; evidence systemEvidence; readErr error; reads int}
func (f *fakeEvidenceConnection) readSystemEvidence()(systemEvidence,error){f.reads++;return f.evidence,f.readErr}
func TestInspectRejectsStateChangeDuringRead(t *testing.T) {
 f:=&fakeEvidenceConnection{fakeConnection:fakeConnection{state:Connected},evidence:validEvidence()}
 s:=&Session{native:f}
 // Model an OS state change after the first Connected sample, before the
 // second. Session locking cannot prevent external system transitions.
 _,err:=s.inspectInterface(func(name string)(observedInterface,error){f.state=Disconnected;return validInterface(name)})
 if err==nil||f.reads!=1 {t.Fatal("accepted evidence across disconnect")}
}
func TestInspectRejectsInactiveStoppingAndClosed(t *testing.T) {
 f:=&fakeEvidenceConnection{fakeConnection:fakeConnection{state:Connecting},evidence:validEvidence()}
 s:=&Session{native:f}
 if _,err:=s.inspectInterface(validInterface);err==nil||f.reads!=0 {t.Fatal("inspected inactive service")}
 f.state=Connected;s.stopping=true
 if _,err:=s.inspectInterface(validInterface);err==nil||f.reads!=0 {t.Fatal("inspected stopping service")}
 s.native=nil
 if _,err:=s.inspectInterface(validInterface);!errors.Is(err,ErrClosed) {t.Fatal(err)}
}
func TestInspectEvidenceReadFailureAndSuccess(t *testing.T) {
 f:=&fakeEvidenceConnection{fakeConnection:fakeConnection{state:Connected},evidence:validEvidence(),readErr:errors.New("native unavailable")}
 s:=&Session{native:f}
 if _,err:=s.inspectInterface(validInterface);err==nil {t.Fatal("ignored read failure")}
 f.readErr=nil
 if _,err:=s.inspectInterface(validInterface);err!=nil {t.Fatal(err)}
 if f.starts!=0||f.stops!=0||f.closes!=0 {t.Fatal("inspection changed session")}
}

func TestInspectSerializesWithStop(t *testing.T) {
 f:=&fakeEvidenceConnection{fakeConnection:fakeConnection{state:Connected,disconnectOnStop:true},evidence:validEvidence()}
 s:=&Session{native:f,poll:time.Microsecond}
 entered:=make(chan struct{});release:=make(chan struct{})
 inspected:=make(chan error,1);stopped:=make(chan error,1)
 go func(){_,err:=s.inspectInterface(func(name string)(observedInterface,error){close(entered);<-release;return validInterface(name)});inspected<-err}()
 <-entered
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
 go func(){stopped<-s.Stop(ctx)}()
 close(release)
 select {case err:=<-inspected:if err!=nil {t.Fatal(err)};case <-ctx.Done():t.Fatal("inspection did not return")}
 select {case err:=<-stopped:if err!=nil {t.Fatal(err)};case <-ctx.Done():t.Fatal("stop did not return")}
 if f.closes!=1||f.reads!=1 {t.Fatal("native reference not serialized correctly")}
}

func TestEvidenceAddressAndNameBoundaries(t *testing.T) {
 for _,bad:=range []string{"0.0.0.0","127.0.0.1","169.254.1.2","224.0.0.1","255.255.255.255","::1","::ffff:10.8.0.2","10.8.0.2/24","10.8.0.2%ppp0",""} {
  if _,err:=ipv4Set([]string{bad});err==nil {t.Fatalf("accepted invalid address %q",bad)}
 }
 values:=make([]string,16);actual:=observedInterface{index:8,flags:net.FlagUp|net.FlagPointToPoint}
 for i:=range values {values[i]=fmt.Sprintf("10.8.0.%d",i+1);actual.addresses=append(actual.addresses,netip.MustParseAddr(values[i]))}
 raw:=validEvidence();raw.extendedAddresses=values;raw.serviceAddresses=values;raw.interfaceName="ppp123456789012"
 lookup:=func(string)(observedInterface,error){return actual,nil}
 if _,err:=verifyEvidence(raw,lookup);err!=nil {t.Fatalf("valid maximum address/name boundaries: %v",err)}
 raw.interfaceName+="3"
 if _,err:=verifyEvidence(raw,lookup);err==nil {t.Fatal("accepted oversized interface name")}
 if _,err:=ipv4Set(append(values,"10.8.0.17"));err==nil {t.Fatal("accepted oversized address set")}
}
