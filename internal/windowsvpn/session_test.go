package windowsvpn

import (
 "context"
 "errors"
 "net"
 "strings"
 "testing"
 "time"
)

type fakeDriver struct { lease *fakeLease; reserves int }
func (d *fakeDriver) Reserve(id Identity) (Lease, error) { d.reserves++; d.lease.id = id; return d.lease, nil }
type fakeLease struct {
 id Identity
 fail string
 wrongIdentity bool
 password, psk []byte
 cleanupCalls int
 cleanupCanceled bool
 cancel context.CancelFunc
 block string
 entered chan struct{}
 pskErasedBeforeDial bool
}
func (l *fakeLease) Configure(ctx context.Context, r Request, psk []byte) error {
 l.psk = psk
 if err := l.wait(ctx,"configure"); err != nil { return err }
 if l.cancel != nil { l.cancel() }
 if l.fail == "configure" { return errors.New("secret-value") }
 return nil
}
func (l *fakeLease) Dial(ctx context.Context, password []byte) error {
 l.password = password
 l.pskErasedBeforeDial = true
 for _, b := range l.psk { if b != 0 { l.pskErasedBeforeDial = false } }
 if err := l.wait(ctx,"dial"); err != nil { return err }
 if l.fail == "dial" { return errors.New("secret-value") }; return nil
}
func (l *fakeLease) Inspect(ctx context.Context) (Observation, error) {
 if err := l.wait(ctx,"inspect"); err != nil { return Observation{}, err }
 if l.fail == "inspect" { return Observation{}, errors.New("secret-value") }
 id := l.id
 if l.wrongIdentity { id = "unrelated" }
 return Observation{Identity:id, Connected:true, InterfaceIndex:42, Address:net.ParseIP("10.23.0.7")}, nil
}
func (l *fakeLease) Cleanup(ctx context.Context) error {
 l.cleanupCalls++
 l.cleanupCanceled = ctx.Err() != nil
 if l.fail == "cleanup" { return errors.New("secret-value") }; return nil
}
func request() Request { return Request{Protocol:"l2tp", Gateway:"vpn.example.test", Username:"tester"} }
func secrets() Secrets { return Secrets{Password:[]byte("secret-value"), PSK:[]byte("secret-psk")} }
func consent() Consent { return Consent{NetworkChanges:true, PSKStorage:true} }
func controller() (*Controller, *fakeLease, *fakeDriver) {
 l := &fakeLease{}
 d := &fakeDriver{lease:l}
 return New(d), l, d
}
func TestConsentBeforeAnyDriverCall(t *testing.T) {
 for _, grant := range []Consent{{}, {NetworkChanges:true}, {PSKStorage:true}} {
  c, _, d := controller()
  if err := c.Start(context.Background(), request(), secrets(), grant); !errors.Is(err, ErrAuthorization) { t.Fatal(err) }
  if d.reserves != 0 { t.Fatal("touched driver without both grants") }
 }
}
func TestRejectUnsupportedProtocols(t *testing.T) {
 for _, protocol := range []string{"univpn", "anyconnect", "pptp", "sstp", "ikev2", ""} {
  c, _, d := controller(); r := request(); r.Protocol = protocol
  if err := c.Start(context.Background(), r, secrets(), consent()); !errors.Is(err, ErrUnsupported) { t.Fatal(protocol, err) }
  if d.reserves != 0 { t.Fatal("driver called") }
 }
}
func TestSessionLifecycleAndSecretOwnership(t *testing.T) {
 c, l, d := controller(); original := secrets()
 if err := c.Start(context.Background(), request(), original, consent()); err != nil { t.Fatal(err) }
 if string(original.Password) != "secret-value" || string(original.PSK) != "secret-psk" { t.Fatal("mutated caller-owned secrets") }
 for _, s := range [][]byte{l.password,l.psk} { for _, b := range s { if b != 0 { t.Fatal("copy not erased") } } }
 if err := c.Check(context.Background()); err != nil { t.Fatal(err) }
 if err := c.Start(context.Background(), request(), secrets(), consent()); !errors.Is(err, ErrBusy) { t.Fatal(err) }
 if d.reserves != 1 { t.Fatal("reserved duplicate session") }
 if err := c.Stop(); err != nil { t.Fatal(err) }
 if err := c.Stop(); err != nil { t.Fatal(err) }
 if l.cleanupCalls != 1 { t.Fatal("repeated successful cleanup") }
 if err := c.Start(context.Background(), request(), secrets(), consent()); err != nil { t.Fatal(err) }
 if d.reserves != 2 { t.Fatal("did not allow clean reconnect") }
}
func TestPartialFailuresRollbackAndRedact(t *testing.T) {
 for _, stage := range []string{"configure", "dial", "inspect"} {
  t.Run(stage,func(t *testing.T) {
   c,l,_ := controller(); l.fail = stage
   err := c.Start(context.Background(), request(), secrets(), consent())
   if err == nil || strings.Contains(err.Error(), "secret-value") { t.Fatalf("unredacted failure: %v",err) }
   if l.cleanupCalls != 1 { t.Fatal("no rollback") }
  })
 }
}
func TestCleanupFailureBlocksUntilConfirmed(t *testing.T) {
 c,l,d := controller()
 if err := c.Start(context.Background(), request(), secrets(), consent()); err != nil { t.Fatal(err) }
 l.fail = "cleanup"
 if err := c.Stop(); !errors.Is(err,ErrCleanup) { t.Fatal(err) }
 if err := c.Start(context.Background(), request(), secrets(), consent()); !errors.Is(err,ErrBusy) { t.Fatal(err) }
 if d.reserves != 1 { t.Fatal("started during unresolved cleanup") }
 l.fail = ""
 if err := c.Stop(); err != nil { t.Fatal(err) }
 if err := c.Start(context.Background(), request(), secrets(), consent()); err != nil { t.Fatal(err) }
}
func TestCanceledStartUsesIndependentCleanupContext(t *testing.T) {
 c,l,_ := controller(); ctx,cancel := context.WithCancel(context.Background()); defer cancel(); l.cancel = cancel
 if err := c.Start(ctx, request(), secrets(), consent()); !errors.Is(err,context.Canceled) { t.Fatal(err) }
 if l.cleanupCalls != 1 || l.cleanupCanceled { t.Fatal("cleanup inherited canceled context") }
}
func TestForeignIdentityNeverReady(t *testing.T) {
 c,l,_ := controller(); l.wrongIdentity = true
 if err := c.Start(context.Background(), request(), secrets(), consent()); !errors.Is(err,ErrVerification) { t.Fatal(err) }
 if l.cleanupCalls != 1 { t.Fatal("no rollback") }
}
func TestFreshCheckDetectsIdentityLoss(t *testing.T) {
 c,l,_ := controller()
 if err := c.Start(context.Background(), request(), secrets(), consent()); err != nil { t.Fatal(err) }
 l.wrongIdentity = true
 if err := c.Check(context.Background()); !errors.Is(err,ErrVerification) { t.Fatal(err) }
 if l.cleanupCalls != 1 { t.Fatal("no cleanup on identity loss") }
}
func TestInvalidObservations(t *testing.T) {
 valid := Observation{Identity:"owned", Connected:true, InterfaceIndex:1, Address:net.ParseIP("10.0.0.2")}
 if !verified(valid,"owned") { t.Fatal("valid rejected") }
 for _, ip := range []net.IP{nil,{},net.IP{1},net.ParseIP("0.0.0.0"),net.ParseIP("::"),net.ParseIP("127.0.0.1"),net.ParseIP("::1"),net.ParseIP("224.0.0.1")} {
  o := valid; o.Address = ip
  if verified(o,"owned") { t.Fatalf("accepted %v",ip) }
 }
 o := valid; o.InterfaceIndex = 0; if verified(o,"owned") { t.Fatal("accepted no interface") }
 o = valid; o.Connected = false; if verified(o,"owned") { t.Fatal("accepted disconnected") }
}
func TestNoDefaultNativeDriver(t *testing.T) {
 if err := New(nil).Start(context.Background(),request(),secrets(),consent()); !errors.Is(err,ErrUnavailable) { t.Fatal(err) }
}
func TestValidation(t *testing.T) {
 for _, host := range []string{"https://vpn.example.test", "vpn.example.test:443", "-bad.test", "bad_.test", "bad..test", "vpn\n.test"} {
  r := request(); r.Gateway = host
  if validate(r,secrets(),consent()) == nil { t.Fatal(host) }
 }
 for _, auth := range []string{"pap","chap","eap"} {
  r := request(); r.Authentication = auth
  if !errors.Is(validate(r,secrets(),consent()),ErrUnsupported) { t.Fatal(auth) }
 }
 for _, secret := range [][]byte{nil,[]byte("bad\x00"),[]byte("bad\n"),{0xff},[]byte(strings.Repeat("a",257))} {
  s := secrets(); s.PSK = secret
  if validate(request(),s,consent()) == nil { t.Fatal("invalid secret accepted") }
 }
}
func TestAlreadyCanceledDoesNotReserve(t *testing.T) {
 c,_,d := controller()
 ctx,cancel := context.WithCancel(context.Background()); cancel()
 if err := c.Start(ctx,request(),secrets(),consent()); !errors.Is(err,context.Canceled) { t.Fatal(err) }
 if d.reserves != 0 { t.Fatal("reserved after cancellation") }
}

// This intentionally keeps aliases only to audit controller erasure. A real
// driver must not retain them, and must erase its own native buffers separately.
func (l *fakeLease) wait(ctx context.Context, stage string) error {
 if l.block != stage { return nil }
 close(l.entered)
 <-ctx.Done()
 return ctx.Err()
}
func TestStopCancelsConnectionStages(t *testing.T) {
 for _, stage := range []string{"configure", "dial", "inspect"} {
  t.Run(stage,func(t *testing.T) {
   c,l,_ := controller()
   l.block, l.entered = stage, make(chan struct{})
   started := make(chan error,1)
   go func() { started <- c.Start(context.Background(),request(),secrets(),consent()) }()
   select { case <-l.entered: case <-time.After(time.Second): t.Fatal("stage never entered") }
   stopped := make(chan error,1)
   go func() { stopped <- c.Stop() }()
   select { case err := <-stopped: if err != nil { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("Stop did not cancel pending connection") }
   select { case err := <-started: if err == nil { t.Fatal("canceled Start reported ready") }; case <-time.After(time.Second): t.Fatal("Start did not return") }
   if l.cleanupCalls != 1 || l.cleanupCanceled { t.Fatal("cleanup missing, duplicated or canceled") }
   for _, secret := range [][]byte{l.password,l.psk} { for _, b := range secret { if b != 0 { t.Fatal("secret retained after cancellation") } } }
  })
 }
}
func TestSecretLifetimesAreSeparated(t *testing.T) {
 c,l,_ := controller()
 if err := c.Start(context.Background(),request(),secrets(),consent()); err != nil { t.Fatal(err) }
 if !l.pskErasedBeforeDial { t.Fatal("PSK survived Configure") }
 for _, b := range l.password { if b != 0 { t.Fatal("password survived Dial") } }
}

type reserveFailureDriver struct { lease Lease; err error }
func (d reserveFailureDriver) Reserve(Identity) (Lease,error) { return d.lease,d.err }
func TestNilBoundariesAndReserveFailure(t *testing.T) {
 var nilDriver *fakeDriver
 var nilLease *fakeLease
 for _, driver := range []Driver{nilDriver, reserveFailureDriver{}, reserveFailureDriver{lease:nilLease}, reserveFailureDriver{err:errors.New("secret-value")}} {
  err := New(driver).Start(context.Background(),request(),secrets(),consent())
  if err == nil || strings.Contains(err.Error(),"secret-value") { t.Fatalf("unexpected result: %v",err) }
 }
}
func TestDeadlineCancelsStages(t *testing.T) {
 for _, stage := range []string{"configure","dial","inspect"} {
  t.Run(stage,func(t *testing.T) {
   c,l,_ := controller(); l.block,l.entered = stage,make(chan struct{})
   ctx,cancel := context.WithTimeout(context.Background(),20*time.Millisecond); defer cancel()
   returned := make(chan error,1)
   go func() { returned <- c.Start(ctx,request(),secrets(),consent()) }()
   select { case err := <-returned: if err == nil { t.Fatal("expired operation succeeded") }; case <-time.After(time.Second): t.Fatal("deadline ignored") }
   if l.cleanupCanceled { t.Fatal("cleanup inherited deadline") }
  })
 }
}
func TestStopCancelsFreshInspection(t *testing.T) {
 c,l,_ := controller()
 if err := c.Start(context.Background(),request(),secrets(),consent()); err != nil { t.Fatal(err) }
 l.block,l.entered = "inspect",make(chan struct{})
 checked := make(chan error,1)
 go func() { checked <- c.Check(context.Background()) }()
 select { case <-l.entered: case <-time.After(time.Second): t.Fatal("check never entered") }
 stopped := make(chan error,1)
 go func() { stopped <- c.Stop() }()
 select { case err := <-stopped: if err != nil { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("Stop blocked on Check") }
 select { case err := <-checked: if err == nil { t.Fatal("canceled Check succeeded") }; case <-time.After(time.Second): t.Fatal("Check did not exit") }
}
func TestConcurrentStartStop(t *testing.T) {
 // Exercise state serialization without changing fake fields concurrently.
 c,_,_ := controller()
 finished := make(chan error,32)
 for i:=0;i<16;i++ {
  go func() { finished <- c.Start(context.Background(),request(),secrets(),consent()) }()
  go func() { finished <- c.Stop() }()
 }
 for i:=0;i<32;i++ {
  select {
  case err := <-finished:
   if err != nil && !errors.Is(err,ErrBusy) && !errors.Is(err,context.Canceled) { t.Fatal(err) }
  case <-time.After(2*time.Second): t.Fatal("concurrent operations deadlocked")
  }
 }
 if err := c.Stop(); err != nil { t.Fatal(err) }
}
func TestCancellationCleanupFailureRetainsLease(t *testing.T) {
 c,l,_ := controller(); l.block,l.entered,l.fail = "dial",make(chan struct{}),"cleanup"
 started := make(chan error,1)
 go func() { started <- c.Start(context.Background(),request(),secrets(),consent()) }()
 select { case <-l.entered: case <-time.After(time.Second): t.Fatal("dial never entered") }
 stopped := make(chan error,1)
 go func() { stopped <- c.Stop() }()
 select { case err := <-stopped: if !errors.Is(err,ErrCleanup) { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("Stop blocked") }
 select { case err := <-started: if !errors.Is(err,ErrCleanup) { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("Start blocked") }
 if err := c.Start(context.Background(),request(),secrets(),consent()); !errors.Is(err,ErrBusy) { t.Fatal(err) }
 l.block,l.fail = "",""
 if err := c.Stop(); err != nil { t.Fatal(err) }
}
