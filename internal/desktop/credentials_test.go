package desktop

import (
 "bytes"
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "sync/atomic"
 "testing"
 "time"

 "github.com/egoist/mygo/ui"
 "mygo-vpn/internal/core"
 "mygo-vpn/internal/credentialstore"
)

type passwordCall struct{ action credentialstore.Consent; reference credentialstore.Reference; input []byte; ctx context.Context }
type mockPasswordStore struct{ calls chan passwordCall; value []byte; err error; release chan struct{}; returned chan struct{} }
func(m *mockPasswordStore)run(ctx context.Context,action credentialstore.Consent,r credentialstore.Reference,value []byte)([]byte,error){
 m.calls<-passwordCall{action,r,value,ctx}
 if m.release!=nil{<-m.release} // Deliberately ignore cancellation to test stale results.
 if m.returned!=nil{defer close(m.returned)}
 return m.value,m.err
}
func(m *mockPasswordStore)Save(ctx context.Context,r credentialstore.Reference,value []byte,c credentialstore.Consent)error{_,err:=m.run(ctx,c,r,value);return err}
func(m *mockPasswordStore)Load(ctx context.Context,r credentialstore.Reference,c credentialstore.Consent)([]byte,error){return m.run(ctx,c,r,nil)}
func(m *mockPasswordStore)Delete(ctx context.Context,r credentialstore.Reference,c credentialstore.Consent)error{_,err:=m.run(ctx,c,r,nil);return err}
type passwordNetworkAdapter struct{ starts *atomic.Int32 }
func(a passwordNetworkAdapter)Capability()core.Capability{return core.Capability{Available:true}}
func(a passwordNetworkAdapter)Start(context.Context,core.Profile,[]byte)(core.Session,error){a.starts.Add(1);return nil,errors.New("network must not be invoked")}
func passwordTestApp(t *testing.T)(*App,*mockPasswordStore,*atomic.Int32){
 t.Helper();starts:=&atomic.Int32{};adapter:=passwordNetworkAdapter{starts};backend:=&mockPasswordStore{calls:make(chan passwordCall,10)}
 a:=&App{Page:"Overview",ConnectPanel:true,Engine:core.NewEngine(adapter),Adapter:adapter,Capability:adapter.Capability(),passwordStore:backend,Store:core.Store{Path:filepath.Join(t.TempDir(),"profiles.json")}}
 a.Config=core.Config{Version:1,SelectedID:"profile-a",Profiles:[]core.Profile{{ID:"profile-a",Name:"Fixture",Gateway:"https://vpn.example",AdditionalGateways:[]string{"https://backup.example"},Protocol:"anyconnect",Username:"alice"}}}
 a.Config.Settings.Language="en";a.GatewayChoice="https://vpn.example"
 return a,backend,starts
}
func waitPasswordCall(t *testing.T,m *mockPasswordStore)passwordCall{t.Helper();select{case call:=<-m.calls:return call;case <-time.After(time.Second):t.Fatal("mock password operation never started");return passwordCall{}}}
func awaitPasswordResult(t *testing.T,a *App){t.Helper();deadline:=time.Now().Add(time.Second);for a.credentialOperation!=nil && time.Now().Before(deadline){a.pollCredentials();time.Sleep(time.Millisecond)};if a.credentialOperation!=nil{t.Fatal("password result not consumed")}}
func noPasswordCall(t *testing.T,m *mockPasswordStore){t.Helper();select{case <-m.calls:t.Fatal("unexpected keyring call");default:}}

func TestPasswordActionsRequireExplicitConfirmation(t *testing.T){
 for _,action:=range []credentialstore.Consent{credentialstore.SavePassword,credentialstore.UsePassword,credentialstore.DeletePassword}{t.Run(string(rune('0'+action)),func(t *testing.T){
  a,m,starts:=passwordTestApp(t);a.Password="synthetic-password";m.value=[]byte("synthetic-loaded")
  a.pollCredentials();a.openConnectForm();noPasswordCall(t,m);a.Password="synthetic-password"
  a.confirmCredentialAction();noPasswordCall(t,m)
  a.requestCredentialAction(action);noPasswordCall(t,m)
  if action==credentialstore.SavePassword{a.confirmCredentialAction();noPasswordCall(t,m);a.credentialReusable=true}
  a.confirmCredentialAction();op:=a.credentialOperation;call:=waitPasswordCall(t,m)
  if call.action!=action || call.reference.ProfileID!="profile-a" || call.reference.Gateway!="https://vpn.example" || call.reference.Account!="alice"{t.Fatal("operation identity or consent changed")}
  if action==credentialstore.SavePassword && !bytes.Equal(call.input,[]byte("synthetic-password")){t.Fatal("save input mismatch")}
  awaitPasswordResult(t,a);<-op.finished
  for _,b:=range call.input{if b!=0{t.Fatal("worker input was not cleared")}}
  if starts.Load()!=0 || a.Engine.Snapshot().State!=core.Disconnected{t.Fatal("keyring operation started network")}
  if action==credentialstore.UsePassword && (a.Password!="synthetic-loaded" || a.Authorized || a.ProxyConsent){t.Fatal("load did more than fill/revoke network consent")}
  if action==credentialstore.DeletePassword && a.Password!=""{t.Fatal("delete left password field populated")}
 })}
}
func TestPasswordConfirmationInvalidatedByEditsAndSelection(t *testing.T){
 for _,change:=range []func(*App){func(a *App){a.Password="new-input"},func(a *App){a.GatewayChoice="https://backup.example"},func(a *App){a.Config.Profiles[0].Username="bob"},func(a *App){a.Config.Profiles[0].ID="different"},func(a *App){a.Page="Settings"},func(a *App){a.BeginShutdown()}}{
  a,m,_:=passwordTestApp(t);a.Password="synthetic";a.requestCredentialAction(credentialstore.SavePassword);a.credentialReusable=true;change(a);a.confirmCredentialAction();noPasswordCall(t,m)
  if a.credentialIntent!=nil{t.Fatal("stale confirmation retained")}
 }
}
func TestLatePasswordLoadNeverOverwritesNewInput(t *testing.T){
 a,m,starts:=passwordTestApp(t);m.value=[]byte("synthetic-stale");m.release=make(chan struct{});m.returned=make(chan struct{})
 a.requestCredentialAction(credentialstore.UsePassword);a.confirmCredentialAction();op:=a.credentialOperation;call:=waitPasswordCall(t,m)
 a.Password="new-manual-input";a.pollCredentials()
 if call.ctx.Err()==nil || a.credentialOperation!=nil{t.Fatal("stale load not canceled")}
 close(m.release);<-m.returned
 <-op.finished
 if !bytes.Equal(m.value,make([]byte,len(m.value))){t.Fatal("canceled worker result was not cleared")}
 if a.Password!="new-manual-input" || starts.Load()!=0{t.Fatal("late load changed user input or connected")}
}
func TestLoadedPasswordClearsOnGatewayOrProfileChange(t *testing.T){
 a,m,_:=passwordTestApp(t);m.value=[]byte("synthetic-loaded");a.requestCredentialAction(credentialstore.UsePassword);a.confirmCredentialAction();waitPasswordCall(t,m);awaitPasswordResult(t,a)
 a.Authorized=true;a.ProxyConsent=true;a.GatewayChoice="https://backup.example";a.syncCredentialContext()
 if a.Password!="" || a.Authorized || a.ProxyConsent || a.credentialLoaded!=nil{t.Fatal("saved password carried to another gateway")}
}
func TestPasswordStoreErrorsAreRedactedAndLockIsVisible(t *testing.T){
 for _,err:=range []error{credentialstore.ErrLocked,errors.New("synthetic-private-error-detail")}{
  a,m,_:=passwordTestApp(t);m.err=err;a.requestCredentialAction(credentialstore.UsePassword);a.confirmCredentialAction();waitPasswordCall(t,m);awaitPasswordResult(t,a)
  if strings.Contains(a.credentialNotice,"synthetic-private") || a.Password!=""{t.Fatal("provider error/secret leaked")}
  if err==credentialstore.ErrLocked && !strings.Contains(a.credentialNotice,"locked"){t.Fatal("locked state missing")}
 }
}
func TestPasswordNeverEntersConfiguration(t *testing.T){
 a,m,_:=passwordTestApp(t);m.value=[]byte("synthetic-never-config");a.requestCredentialAction(credentialstore.UsePassword);a.confirmCredentialAction();waitPasswordCall(t,m);awaitPasswordResult(t,a)
 if !a.commit(a.copyConfig()){t.Fatal("fixture config write failed")};data,err:=os.ReadFile(a.Store.Path);if err!=nil{t.Fatal(err)}
 if bytes.Contains(data,[]byte("synthetic-never-config")) || bytes.Contains(data,[]byte("credential")){t.Fatal("password or storage consent persisted")}
}
func TestPasswordUnsupportedAndSensitiveFormsHaveNoAccess(t *testing.T){
 for _,change:=range []func(*App){func(a *App){a.passwordStore=nil},func(a *App){a.Config.Profiles[0].InteractiveAuth=true},func(a *App){a.Config.Profiles[0].ClientCertificate="/synthetic.pem"},func(a *App){a.Config.Profiles[0].AuthGroup="realm"},func(a *App){a.Config.Profiles[0].Username=""},func(a *App){a.GatewayChoice="https://unlisted.example"}}{
  a,m,_:=passwordTestApp(t);change(a);a.requestCredentialAction(credentialstore.UsePassword);a.confirmCredentialAction();noPasswordCall(t,m)
 }
}
func TestPasswordUIRequestsBeforeProviderIO(t *testing.T){
 a,m,_:=passwordTestApp(t);v:=ui.NewTester(a.credentialControls,880,700)
 if err:=v.Click("Load saved password");err!=nil{t.Fatal(err)};v.Frame();noPasswordCall(t,m)
 if !v.HasText("Confirm load only") || !v.HasText("https://vpn.example") || !v.HasText("alice"){t.Fatal("exact-reference confirmation missing")}
 if err:=v.Click("Cancel password request");err!=nil{t.Fatal(err)};v.Frame();noPasswordCall(t,m)
 a.passwordStore=nil;v.Frame();if !v.HasText("System password storage is available on Linux only."){t.Fatal("unsupported platform notice missing")}
}

func TestPasswordCancelNavigationAndShutdownDisposeResults(t *testing.T){
 for _,cancel:=range []func(*App){func(a *App){a.clearCredentials()},func(a *App){a.navigate("Settings")},func(a *App){a.BeginShutdown()},func(a *App){a.PrepareToHide()}}{
  a,m,_:=passwordTestApp(t);m.value=[]byte("synthetic-discard");m.release=make(chan struct{})
  a.requestCredentialAction(credentialstore.UsePassword);a.confirmCredentialAction();op:=a.credentialOperation;call:=waitPasswordCall(t,m)
  cancel(a);if call.ctx.Err()==nil{t.Fatal("navigation did not cancel provider")}
  close(m.release);<-op.finished
  if a.Password!="" || a.credentialOperation!=nil || !bytes.Equal(m.value,make([]byte,len(m.value))){t.Fatal("canceled result survived")}
 }
}
func TestPasswordCancellationReportsUncertainWrite(t *testing.T){
 for _,action:=range []credentialstore.Consent{credentialstore.SavePassword,credentialstore.DeletePassword}{
  a,m,_:=passwordTestApp(t);m.release=make(chan struct{});a.Password="synthetic"
  a.requestCredentialAction(action);a.credentialReusable=true;a.confirmCredentialAction();op:=a.credentialOperation;waitPasswordCall(t,m)
  a.cancelCredentialOperation();close(m.release);<-op.finished
  if !strings.Contains(a.credentialWarning,"unknown") || a.credentialOperation!=nil{t.Fatal("write cancellation implied no side effect")}
 }
}
func TestPasswordRepeatedConfirmStartsOnlyOneOperation(t *testing.T){
 a,m,_:=passwordTestApp(t);m.release=make(chan struct{});a.Password="synthetic"
 a.requestCredentialAction(credentialstore.SavePassword);a.credentialReusable=true;a.confirmCredentialAction();op:=a.credentialOperation;waitPasswordCall(t,m)
 a.confirmCredentialAction();a.requestCredentialAction(credentialstore.DeletePassword);noPasswordCall(t,m)
 close(m.release);awaitPasswordResult(t,a);<-op.finished
}

func TestPasswordNoticeIsBoundAndUnknownWriteWarningSurvivesNavigation(t *testing.T){
 a,m,_:=passwordTestApp(t);a.Password="synthetic";a.requestCredentialAction(credentialstore.SavePassword);a.credentialReusable=true;a.confirmCredentialAction();op:=a.credentialOperation;waitPasswordCall(t,m);awaitPasswordResult(t,a);<-op.finished
 if a.credentialNotice==""{t.Fatal("completion notice missing")}
 a.GatewayChoice="https://backup.example";a.syncCredentialContext();if a.credentialNotice!=""{t.Fatal("success notice carried to another gateway")}
 a.Password="synthetic";m.release=make(chan struct{});a.requestCredentialAction(credentialstore.SavePassword);a.credentialReusable=true;a.confirmCredentialAction();op=a.credentialOperation;waitPasswordCall(t,m)
 a.navigate("Settings");close(m.release);<-op.finished
 if !strings.Contains(a.credentialWarning,"https://backup.example") || !strings.Contains(a.credentialWarning,"alice") || !strings.Contains(a.credentialWarning,"unknown"){t.Fatal("uncertain write warning lost its exact target")}
 if !a.commit(a.copyConfig()) || a.credentialWarning==""{t.Fatal("configuration save swallowed keyring warning")}
 a.openConnectForm();a.requestCredentialAction(credentialstore.UsePassword);noPasswordCall(t,m);if a.credentialIntent!=nil{t.Fatal("unacknowledged write warning allowed another operation")}
}

func TestPasswordControlsFitMinimumApplicationWidth(t *testing.T){
 for _,language:=range []string{"en","zh"}{t.Run(language,func(t *testing.T){
 a,m,_:=passwordTestApp(t);a.Config.Settings.Language=language;a.Password="synthetic";v:=ui.NewTester(a.View,880,580)
 for _,label:=range []string{"Save / replace password","Load saved password","Delete saved password"}{
  r,ok:=v.Find(a.tr(label));if !ok || r.X<0 || r.W<=0 || r.X+r.W>880{t.Fatalf("password button exceeds minimum viewport: %s found=%t rect=%+v",label,ok,r)}
 }
 a.requestCredentialAction(credentialstore.UsePassword);v.Frame()
 for _,label:=range []string{"Confirm load only","Cancel password request","https://vpn.example","alice"}{
  r,ok:=v.Find(a.tr(label));if !ok || r.X<0 || r.W<=0 || r.X+r.W>880{t.Fatalf("password confirmation exceeds minimum viewport: %s found=%t rect=%+v",label,ok,r)}
 }
 if v.HasText(a.tr("Session password")) || v.HasText(a.tr("Authorize network changes")){t.Fatal("confirmation did not replace unrelated session inputs")}
 if err:=v.Click(a.tr("Cancel password request"));err!=nil{t.Fatal(err)};v.Frame()
 if a.credentialIntent!=nil || a.Password!="synthetic" || !v.HasText(a.tr("Session password")){t.Fatal("cancel did not restore the unchanged session form")}
 noPasswordCall(t,m)
 })}
}

type hidePasswordSession struct{ switchSession; stops atomic.Int32 }
func(s *hidePasswordSession)Stop()error{s.stops.Add(1);return s.switchSession.Stop()}
type hidePasswordAdapter struct{session *hidePasswordSession}
func(hidePasswordAdapter)Capability()core.Capability{return core.Capability{Available:true}}
func(a hidePasswordAdapter)Start(context.Context,core.Profile,[]byte)(core.Session,error){return a.session,nil}
func TestHidingPasswordFormNeverStopsActiveTunnel(t *testing.T){
 a,m,_:=passwordTestApp(t)
 session:=&hidePasswordSession{switchSession:switchSession{ready:make(chan error,1),done:make(chan error,1)}}
 a.Engine=core.NewEngine(hidePasswordAdapter{session})
 if err:=a.Engine.Connect(a.Config.Profiles[0],"synthetic-in-memory-only",true);err!=nil{t.Fatal(err)}
 session.ready<-nil;awaitState(t,a,core.Connected)
 defer func(){_=a.Engine.Disconnect();awaitState(t,a,core.Disconnected)}()
 a.Password="synthetic";a.KeyPassword="synthetic-key";a.IPsecPSK="synthetic-psk";a.Authorized=true;a.ProxyConsent=true
 a.PrepareToHide()
 if a.Password!="" || a.KeyPassword!="" || a.IPsecPSK!="" || a.Authorized || a.ProxyConsent || a.ConnectPanel{t.Fatal("tray hide retained session inputs")}
 if a.Engine.Snapshot().State!=core.Connected || session.stops.Load()!=0{t.Fatal("tray hide stopped active tunnel")}
 noPasswordCall(t,m)
}

// A valid long synthetic target forces scrolling without hiding or truncating
// the operation's exact identity. Every action must still offer a usable cancel.
func TestPasswordConfirmationsRemainReachableByScrolling(t *testing.T){
 for _,language:=range []string{"en","zh"}{
  for _,action:=range []credentialstore.Consent{credentialstore.SavePassword,credentialstore.UsePassword,credentialstore.DeletePassword}{
   t.Run(language+"/"+string(rune('0'+action)),func(t *testing.T){
    a,m,_:=passwordTestApp(t);a.Config.Settings.Language=language;a.Password="synthetic"
    a.Config.Profiles[0].Name=strings.Repeat("Fixture ",10) // 80 characters, the allowed maximum.
    a.Config.Profiles[0].Gateway="https://vpn.example/"+strings.Repeat("synthetic/",60)
    a.GatewayChoice=a.Config.Profiles[0].Gateway
    if err:=core.ValidateProfile(a.Config.Profiles[0]);err!=nil{t.Fatalf("invalid scrolling fixture: %v",err)}
    a.requestCredentialAction(action)
    if a.credentialIntent==nil{t.Fatal("valid scrolling fixture did not create a confirmation")}
    v:=ui.NewTester(a.View,880,580)
    v.Scroll(650,300,0,10000);v.Frame()
    confirm:="Confirm load only"
    if action==credentialstore.SavePassword{confirm="Confirm save / replace"}
    if action==credentialstore.DeletePassword{confirm="Confirm delete saved password"}
    for _,label:=range []string{confirm,"Cancel password request"}{
     r,ok:=v.Find(a.tr(label));if !ok || r.X<0 || r.W<=0 || r.H<=0 || r.X+r.W>880 || r.Y<0 || r.Y+r.H>580{t.Fatalf("scrolled confirmation is unreachable: %s found=%t rect=%+v",label,ok,r)}
    }
    if err:=v.Click(a.tr("Cancel password request"));err!=nil{t.Fatal(err)};v.Frame()
    if a.credentialIntent!=nil || a.Password!="synthetic"{t.Fatal("scrolled cancel did not preserve the session input")}
    noPasswordCall(t,m)
   })
  }
 }
}
