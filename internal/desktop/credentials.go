package desktop

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/json"
 "errors"
 "runtime"
 "time"
 "unicode/utf8"

 "github.com/egoist/mygo/ui"
 "mygo-vpn/internal/core"
 "mygo-vpn/internal/credentialstore"
)

// The application never calls a keyring as part of startup, profile selection,
// authentication, reconnect, import/export, or a network authorization checkbox.
type passwordStore interface {
 Save(context.Context,credentialstore.Reference,[]byte,credentialstore.Consent) error
 Load(context.Context,credentialstore.Reference,credentialstore.Consent)([]byte,error)
 Delete(context.Context,credentialstore.Reference,credentialstore.Consent) error
}
type credentialSnapshot struct {
 reference credentialstore.Reference
 profile [32]byte
 password [32]byte
}
type credentialIntent struct { action credentialstore.Consent; snapshot credentialSnapshot }
type credentialResult struct { value []byte; err error }
type credentialOperation struct {
 intent credentialIntent
 ctx context.Context
 cancel context.CancelFunc
 result chan credentialResult // Unbuffered: canceled readers cannot orphan secret buffers.
 finished chan struct{}
}

func(a *App)initializeCredentialStore(){
 if runtime.GOOS=="linux" { a.passwordStore=credentialstore.NewSystem() } // No I/O.
}
func(a *App)credentialSnapshot()(credentialSnapshot,bool){
 if !a.ConnectPanel || a.Page!="Overview" || a.Editing || a.ShuttingDown || a.LoadBlocked || a.Checking || a.SwitchPending || a.Engine==nil || a.busy(){return credentialSnapshot{},false}
 p:=a.selected()
 if p==nil || p.ID=="" || p.Username=="" || p.InteractiveAuth || p.ClientCertificate!="" || p.ClientKey!="" || p.AuthGroup!="" || p.Protocol=="l2tp" || p.Protocol=="univpn" {return credentialSnapshot{},false}
 selectedGateway:=a.GatewayChoice
 if selectedGateway=="" {selectedGateway=p.Gateway}
 allowed:=selectedGateway==p.Gateway
 for _,gateway:=range p.AdditionalGateways{if gateway==selectedGateway{allowed=true}}
 if !allowed{return credentialSnapshot{},false}
 final:=*p;final.Gateway=selectedGateway;final.AdditionalGateways=nil
 if core.ValidateProfile(final)!=nil{return credentialSnapshot{},false}
 raw,_:=json.Marshal(p) // Profile has no secret fields. Bind edits to this exact prompt.
 return credentialSnapshot{credentialstore.Reference{ProfileID:p.ID,Gateway:selectedGateway,Protocol:p.Protocol,Account:p.Username},sha256.Sum256(raw),sha256.Sum256([]byte(a.Password))},true
}
func validDesktopPassword(value []byte)bool{return len(value)>0 && len(value)<=credentialstore.MaxSecretBytes && utf8.Valid(value) && !bytes.ContainsAny(value,"\r\n\x00")}

func(a *App)setCredentialNotice(message string,snapshot credentialSnapshot){
 a.credentialNotice=message;a.credentialNoticeScope=&snapshot
}
func(a *App)setCredentialWarning(message string,snapshot credentialSnapshot){
 r:=snapshot.reference
 a.credentialWarning=a.tr(message)+"\n"+r.ProfileID+" · "+r.Protocol+"\n"+r.Gateway+"\n"+r.Account
}
func(a *App)cancelCredentialOperation(){
 a.credentialIntent=nil;a.credentialReusable=false
 if op:=a.credentialOperation;op!=nil{
  op.cancel();a.credentialOperation=nil
  if op.intent.action==credentialstore.SavePassword || op.intent.action==credentialstore.DeletePassword {
   a.setCredentialWarning("Keyring change canceled; the result may be unknown. Check the keyring before retrying.",op.intent.snapshot)
  }
 }
}
func(a *App)clearCredentialWorkflow(){
 a.cancelCredentialOperation()
 a.credentialLoaded=nil;a.credentialNotice="";a.credentialNoticeScope=nil
}
func(a *App)syncCredentialContext(){
 current,valid:=a.credentialSnapshot()
 if loaded:=a.credentialLoaded;loaded!=nil{
  if !valid || loaded.reference!=current.reference || loaded.profile!=current.profile{
   a.Password="";a.Authorized=false;a.ProxyConsent=false;a.credentialLoaded=nil
   current,valid=a.credentialSnapshot()
  }else if loaded.password!=current.password{a.credentialLoaded=nil} // New manually entered input.
 }
 if intent:=a.credentialIntent;intent!=nil && (!valid || intent.snapshot!=current){a.credentialIntent=nil;a.credentialReusable=false}
 if op:=a.credentialOperation;op!=nil && (!valid || op.intent.snapshot!=current){a.cancelCredentialOperation()}
 if scope:=a.credentialNoticeScope;scope!=nil && (!valid || scope.reference!=current.reference || scope.profile!=current.profile){a.credentialNotice="";a.credentialNoticeScope=nil}
}
func(a *App)requestCredentialAction(action credentialstore.Consent){
 a.syncCredentialContext()
 if a.passwordStore==nil || a.credentialOperation!=nil || a.credentialWarning!=""{return}
 snapshot,ok:=a.credentialSnapshot();if !ok{return}
 if action!=credentialstore.SavePassword && action!=credentialstore.UsePassword && action!=credentialstore.DeletePassword{return}
 if action==credentialstore.SavePassword && !validDesktopPassword([]byte(a.Password)){return}
 a.credentialIntent=&credentialIntent{action,snapshot};a.credentialReusable=false;a.credentialNotice="";a.credentialNoticeScope=nil
}
func(a *App)confirmCredentialAction(){
 a.syncCredentialContext()
 intent:=a.credentialIntent
 if intent==nil || a.passwordStore==nil || a.credentialOperation!=nil || a.credentialWarning!=""{return}
 if intent.action==credentialstore.SavePassword && !a.credentialReusable{return}
 snapshot,ok:=a.credentialSnapshot();if !ok || snapshot!=intent.snapshot{return}
 if intent.action==credentialstore.SavePassword && !validDesktopPassword([]byte(a.Password)){return}
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
 op:=&credentialOperation{intent:*intent,ctx:ctx,cancel:cancel,result:make(chan credentialResult),finished:make(chan struct{})}
 a.credentialOperation=op;a.credentialIntent=nil;a.credentialReusable=false
 backend:=a.passwordStore
 var input []byte
 if op.intent.action==credentialstore.SavePassword{input=[]byte(a.Password)}
 go func(){
  defer close(op.finished)
  defer clear(input)
  var result credentialResult
  switch op.intent.action{
  case credentialstore.SavePassword:result.err=backend.Save(ctx,op.intent.snapshot.reference,input,credentialstore.SavePassword)
  case credentialstore.UsePassword:result.value,result.err=backend.Load(ctx,op.intent.snapshot.reference,credentialstore.UsePassword)
  case credentialstore.DeletePassword:result.err=backend.Delete(ctx,op.intent.snapshot.reference,credentialstore.DeletePassword)
  }
  select{case op.result<-result:case <-ctx.Done():clear(result.value)}
 }()
}
func(a *App)pollCredentials(){
 a.syncCredentialContext()
 op:=a.credentialOperation;if op==nil{return}
 select{
 case result:=<-op.result:
  defer clear(result.value)
  if op.ctx.Err()!=nil{a.cancelCredentialOperation();if op.intent.action==credentialstore.UsePassword{a.setCredentialNotice("Keyring read canceled or timed out. No password was applied.",op.intent.snapshot)};return}
  op.cancel();a.credentialOperation=nil
  current,ok:=a.credentialSnapshot()
  if !ok || current!=op.intent.snapshot{return}
  if result.err!=nil{
   message:=credentialErrorMessage(op.intent.action,result.err)
   if op.intent.action==credentialstore.UsePassword{a.setCredentialNotice(message,op.intent.snapshot)}else{a.setCredentialWarning(message,op.intent.snapshot)}
   return
  }
  switch op.intent.action{
  case credentialstore.SavePassword:a.setCredentialNotice("Password saved in the system keyring. No connection was started.",op.intent.snapshot)
  case credentialstore.UsePassword:
   if !validDesktopPassword(result.value){a.setCredentialNotice("Saved password is not compatible with this password field.",op.intent.snapshot);return}
   a.Password=string(result.value);a.Authorized=false;a.ProxyConsent=false
   loaded,_:=a.credentialSnapshot();a.credentialLoaded=&loaded
   a.setCredentialNotice("Password loaded into this field only. Authorize and press Connect separately.",op.intent.snapshot)
  case credentialstore.DeletePassword:
   a.Password="";a.Authorized=false;a.ProxyConsent=false;a.credentialLoaded=nil
   a.setCredentialNotice("Saved password deleted and this password field cleared.",op.intent.snapshot)
  }
 case <-op.ctx.Done():a.cancelCredentialOperation();if op.intent.action==credentialstore.UsePassword{a.setCredentialNotice("Keyring read canceled or timed out. No password was applied.",op.intent.snapshot)}
 default:
 }
}
func credentialErrorMessage(action credentialstore.Consent,err error)string{
 if action!=credentialstore.UsePassword {
  if errors.Is(err,credentialstore.ErrLocked){return "System keyring is locked; a change may already have occurred. Check it before retrying."}
  return "Keyring change could not be confirmed. Check the keyring before retrying."
 }
 switch{
 case errors.Is(err,credentialstore.ErrLocked):return "System keyring is locked. Unlock it yourself, then request this operation again."
 case errors.Is(err,credentialstore.ErrNotFound):return "No saved password exists for this exact profile, gateway and account."
 case errors.Is(err,credentialstore.ErrAmbiguous):return "Multiple saved passwords match. Resolve them in the system keyring; no password was selected."
 case errors.Is(err,credentialstore.ErrPromptRequired):return "System keyring needs user interaction. Manage it yourself; no prompt was accepted."
 case errors.Is(err,credentialstore.ErrUnsupported):return "System password storage is available on Linux only."
 default:
  if action==credentialstore.SavePassword || action==credentialstore.DeletePassword{return "Keyring change could not be confirmed. Check the keyring before retrying."}
  return "System keyring is unavailable. No password was applied."
 }
}

func(a *App)credentialControls(c *ui.Context){
 a.syncCredentialContext()
 ui.Column(c).FillWidth().Gap(8).Children(func(){
  a.label(c,"System password storage (optional)")
  if a.passwordStore==nil{a.label(c,"System password storage is available on Linux only.");return}
  _,eligible:=a.credentialSnapshot()
  if !eligible{a.label(c,"Requires a named account and a non-interactive HTTPS password profile without certificates or an authentication group.");return}
  if a.credentialNotice!=""{a.label(c,a.credentialNotice)}
  if a.credentialWarning!=""{a.label(c,"Review and dismiss the keyring warning before another password operation.");return}
  if a.credentialOperation!=nil{
   a.label(c,"Waiting for the system keyring; no connection will be started.")
   if ui.Button(c.Key("cancel-keyring-operation"),a.tr("Cancel keyring operation")).Clicked(){a.cancelCredentialOperation()}
   return
  }
  if intent:=a.credentialIntent;intent!=nil{
   r:=intent.snapshot.reference
   a.label(c,"Confirm this exact profile, gateway and account:")
   if p:=a.selected();p!=nil{ui.Text(c,p.Name).FillWidth().FontSize(12)}
   ui.Text(c,r.ProfileID+" · "+r.Protocol).FillWidth().FontSize(12)
   ui.Text(c,r.Gateway).FillWidth().FontSize(12)
   ui.Text(c,r.Account).FillWidth().FontSize(12)
   label:="Confirm load only"
   switch intent.action{
   case credentialstore.SavePassword:
    label="Confirm save / replace"
    a.label(c,"Save this reusable password across logins in the system keyring, replacing its previous value. Never save a one-time code.")
    ui.Checkbox(c.Key("keyring-reusable"),&a.credentialReusable,a.tr("This is a reusable password, not a one-time code"))
   case credentialstore.UsePassword:a.label(c,"Replace this password field with the saved value. This does not connect or authorize network changes.")
   case credentialstore.DeletePassword:label="Confirm delete saved password";a.label(c,"Delete this saved password from the system keyring and clear this password field.")
   }
   ui.Column(c).FillWidth().Gap(8).Children(func(){
    if ui.Button(c.Key("confirm-keyring-operation"),a.tr(label)).FillWidth().Disabled(intent.action==credentialstore.SavePassword && !a.credentialReusable).Clicked(){a.confirmCredentialAction()}
    if ui.Button(c.Key("cancel-keyring-confirm"),a.tr("Cancel password request")).FillWidth().Clicked(){a.credentialIntent=nil;a.credentialReusable=false}
   })
   return
  }
  ui.Column(c).FillWidth().Gap(8).Children(func(){
   if ui.Button(c.Key("request-keyring-save"),a.tr("Save / replace password")).FillWidth().Disabled(!validDesktopPassword([]byte(a.Password))).Clicked(){a.requestCredentialAction(credentialstore.SavePassword)}
   if ui.Button(c.Key("request-keyring-load"),a.tr("Load saved password")).FillWidth().Clicked(){a.requestCredentialAction(credentialstore.UsePassword)}
   if ui.Button(c.Key("request-keyring-delete"),a.tr("Delete saved password")).FillWidth().Clicked(){a.requestCredentialAction(credentialstore.DeletePassword)}
  })
 })
}

// PrepareToHide clears session input and cancels pending keyring operations
// before the window is hidden to the tray. It never changes the VPN session.
func(a *App)PrepareToHide(){a.clearCredentials()}
