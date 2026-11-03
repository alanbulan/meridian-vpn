//go:build linux

package credentialstore

import (
 "context"
 "strings"
 "testing"
 "github.com/godbus/dbus/v5"
)

type fakeBus struct {
 calls []string
 unlocked, locked []dbus.ObjectPath
 collectionLocked bool
 secretValue []byte
 responseContentType string
 responseSession dbus.ObjectPath
 responseParameters []byte
 written secret
 prompt dbus.ObjectPath
 invalidSessionOutput bool
 nonStringSessionOutput bool
 createDuplicate bool
}
func (b *fakeBus) call(_ context.Context, _ dbus.ObjectPath, method string, args []any, out ...any) error {
 b.calls = append(b.calls,method)
 switch method {
 case serviceInterface+".SearchItems":
  attrs := args[0].(map[string]string)
  if attrs["reference"] != "digest" || attrs["kind"] != credentialKind { panic("wrong scope") }
  *out[0].(*[]dbus.ObjectPath)=b.unlocked; *out[1].(*[]dbus.ObjectPath)=b.locked
 case serviceInterface+".ReadAlias": *out[0].(*dbus.ObjectPath)="/collection"
 case "org.freedesktop.DBus.Properties.Get": *out[0].(*dbus.Variant)=dbus.MakeVariant(b.collectionLocked)
 case serviceInterface+".OpenSession":
  *out[0].(*dbus.Variant)=dbus.MakeVariant(""); if b.invalidSessionOutput { *out[0].(*dbus.Variant)=dbus.MakeVariant("wrong") }; if b.nonStringSessionOutput { *out[0].(*dbus.Variant)=dbus.MakeVariant(uint32(1)) }; *out[1].(*dbus.ObjectPath)="/session"
 case itemInterface+".GetSecret":
  contentType:=b.responseContentType;if contentType==""{contentType="text/plain"}
  responseSession:=b.responseSession;if responseSession==""{responseSession="/session"}
  *out[0].(*secret)=secret{responseSession,b.responseParameters,b.secretValue,contentType}
 case itemInterface+".SetSecret": b.written=args[0].(secret);b.written.Value=append([]byte(nil),b.written.Value...)
 case collectionInterface+".CreateItem": b.unlocked=[]dbus.ObjectPath{"/item"}; if b.createDuplicate { b.unlocked=append(b.unlocked,"/other") }; *out[0].(*dbus.ObjectPath)="/item"; *out[1].(*dbus.ObjectPath)=b.prompt
 case itemInterface+".Delete": *out[0].(*dbus.ObjectPath)=b.prompt
 }
 return nil
}
func TestFailClosedStates(t *testing.T) {
 cases := []struct{name string; b fakeBus; op operation; want error}{
  {"missing",fakeBus{},load,ErrNotFound},
  {"locked",fakeBus{locked:[]dbus.ObjectPath{"/item"}},load,ErrLocked},
  {"duplicate",fakeBus{unlocked:[]dbus.ObjectPath{"/one","/two"}},load,ErrAmbiguous},
  {"locked collection",fakeBus{collectionLocked:true},save,ErrLocked},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T){
  _,err:=execute(context.Background(),&tc.b,tc.op,"digest",[]byte("synthetic"))
  if err!=tc.want { t.Fatal(err) }
  for _,call:=range tc.b.calls { if strings.Contains(call,"OpenSession") || strings.Contains(call,"Unlock") || strings.Contains(call,"CreateItem") { t.Fatal("failed state accessed secret") } }
 }) }
}
func TestSaveLoadDeleteAndPrompt(t *testing.T) {
 for _, op := range []operation{save,load,remove} {
  b:=&fakeBus{unlocked:[]dbus.ObjectPath{"/item"},secretValue:encodePassword("digest",[]byte("synthetic")),prompt:"/"}
  out,err:=execute(context.Background(),b,op,"digest",[]byte("synthetic"))
  if err!=nil { t.Fatal(err) }
  if op==load && string(out)!="synthetic" { t.Fatal("wrong value") }; clear(out)
 }
 b:=&fakeBus{prompt:"/prompt"}
 if _,err:=execute(context.Background(),b,save,"digest",[]byte("synthetic"));err!=ErrPromptRequired { t.Fatal(err) }
 for _,call:=range b.calls { if strings.Contains(call,".Prompt") { t.Fatal("prompt executed") } }
}
func TestMalformedSecretRejectedAndCleared(t *testing.T) {
 b:=&fakeBus{unlocked:[]dbus.ObjectPath{"/item"},secretValue:make([]byte,maxStoredBytes+1)}
 b.secretValue[0]=1
 if _,err:=execute(context.Background(),b,load,"digest",nil);err!=ErrUnavailable { t.Fatal(err) }
 if b.secretValue[0]!=0 { t.Fatal("oversized secret retained") }
}

func TestCreateDetectsCompetingRecord(t *testing.T) {
 for _, duplicate := range []bool{false,true} {
  b:=&fakeBus{prompt:"/",createDuplicate:duplicate}
  _,err:=execute(context.Background(),b,save,"digest",[]byte("synthetic"))
  if duplicate && err!=ErrAmbiguous || !duplicate && err!=nil { t.Fatal(err) }
 }
}
func TestMalformedPathsAndSessionOutputFailClosed(t *testing.T) {
 for _,b:=range []*fakeBus{
  {unlocked:[]dbus.ObjectPath{"/"}},
  {unlocked:[]dbus.ObjectPath{"not/a/path"}},
  {unlocked:[]dbus.ObjectPath{"/item"},invalidSessionOutput:true},
  {unlocked:[]dbus.ObjectPath{"/item"},nonStringSessionOutput:true},
 } {
  if _,err:=execute(context.Background(),b,save,"digest",[]byte("synthetic"));err!=ErrUnavailable { t.Fatal(err) }
  for _,call:=range b.calls { if strings.Contains(call,"SetSecret") || strings.Contains(call,"CreateItem") { t.Fatal("invalid response received secret") } }
 }
}

func TestRemoteErrorsNeverExposeMessages(t *testing.T) {
 for _, err := range []error{
  dbus.Error{Name:"org.freedesktop.Secret.Error.IsLocked",Body:[]any{"synthetic-private-detail"}},
  &dbus.Error{Name:"org.freedesktop.Secret.Error.IsLocked",Body:[]any{"synthetic-private-detail"}},
 } {
  if classifyError(err)!=ErrLocked { t.Fatal("locked error lost") }
 }
 if classifyError(dbus.Error{Name:"org.freedesktop.Secret.Error.NoSuchObject"})!=ErrNotFound { t.Fatal("not-found error lost") }
 if classifyError(dbus.Error{Name:"private-name",Body:[]any{"synthetic-private-detail"}})!=ErrUnavailable { t.Fatal("raw error exposed") }
}

func TestProviderKeepsStrictContentTypeAndEnvelopeBinding(t *testing.T){
 for _,contentType:=range []string{"application/octet-stream","text/plain; charset=utf-8","text/html"}{
  b:=&fakeBus{unlocked:[]dbus.ObjectPath{"/item"},secretValue:encodePassword("digest",[]byte("synthetic")),responseContentType:contentType}
  if out,err:=execute(context.Background(),b,load,"digest",nil);err!=ErrUnavailable || out!=nil{clear(out);t.Fatal("unexpected content type accepted")}
  for _,v:=range b.secretValue{if v!=0{t.Fatal("rejected wire bytes retained")}}
 }
 b:=&fakeBus{unlocked:[]dbus.ObjectPath{"/item"},secretValue:encodePassword("other-reference",[]byte("synthetic"))}
 if out,err:=execute(context.Background(),b,load,"digest",nil);err!=ErrUnavailable || out!=nil{clear(out);t.Fatal("cross-reference envelope accepted")}
 for _,v:=range b.secretValue{if v!=0{t.Fatal("rejected cross-reference bytes retained")}}
}
func TestProviderWritesVersionedTextEnvelope(t *testing.T){
 b:=&fakeBus{unlocked:[]dbus.ObjectPath{"/item"}}
 if _,err:=execute(context.Background(),b,save,"digest",[]byte{0,0xff,0xfe});err!=nil{t.Fatal(err)}
 defer clear(b.written.Value)
 if b.written.ContentType!="text/plain"{t.Fatal("write is not explicit text format")}
 out,err:=decodePassword("digest",b.written.Value);defer clear(out)
 if err!=nil || len(out)!=3 || out[0]!=0 || out[1]!=0xff || out[2]!=0xfe{t.Fatal("wire envelope changed password bytes")}
}

func TestEnvelopeDoesNotRelaxSessionOrParameters(t *testing.T){
 for _,b:=range []*fakeBus{
  {unlocked:[]dbus.ObjectPath{"/item"},responseSession:"/other_session",secretValue:encodePassword("digest",[]byte("synthetic"))},
  {unlocked:[]dbus.ObjectPath{"/item"},responseParameters:[]byte{1},secretValue:encodePassword("digest",[]byte("synthetic"))},
 } {
  out,err:=execute(context.Background(),b,load,"digest",nil)
  if err!=ErrUnavailable || out!=nil{clear(out);t.Fatal("invalid transport envelope accepted")}
  for _,v:=range b.secretValue{if v!=0{t.Fatal("invalid transport response retained")}}
 }
}
