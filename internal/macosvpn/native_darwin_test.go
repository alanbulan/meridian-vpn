//go:build darwin

package macosvpn

import ("testing"; "unsafe")

// These tests exercise the ABI wrapper with fake C-function bindings. They do
// not load frameworks, read actual profiles or connect a real system service.
func testAPI(t *testing.T, upper, lower string) (*nativeAPI, *[]uintptr) {
 t.Helper()
 released:=[]uintptr{}
 next:=uintptr(0)
 a:=&nativeAPI{
  release:func(p uintptr){released=append(released,p)},
  createString:func(alloc uintptr,s string,encoding uint32) uintptr {if alloc!=0||encoding!=utf8Encoding {t.Fatal("string ABI")};next++;return next},
  preferencesCreate:func(alloc,name,prefs uintptr)uintptr{if alloc!=0||name!=1||prefs!=0 {t.Fatal("preferences ABI")};return 10},
  serviceCopy:func(prefs,id uintptr)uintptr{if prefs!=10||id!=2 {t.Fatal("service ABI")};return 20},
  serviceEnabled:func(uintptr)uint8{return 1},
  serviceInterface:func(uintptr)uintptr{return 30},
  interfaceType:func(v uintptr)uintptr{return v},
  lowerInterface:func(uintptr)uintptr{return 40},
  stringCString:func(v uintptr,p *byte,n int,encoding uint32)uint8{
   text:=upper;if v==40 {text=lower}; if len(text)+1>n {return 0};b:=unsafe.Slice(p,n);copy(b,text);b[len(text)]=0;return 1
  },
  createConnection:func(alloc,id,callback,ctx uintptr)uintptr{if alloc!=0||id!=2||callback!=0||ctx!=0 {t.Fatal("connection ABI")};return 50},
  status:func(uintptr)int32{return int32(Disconnected)},
  start:func(ref,opts uintptr,linger uint8)uint8{if ref!=50||opts!=0||linger!=0 {t.Fatal("start must not override credentials or linger")};return 1},
  stop:func(ref uintptr,force uint8)uint8{if ref!=50||force!=0 {t.Fatal("stop must not force others off")};return 1},
 }
 return a,&released
}

func TestNativeServiceTypeRejectedBeforeConnection(t *testing.T) {
 for _,types:=range [][2]string{{"Ethernet","L2TP"},{"PPP","PPTP"},{"PPP","IPSec"},{"",""}} {
  a,released:=testAPI(t,types[0],types[1])
  a.createConnection=func(uintptr,uintptr,uintptr,uintptr)uintptr{t.Fatal("opened non-L2TP service");return 0}
  if _,err:=openWithAPI(a,"service-id");err==nil {t.Fatal("accepted wrong service type")}
  if len(*released)!=4 {t.Fatalf("leaked CF objects: %v",*released)}
 }
}
func TestNativeL2TPABIAndRelease(t *testing.T) {
 a,released:=testAPI(t,"PPP","L2TP")
 n,err:=openWithAPI(a,"service-id");if err!=nil {t.Fatal(err)}
 if len(*released)!=4 {t.Fatal("CF temporary objects leaked")}
 if n.status()!=Disconnected {t.Fatal("status ABI")}
 if err=n.start();err!=nil {t.Fatal(err)}
 if err=n.stop();err!=nil {t.Fatal(err)}
 n.close();n.close()
 if len(*released)!=5||(*released)[4]!=50 {t.Fatal("CF connection double release or leak")}
}
func TestNativeDisabledServiceRejected(t *testing.T) {
 a,_:=testAPI(t,"PPP","L2TP")
 a.serviceEnabled=func(uintptr)uint8{return 0}
 a.createConnection=func(uintptr,uintptr,uintptr,uintptr)uintptr{t.Fatal("opened disabled service");return 0}
 if _,err:=openWithAPI(a,"service-id");err==nil {t.Fatal("accepted disabled service")}
}
