//go:build darwin

package macosvpn

import (
 "errors"
 "sync"
 "unsafe"

 "github.com/ebitengine/purego"
)

// ABI: Apple SCNetworkConnection.h uses int32_t for Status and unsigned-char
// Boolean for Start/Stop. CFIndex is signed pointer-width on supported macOS.
// No Go callbacks or pointers are retained by SystemConfiguration.
type nativeAPI struct {
 release func(uintptr)
 createString func(uintptr, string, uint32) uintptr
 stringCString func(uintptr, *byte, int, uint32) uint8
 preferencesCreate func(uintptr, uintptr, uintptr) uintptr
 serviceCopy func(uintptr, uintptr) uintptr
 serviceEnabled func(uintptr) uint8
 serviceInterface func(uintptr) uintptr
 interfaceType func(uintptr) uintptr
 lowerInterface func(uintptr) uintptr
 createConnection func(uintptr, uintptr, uintptr, uintptr) uintptr
 status func(uintptr) int32
 start func(uintptr, uintptr, uint8) uint8
 stop func(uintptr, uint8) uint8
}
var apiOnce sync.Once
var sharedAPI *nativeAPI
var apiError error

func loadAPI() (*nativeAPI, error) {
 apiOnce.Do(func(){
  // Framework handles stay loaded for the process lifetime, like the functions.
  defer func(){ if recover()!=nil { sharedAPI=nil; apiError=errors.New("required SystemConfiguration API is unavailable") } }()
  cf,err:=purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",purego.RTLD_NOW|purego.RTLD_LOCAL)
  if err!=nil { apiError=errors.New("CoreFoundation is unavailable"); return }
  sc,err:=purego.Dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",purego.RTLD_NOW|purego.RTLD_LOCAL)
  if err!=nil { apiError=errors.New("SystemConfiguration is unavailable"); return }
  a:=&nativeAPI{}
  purego.RegisterLibFunc(&a.release,cf,"CFRelease")
  purego.RegisterLibFunc(&a.createString,cf,"CFStringCreateWithCString")
  purego.RegisterLibFunc(&a.stringCString,cf,"CFStringGetCString")
  purego.RegisterLibFunc(&a.preferencesCreate,sc,"SCPreferencesCreate")
  purego.RegisterLibFunc(&a.serviceCopy,sc,"SCNetworkServiceCopy")
  purego.RegisterLibFunc(&a.serviceEnabled,sc,"SCNetworkServiceGetEnabled")
  purego.RegisterLibFunc(&a.serviceInterface,sc,"SCNetworkServiceGetInterface")
  purego.RegisterLibFunc(&a.interfaceType,sc,"SCNetworkInterfaceGetInterfaceType")
  purego.RegisterLibFunc(&a.lowerInterface,sc,"SCNetworkInterfaceGetInterface")
  purego.RegisterLibFunc(&a.createConnection,sc,"SCNetworkConnectionCreateWithServiceID")
  purego.RegisterLibFunc(&a.status,sc,"SCNetworkConnectionGetStatus")
  purego.RegisterLibFunc(&a.start,sc,"SCNetworkConnectionStart")
  purego.RegisterLibFunc(&a.stop,sc,"SCNetworkConnectionStop")
  sharedAPI=a
 })
 return sharedAPI,apiError
}
const utf8Encoding uint32 = 0x08000100
func (a *nativeAPI) text(v uintptr) string {
 if v==0 { return "" }
 var b [128]byte
 if a.stringCString(v,&b[0],len(b),utf8Encoding)==0 { return "" }
 for i,c:=range b { if c==0 { return string(b[:i]) } }
 return ""
}
func openNative(id string) (connection,error) {
 a,err:=loadAPI(); if err!=nil { return nil,err }
 return openWithAPI(a,id)
}
func openWithAPI(a *nativeAPI,id string) (connection,error) {
 name:=a.createString(0,"Meridian L2TP existing service",utf8Encoding)
 if name==0 { return nil,errors.New("could not allocate service reference") }; defer a.release(name)
 prefs:=a.preferencesCreate(0,name,0)
 if prefs==0 { return nil,errors.New("could not read system VPN services") }; defer a.release(prefs)
 sid:=a.createString(0,id,utf8Encoding)
 if sid==0 { return nil,errors.New("could not allocate service identifier") }; defer a.release(sid)
 service:=a.serviceCopy(prefs,sid)
 if service==0 { return nil,errors.New("system VPN service not found") }; defer a.release(service)
 if a.serviceEnabled(service)==0 { return nil,errors.New("system VPN service is disabled") }
 iface:=a.serviceInterface(service)
 if iface==0 || a.text(a.interfaceType(iface))!="PPP" { return nil,errors.New("service is not PPP over L2TP") }
 lower:=a.lowerInterface(iface)
 if lower==0 || a.text(a.interfaceType(lower))!="L2TP" { return nil,errors.New("service is not PPP over L2TP") }
 ref:=a.createConnection(0,sid,0,0)
 if ref==0 { return nil,errors.New("could not open system VPN connection") }
 return &nativeConnection{a:a,ref:ref},nil
}
type nativeConnection struct { a *nativeAPI; ref uintptr }
func (n *nativeConnection) status() Status { return Status(n.a.status(n.ref)) }
func (n *nativeConnection) start() error {
 if n.a.start(n.ref,0,0)==0 { return errors.New("system rejected VPN start; check system configuration and authorization") }; return nil
}
func (n *nativeConnection) stop() error {
 if n.a.stop(n.ref,0)==0 { return errors.New("system rejected VPN stop") }; return nil
}
func (n *nativeConnection) close() { if n.ref!=0 { n.a.release(n.ref); n.ref=0 } }

// Assert pointer-width assumptions in supported 64-bit Darwin builds.
var _ [8-unsafe.Sizeof(uintptr(0))]byte
var _ [unsafe.Sizeof(uintptr(0))-8]byte
