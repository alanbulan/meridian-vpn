package macosvpn

import (
 "errors"
 "net"
 "net/netip"
 "strings"
)

// InterfaceEvidence is a bounded, instantaneous correlation of a system service
// and a live PPP interface. It proves neither exclusive ownership nor route/DNS
// policy, gateway reachability, cleanup, or sustained tunnel readiness.
type InterfaceEvidence struct {
 ServiceID string
 InterfaceName string
 InterfaceIndex int
 IPv4Addresses []netip.Addr
}

type systemEvidence struct {
 requestedID, actualID, interfaceName string
 extendedAddresses, serviceAddresses []string
}
type evidenceConnection interface { readSystemEvidence() (systemEvidence,error) }
type observedInterface struct { index int; flags net.Flags; addresses []netip.Addr }

// InspectInterface performs read-only inspection of this retained connection.
// Do not publish core.Session.Ready based on this result alone.
// Native and net.Interface reads are synchronous and not context-cancelable.
// They run under the session mutex and may delay Stop; this is not a bounded
// production-ready inspection path.
func (s *Session) InspectInterface() (InterfaceEvidence,error) {
 return s.inspectInterface(readInterface)
}
func (s *Session) inspectInterface(lookup func(string)(observedInterface,error)) (InterfaceEvidence,error) {
 s.mu.Lock();defer s.mu.Unlock()
 if s.native==nil {return InterfaceEvidence{},ErrClosed}
 if s.stopping {return InterfaceEvidence{},errors.New("system VPN is stopping")}
 if s.native.status()!=Connected {return InterfaceEvidence{},errors.New("system VPN is not connected")}
 reader,ok:=s.native.(evidenceConnection)
 if !ok {return InterfaceEvidence{},errors.New("native interface evidence is unavailable")}
 raw,err:=reader.readSystemEvidence();if err!=nil {return InterfaceEvidence{},err}
 result,err:=verifyEvidence(raw,lookup);if err!=nil {return InterfaceEvidence{},err}
 // Status is sampled around the reads. It is not an atomic snapshot and does
 // not exclude a disconnect/reconnect cycle between samples.
 if s.native.status()!=Connected {return InterfaceEvidence{},errors.New("system VPN state changed during inspection")}
 return result,nil
}
func verifyEvidence(raw systemEvidence, lookup func(string)(observedInterface,error)) (InterfaceEvidence,error) {
 fail:=func()(InterfaceEvidence,error){return InterfaceEvidence{},errors.New("system VPN interface evidence did not match")}
 if raw.requestedID==""||raw.actualID!=raw.requestedID {return fail()}
 name:=raw.interfaceName
 if !strings.HasPrefix(name,"ppp")||len(name)<4||len(name)>15 {return fail()}
 for _,c:=range name[3:] {if c<'0'||c>'9' {return fail()}}
 ext,err:=ipv4Set(raw.extendedAddresses);if err!=nil {return fail()}
 state,err:=ipv4Set(raw.serviceAddresses);if err!=nil||len(ext)!=len(state) {return fail()}
 for ip:=range ext {if _,ok:=state[ip];!ok {return fail()}}
 actual,err:=lookup(name);if err!=nil||actual.index<=0||actual.flags&net.FlagUp==0||actual.flags&net.FlagPointToPoint==0 {return fail()}
 present:=make(map[netip.Addr]bool,len(actual.addresses))
 for _,ip:=range actual.addresses {present[ip]=true}
 out:=InterfaceEvidence{ServiceID:raw.actualID,InterfaceName:name,InterfaceIndex:actual.index}
 // Preserve the bounded service order, without leaking raw native dictionaries.
 for _,text:=range raw.serviceAddresses {ip,_:=netip.ParseAddr(text);if !present[ip] {return fail()};out.IPv4Addresses=append(out.IPv4Addresses,ip)}
 return out,nil
}
func ipv4Set(values []string)(map[netip.Addr]struct{},error) {
 if len(values)==0||len(values)>16 {return nil,errors.New("invalid address count")}
 result:=make(map[netip.Addr]struct{},len(values))
 for _,s:=range values {
  ip,err:=netip.ParseAddr(s)
  if err!=nil||!ip.Is4()||!ip.IsGlobalUnicast()||ip.IsLinkLocalUnicast() {return nil,errors.New("invalid VPN IPv4 address")}
  if _,exists:=result[ip];exists {return nil,errors.New("duplicate VPN IPv4 address")}
  result[ip]=struct{}{}
 }
 return result,nil
}
func readInterface(name string)(observedInterface,error) {
 iface,err:=net.InterfaceByName(name);if err!=nil {return observedInterface{},err}
 addrs,err:=iface.Addrs();if err!=nil {return observedInterface{},err}
 out:=observedInterface{index:iface.Index,flags:iface.Flags}
 for _,addr:=range addrs {prefix,err:=netip.ParsePrefix(addr.String());if err!=nil {return observedInterface{},errors.New("unrecognized interface address")};out.addresses=append(out.addresses,prefix.Addr())}
 return out,nil
}
