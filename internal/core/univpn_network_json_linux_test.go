//go:build linux

package core

import (
 "context"
 "testing"
)

func TestUniVPNKernelRoutesRejectUnknownAbsenceEvidence(t *testing.T){
 bad:=[]string{`null`,`{}`,`[null]`,`[{}]`,`[{"dst":"default"}]`,`[{"dst":"default","dev":"eth0","dev":"uvtun0"}]`,`[{"dst":"default","dev":"eth0","metric":null}]`,`[{"dst":"default","dev":"eth0","table":{}}]`,`[{"dst":"default","dev":"eth0","protocol":null}]`,`[{"dst":"bad","dev":"eth0"}]`,`[{"dst":"default","dev":"eth0","type":"unknown"}]`,`[{"dst":"default","nexthops":[{"dev":"uvtun0"}]}]`,`[{"dst":"default","type":"blackhole","nexthops":[{"dev":"uvtun0"}]}]`,`[{"dst":"default","dev":"eth0","encap":{"dev":"uvtun0"}}]`,`[{"dst":"default","nhid":7}]`,`[{"dst":"default","dev":"eth0","cache":{"x":1,"x":2}}]`,`[] []`}
 for _,input:=range bad {t.Run(input,func(t *testing.T){if _,e:=uniVPNDecodeRoutes([]byte(input));e==nil{t.Fatal("invalid route evidence accepted")}})}
 for _,input:=range []string{`[]`,`[{"dst":"default","dev":"eth0","protocol":"boot"}]`,`[{"dst":"10.0.0.0/8","type":"blackhole","table":254,"protocol":186}]`,`[{"dst":"127.0.0.1","dev":"lo","type":"local","protocol":"kernel"}]`}{if _,e:=uniVPNDecodeRoutes([]byte(input));e!=nil{t.Fatalf("valid supported route rejected: %s: %v",input,e)}}
}
func TestUniVPNKernelLinksRejectUnknownAbsenceEvidence(t *testing.T){
 bad:=[]string{`null`,`{}`,`[null]`,`[{}]`,`[{"ifindex":1}]`,`[{"ifname":"uvtun0"}]`,`[{"ifindex":77,"ifname":"uvtun0","ifindex":78}]`,`[{"ifindex":77,"ifname":"uvtun0"},{"ifindex":77,"ifname":"other"}]`,`[{"ifindex":77,"ifname":"uvtun0","addr_info":null}]`,`[{"ifindex":77,"ifname":"uvtun0","addr_info":[{}]}]`,`[{"ifindex":77,"ifname":"uvtun0","addr_info":[null]}]`,`[{"ifindex":77,"ifname":"uvtun0","addr_info":[{"local":"10.0.0.2","prefixlen":null}]}]`,`[{"ifindex":77,"ifname":"uvtun0","addr_info":[{"local":"10.0.0.2","prefixlen":33}]}]`,`[{"ifindex":77,"ifname":"uvtun0","linkinfo":{"info_kind":"tun","info_kind":"veth"}}]`}
 for _,input:=range bad {t.Run(input,func(t *testing.T){if _,e:=uniVPNDecodeLinks([]byte(input));e==nil{t.Fatal("invalid link evidence accepted")}})}
 for _,input:=range []string{`[]`,`[{"ifindex":1,"ifname":"lo"}]`,`[{"ifindex":77,"ifname":"uvtun0","addr_info":[{"local":"10.0.0.2","prefixlen":24}]}]`}{if _,e:=uniVPNDecodeLinks([]byte(input));e!=nil{t.Fatalf("valid link rejected: %s: %v",input,e)}}
}
func TestUniVPNNetworkAbsenceRejectsNullRoutes(t *testing.T){r:=&networkCommandMock{response:func(path string,args []string)([]byte,error){if path=="/trusted/resolvectl"{return []byte("Global:\n"),nil};if args[0]=="-json"{return []byte("[]"),nil};return []byte("null"),nil}};o:=commandOpsFixture(t,r);if e:=o.ProveAbsent(context.Background(),UniVPNNetworkConfig{Interface:"uvtun0",Index:77,Alias:"univpn-session-abcdef0123456789"});e==nil{t.Fatal("null route output proved absence")}}
