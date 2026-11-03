//go:build linux

package packetrelay

import (
 "context"
 "encoding/binary"
 "errors"
 "os"
 "syscall"
 "testing"
 "time"

 "golang.org/x/sys/unix"
)

// Every syscall/transport in these tests is injected. No TUN, netlink socket,
// namespace switch, or capability assumption is used, even in the success cases.
func kernelTestAttr(kind uint16, value []byte) []byte {
 b := make([]byte, kernelAlign(4+len(value)))
 binary.NativeEndian.PutUint16(b, uint16(4+len(value)))
 binary.NativeEndian.PutUint16(b[2:], kind)
 copy(b[4:], value)
 return b
}
func kernelTestU32(n uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b,n); return b }
func kernelTestReply(seq uint32) []byte {
 tun := []byte{}
 for k := uint16(3); k <= 7; k++ { v := byte(0); if k == 3 { v = unix.IFF_TUN }; tun = append(tun, kernelTestAttr(k, []byte{v})...) }
 info := append(kernelTestAttr(unix.IFLA_INFO_KIND, []byte("tun\x00")), kernelTestAttr(unix.IFLA_INFO_DATA, tun)...)
 b := make([]byte, 32)
 binary.NativeEndian.PutUint16(b[4:],unix.RTM_NEWLINK)
 binary.NativeEndian.PutUint32(b[8:],seq)
 binary.NativeEndian.PutUint32(b[12:],77)
 binary.NativeEndian.PutUint16(b[18:],unix.ARPHRD_NONE)
 binary.NativeEndian.PutUint32(b[20:],12)
 b = append(b, kernelTestAttr(unix.IFLA_IFNAME,[]byte("mrd0\x00"))...)
 b = append(b, kernelTestAttr(unix.IFLA_MTU,kernelTestU32(1500))...)
 b = append(b, kernelTestAttr(unix.IFLA_LINKINFO,info)...)
 binary.NativeEndian.PutUint32(b,uint32(len(b)))
 return b
}
func kernelTestAppend(b []byte, attr []byte) []byte { b = append(b,attr...); binary.NativeEndian.PutUint32(b,uint32(len(b))); return b }
func kernelTestChangeAttr(b []byte, path []uint16, change func([]byte)) {
 start := 32
 end := len(b)
 for _, want := range path {
  found := false
  for p := start; p+4 <= end; {
   n := int(binary.NativeEndian.Uint16(b[p:]))
   if binary.NativeEndian.Uint16(b[p+2:])&0x3fff == want {
    start, end, found = p+4, p+n, true
    if want == path[len(path)-1] { change(b[p:p+n]); return }
    break
   }
   p += kernelAlign(n)
  }
  if !found { panic("test attribute absent") }
 }
}
func TestKernelLinkReplyProjection(t *testing.T) {
 b := kernelTestReply(1)
 got, err := parseKernelLinkReply(b,1,77,"mrd0")
 want := KernelLinkObservation{Index:12,Name:"mrd0",Type:unix.ARPHRD_NONE,MTU:1500,Kind:"tun",TUNType:unix.IFF_TUN}
 if err != nil || got != want { t.Fatalf("got %+v, %v",got,err) }
 b = kernelTestAppend(b,kernelTestAttr(300,[]byte{1,2,3}))
 if _,err := parseKernelLinkReply(b,1,77,"mrd0"); err != nil { t.Fatalf("valid unknown additive attribute: %v",err) }
 // The kernel also uses unflagged nesting for compatibility. Both encodings
 // are accepted, with structural validation of every nested attribute.
 b = kernelTestReply(1)
 kernelTestChangeAttr(b,[]uint16{unix.IFLA_LINKINFO},func(a []byte){ binary.NativeEndian.PutUint16(a[2:],unix.IFLA_LINKINFO|0x8000) })
 if _,err := parseKernelLinkReply(b,1,77,"mrd0"); err != nil { t.Fatal(err) }
}
func TestKernelLinkRejectsMalformedReplies(t *testing.T) {
 cases := map[string]func([]byte) []byte{
  "short":func(b []byte) []byte{return b[:15]},
  "length":func(b []byte) []byte{binary.NativeEndian.PutUint32(b,15);return b},
  "trailing":func(b []byte) []byte{return append(b,0)},
  "second-message":func(b []byte) []byte{return append(b,b...)},
  "sequence":func(b []byte) []byte{binary.NativeEndian.PutUint32(b[8:],2);return b},
  "port":func(b []byte) []byte{binary.NativeEndian.PutUint32(b[12:],0);return b},
  "multipart":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[6:],unix.NLM_F_MULTI);return b},
  "unknown-flags":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[6:],0x8000);return b},
  "done":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[4:],unix.NLMSG_DONE);return b},
  "family":func(b []byte) []byte{b[16]=unix.AF_INET;return b},
  "pad":func(b []byte) []byte{b[17]=1;return b},
  "index-zero":func(b []byte) []byte{binary.NativeEndian.PutUint32(b[20:],0);return b},
  "index-negative":func(b []byte) []byte{binary.NativeEndian.PutUint32(b[20:],0xffffffff);return b},
  "ethernet":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[18:],unix.ARPHRD_ETHER);return b},
  "attr-short":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[32:],3);return b},
  "attr-overrun":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[32:],65535);return b},
  "attr-zero-type":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[34:],0);return b},
  "attr-network-byte-order":func(b []byte) []byte{binary.NativeEndian.PutUint16(b[34:],unix.IFLA_IFNAME|0x4000);return b},
  "name":func(b []byte) []byte{b[36]='x';return b},
  "missing-nul":func(b []byte) []byte{b[40]='x';return b},
  "embedded-nul":func(b []byte) []byte{b[37]=0;return b},
  "duplicate":func(b []byte) []byte{return kernelTestAppend(b,kernelTestAttr(unix.IFLA_MTU,kernelTestU32(1500)))},
  "unknown-nested-malformed":func(b []byte) []byte{return kernelTestAppend(b,kernelTestAttr(300|0x8000,[]byte{1,2,3}))},
 }
 for name, mutate := range cases { t.Run(name,func(t *testing.T){ if got,err:=parseKernelLinkReply(mutate(kernelTestReply(1)),1,77,"mrd0");err==nil || got!=(KernelLinkObservation{}) {t.Fatalf("accepted %+v, %v",got,err)} }) }
 for _,kind := range []uint16{3,4,5,6,7} { t.Run("tun-value-"+string(rune('0'+kind)),func(t *testing.T){ b:=kernelTestReply(1); kernelTestChangeAttr(b,[]uint16{unix.IFLA_LINKINFO,unix.IFLA_INFO_DATA,kind},func(a []byte){a[4]=2}); if _,err:=parseKernelLinkReply(b,1,77,"mrd0");err==nil {t.Fatal("accepted incompatible type/boolean")} }) }
 for _,path := range [][]uint16{{unix.IFLA_MTU},{unix.IFLA_LINKINFO,unix.IFLA_INFO_KIND},{unix.IFLA_LINKINFO,unix.IFLA_INFO_DATA,3}} {
  b:=kernelTestReply(1); kernelTestChangeAttr(b,path,func(a []byte){ binary.NativeEndian.PutUint16(a,4) }); if _,err:=parseKernelLinkReply(b,1,77,"mrd0");err==nil {t.Fatal("accepted missing required value")}
 }
}
func TestKernelLinkErrors(t *testing.T) {
 for _,code := range []int32{-int32(unix.ENODEV),0,1,-4096} {
  b:=make([]byte,36);binary.NativeEndian.PutUint32(b,36);binary.NativeEndian.PutUint16(b[4:],unix.NLMSG_ERROR);binary.NativeEndian.PutUint32(b[8:],1);binary.NativeEndian.PutUint32(b[12:],77);binary.NativeEndian.PutUint32(b[16:],uint32(code))
  _,err:=parseKernelLinkReply(b,1,77,"mrd0")
  if err==nil {t.Fatal("accepted error/unsolicited ACK")}
  if code == -int32(unix.ENODEV) && !errors.Is(err,unix.ENODEV) {t.Fatalf("lost errno: %v",err)}
 }
}

type kernelTestTransport struct {
 nsCalls, socketCalls, sendCalls, recvCalls, socketCloses, nsCloses int
 clock time.Time
 ops kernelLinkOps
}
func newKernelTestTransport() *kernelTestTransport {
 f:= &kernelTestTransport{clock:time.Unix(100,0)}
 f.ops=kernelLinkOps{
  namespace:func()(KernelNamespaceIdentity,func()error,error){f.nsCalls++;return KernelNamespaceIdentity{1,2},func()error{f.nsCloses++;return nil},nil},
  socket:func()(int,error){f.socketCalls++;return 9,nil},
  bind:func(fd int)error{if fd!=9{panic("wrong socket")};return nil},
  port:func(int)(uint32,error){return 77,nil},
  send:func(fd int,b []byte)error{f.sendCalls++;if fd!=9 || binary.NativeEndian.Uint16(b[4:])!=unix.RTM_GETLINK || binary.NativeEndian.Uint16(b[6:])!=unix.NLM_F_REQUEST || binary.NativeEndian.Uint32(b[12:])!=77 || binary.NativeEndian.Uint32(b[20:])!=0 {panic("non-read-only request")}; return nil},
  recv:func(_ int,b []byte)(int,int,unix.Sockaddr,error){f.recvCalls++;r:=kernelTestReply(uint32(f.recvCalls));return copy(b,r),0,&unix.SockaddrNetlink{Family:unix.AF_NETLINK},nil},
  poll:func(_ int,_ int16,ms int)(int16,error){f.clock=f.clock.Add(time.Duration(ms)*time.Millisecond);return 0,nil},
  close:func(fd int)error{if fd!=9{panic("wrong close")};f.socketCloses++;return nil},
  now:func()time.Time{return f.clock},
 }
 return f
}
func TestKernelLinkInjectedTransport(t *testing.T) {
 f:=newKernelTestTransport(); got,err:=readTUNKernelLinkWith(context.Background(),KernelNamespaceIdentity{1,2},"mrd0",f.ops)
 if err!=nil || got.Index!=12 || f.socketCalls!=1 || f.sendCalls!=2 || f.recvCalls!=2 || f.nsCalls!=3 || f.nsCloses!=3 || f.socketCloses!=1 {t.Fatalf("got %+v %v transport %+v",got,err,f)}
}
func TestKernelLinkTransportFailures(t *testing.T) {
 boom:=errors.New("injected")
 cases:=map[string]func(*kernelTestTransport){
  "namespace":func(f *kernelTestTransport){f.ops.namespace=func()(KernelNamespaceIdentity,func()error,error){return KernelNamespaceIdentity{1,3},nil,nil}},
  "namespace-drift":func(f *kernelTestTransport){base:=f.ops.namespace;f.ops.namespace=func()(KernelNamespaceIdentity,func()error,error){id,c,e:=base();if f.nsCalls==2{id.Inode++};return id,c,e}},
  "namespace-final-drift":func(f *kernelTestTransport){base:=f.ops.namespace;f.ops.namespace=func()(KernelNamespaceIdentity,func()error,error){id,c,e:=base();if f.nsCalls==3{id.Inode++};return id,c,e}},
  "namespace-error-with-handle":func(f *kernelTestTransport){base:=f.ops.namespace;f.ops.namespace=func()(KernelNamespaceIdentity,func()error,error){id,c,_:=base();return id,c,boom}},
  "socket":func(f *kernelTestTransport){f.ops.socket=func()(int,error){return -1,unix.EPERM}},
  "bind":func(f *kernelTestTransport){f.ops.bind=func(int)error{return boom}},
  "port":func(f *kernelTestTransport){f.ops.port=func(int)(uint32,error){return 0,nil}},
  "send":func(f *kernelTestTransport){f.ops.send=func(int,[]byte)error{return boom}},
  "recv":func(f *kernelTestTransport){f.ops.recv=func(int,[]byte)(int,int,unix.Sockaddr,error){return 0,0,nil,boom}},
  "timeout":func(f *kernelTestTransport){f.ops.recv=func(int,[]byte)(int,int,unix.Sockaddr,error){return 0,0,nil,unix.EAGAIN}},
  "poll-error":func(f *kernelTestTransport){f.ops.recv=func(int,[]byte)(int,int,unix.Sockaddr,error){return 0,0,nil,unix.EAGAIN};f.ops.poll=func(int,int16,int)(int16,error){return unix.POLLERR,nil}},
  "socket-cleanup":func(f *kernelTestTransport){f.ops.close=func(int)error{f.socketCloses++;return boom}},
  "namespace-cleanup":func(f *kernelTestTransport){base:=f.ops.namespace;f.ops.namespace=func()(KernelNamespaceIdentity,func()error,error){id,_,e:=base();return id,func()error{f.nsCloses++;return boom},e}},
 }
 for _,mode:=range []string{"foreign","multicast","wrong-family","truncated","ctruncated","name-change","index-change","oversized","empty","non-netlink"} {
  mode:=mode
  cases[mode]=func(f *kernelTestTransport){base:=f.ops.recv;f.ops.recv=func(fd int,b []byte)(int,int,unix.Sockaddr,error){n,flags,from,e:=base(fd,b);a:=from.(*unix.SockaddrNetlink);switch mode{case "foreign":a.Pid=4;case "multicast":a.Groups=1;case "wrong-family":a.Family=unix.AF_UNIX;case "truncated":flags=unix.MSG_TRUNC;case "ctruncated":flags=unix.MSG_CTRUNC;case "name-change":if f.recvCalls==2{b[36]='x'};case "index-change":if f.recvCalls==2{binary.NativeEndian.PutUint32(b[20:],13)};case "oversized":n=len(b)+1;case "empty":n=0;case "non-netlink":from=&unix.SockaddrUnix{}};return n,flags,from,e}}
 }
 for name,setup:=range cases{t.Run(name,func(t *testing.T){f:=newKernelTestTransport();setup(f);got,err:=readTUNKernelLinkWith(context.Background(),KernelNamespaceIdentity{1,2},"mrd0",f.ops);if err==nil || got!=(KernelLinkObservation{}){t.Fatalf("accepted %+v %v",got,err)};if f.socketCloses>1 || f.nsCloses>f.nsCalls{t.Fatal("double close")};if name=="socket-cleanup" || name=="namespace-cleanup"{if !errors.Is(err,ErrCleanup){t.Fatalf("cleanup not retained: %v",err)}};if name=="timeout" && !errors.Is(err,context.DeadlineExceeded){t.Fatal(err)}})}
}

func TestKernelLinkCancellationAndRetry(t *testing.T) {
 for _,when:=range []string{"before","send","poll","after-reply"} {
  t.Run(when,func(t *testing.T){f:=newKernelTestTransport();ctx,cancel:=context.WithCancel(context.Background());defer cancel();switch when{
  case "before":cancel()
  case "send":f.ops.send=func(int,[]byte)error{cancel();return unix.EAGAIN}
  case "poll":f.ops.recv=func(int,[]byte)(int,int,unix.Sockaddr,error){return 0,0,nil,unix.EAGAIN};f.ops.poll=func(int,int16,int)(int16,error){cancel();return 0,nil}
  case "after-reply":base:=f.ops.recv;f.ops.recv=func(fd int,b []byte)(int,int,unix.Sockaddr,error){n,flags,a,e:=base(fd,b);cancel();return n,flags,a,e}
  };_,err:=readTUNKernelLinkWith(ctx,KernelNamespaceIdentity{1,2},"mrd0",f.ops);if !errors.Is(err,context.Canceled){t.Fatal(err)};if when=="before" && f.socketCalls!=0{t.Fatal("opened after cancellation")}})
 }
 f:=newKernelTestTransport();send:=f.ops.send;recv:=f.ops.recv;attempt:=0
 f.ops.send=func(fd int,b []byte)error{attempt++;if attempt==1{return unix.EINTR};return send(fd,b)}
 readAttempt:=0;f.ops.recv=func(fd int,b []byte)(int,int,unix.Sockaddr,error){readAttempt++;if readAttempt==1{return 0,0,nil,unix.EAGAIN};return recv(fd,b)}
 if _,err:=readTUNKernelLinkWith(context.Background(),KernelNamespaceIdentity{1,2},"mrd0",f.ops);err!=nil{t.Fatal(err)}
}

func kernelTestNamespaceOps() kernelNamespaceOps {
 return kernelNamespaceOps{
  stat:func(_ int,st *unix.Stat_t)error{st.Mode=unix.S_IFREG|0444;st.Dev=7;st.Ino=9;return nil},
  statfs:func(_ int,fs *unix.Statfs_t)error{fs.Type=unix.NSFS_MAGIC;return nil},
  fcntl:func(_ uintptr,cmd,arg int)(int,error){if cmd!=unix.F_GETFD || arg!=0{panic("mutating fcntl")};return unix.FD_CLOEXEC,nil},
  ioctl:func(_ int,req uint)(int,error){if req!=unix.NS_GET_NSTYPE{panic("wrong ioctl")};return unix.CLONE_NEWNET,nil},
 }
}
func TestKernelNamespaceInspection(t *testing.T) {
 id,err:=inspectNetworkNamespaceRaw(&fakeRaw{},kernelTestNamespaceOps())
 if err!=nil || id!=(KernelNamespaceIdentity{7,9}){t.Fatalf("%+v %v",id,err)}
 for _,mode:=range []string{"stat","statfs","not-nsfs","not-regular","zero-inode","fcntl","cloexec","ioctl","wrong-type","raw"}{t.Run(mode,func(t *testing.T){ops:=kernelTestNamespaceOps();raw:=&fakeRaw{};boom:=errors.New("injected");switch mode{
 case "stat":ops.stat=func(int,*unix.Stat_t)error{return boom}
 case "statfs":ops.statfs=func(int,*unix.Statfs_t)error{return boom}
 case "not-nsfs":ops.statfs=func(_ int,s *unix.Statfs_t)error{s.Type=0;return nil}
 case "not-regular":ops.stat=func(_ int,s *unix.Stat_t)error{s.Mode=unix.S_IFDIR;s.Ino=9;return nil}
 case "zero-inode":ops.stat=func(_ int,s *unix.Stat_t)error{s.Mode=unix.S_IFREG;return nil}
 case "fcntl":ops.fcntl=func(uintptr,int,int)(int,error){return 0,boom}
 case "cloexec":ops.fcntl=func(uintptr,int,int)(int,error){return 0,nil}
 case "ioctl":ops.ioctl=func(int,uint)(int,error){return 0,boom}
 case "wrong-type":ops.ioctl=func(int,uint)(int,error){return unix.CLONE_NEWUSER,nil}
 case "raw":raw.err=boom
 };id,err:=inspectNetworkNamespaceRaw(raw,ops);if err==nil || id!=(KernelNamespaceIdentity{}){t.Fatalf("accepted %+v %v",id,err)}})}
 if _,err:=inspectNetworkNamespace(nil);err==nil{t.Fatal("nil namespace accepted")}
}

// This RawConn permits testing post-callback failures while modeling a retained
// TUN descriptor. It never contains or touches a kernel TUN descriptor.
type kernelPostControlRaw struct { after error }
func (r kernelPostControlRaw) Control(f func(uintptr))error{f(321);return r.after}
func (r kernelPostControlRaw) Read(func(uintptr)bool)error{panic("unexpected read")}
func (r kernelPostControlRaw) Write(func(uintptr)bool)error{panic("unexpected write")}
func TestOpenTUNNamespaceTransfersOwnership(t *testing.T) {
 for _,mode:=range []string{"success","ioctl-error","negative-fd","inspection-error","post-control-error"}{t.Run(mode,func(t *testing.T){
  // This object is only an opaque token; no os.NewFile/finalizer or real close.
  token:=new(os.File);wrapped,inspected:=0,0;boom:=errors.New("injected");var raw syscall.RawConn=kernelPostControlRaw{}
  if mode=="post-control-error"{raw=kernelPostControlRaw{after:boom}}
  f,id,err:=openTUNNetworkNamespaceWith(raw,func(fd int,req uint)(int,error){if fd!=321 || req!=unix.TUNGETDEVNETNS{t.Fatal("wrong descriptor/request")};if mode=="ioctl-error"{return -1,unix.EPERM};if mode=="negative-fd"{return -1,nil};return 456,nil},func(fd uintptr,_ string)*os.File{wrapped++;if fd!=456{t.Fatal("wrong acquired fd")};return token},func(f *os.File)(KernelNamespaceIdentity,error){inspected++;if f!=token{t.Fatal("wrong namespace")};if mode=="inspection-error"{return KernelNamespaceIdentity{},boom};return KernelNamespaceIdentity{7,9},nil})
  switch mode{case "success":if err!=nil || f!=token || id!=(KernelNamespaceIdentity{7,9}) || inspected!=1{t.Fatalf("%p %+v %v",f,id,err)}
  case "ioctl-error","negative-fd":if err==nil || f!=nil || wrapped!=0 || inspected!=0{t.Fatal("unexpected ownership")}
  default:if err==nil || f!=token || wrapped!=1{t.Fatal("lost acquired namespace on error")}}
 })}
}

func FuzzKernelLinkReply(f *testing.F) {
 f.Add(kernelTestReply(1))
 f.Add([]byte{})
 f.Fuzz(func(t *testing.T,b []byte){if len(b)>65536{return};got,err:=parseKernelLinkReply(b,1,77,"mrd0");if err!=nil && got!=(KernelLinkObservation{}){t.Fatal("partial observation on error")}})
}

func TestKernelLinkUnknownNestedLists(t *testing.T) {
 list:=append(kernelTestAttr(1,[]byte("first\x00")),kernelTestAttr(1,[]byte("second\x00"))...)
 b:=kernelTestAppend(kernelTestReply(1),kernelTestAttr(300|0x8000,list))
 if _,err:=parseKernelLinkReply(b,1,77,"mrd0");err!=nil{t.Fatal("valid unknown nested list rejected",err)}
 for i:=0;i<10;i++{list=kernelTestAttr(1|0x8000,list)}
 b=kernelTestAppend(kernelTestReply(1),kernelTestAttr(300|0x8000,list))
 if _,err:=parseKernelLinkReply(b,1,77,"mrd0");err==nil{t.Fatal("unbounded nesting accepted")}
}

func TestKernelLinkRejectsUnsupportedTUNAttributes(t *testing.T) {
 // Build the enclosing attributes again because insertion changes their size.
 for _,kind:=range []uint16{1,2,8,9}{t.Run(string(rune('0'+kind)),func(t *testing.T){
  b:=kernelTestReply(1)
  attrs,err:=kernelAttributes(b[32:],0);if err!=nil{t.Fatal(err)}
  info,err:=kernelAttributes(attrs[unix.IFLA_LINKINFO].value,1);if err!=nil{t.Fatal(err)}
  tun:=append(append([]byte(nil),info[unix.IFLA_INFO_DATA].value...),kernelTestAttr(kind,kernelTestU32(0))...)
  rebuilt:=append(kernelTestAttr(unix.IFLA_INFO_KIND,[]byte("tun\x00")),kernelTestAttr(unix.IFLA_INFO_DATA,tun)...)
  b=b[:32];b=append(b,kernelTestAttr(unix.IFLA_IFNAME,[]byte("mrd0\x00"))...);b=append(b,kernelTestAttr(unix.IFLA_MTU,kernelTestU32(1500))...);b=kernelTestAppend(b,kernelTestAttr(unix.IFLA_LINKINFO,rebuilt))
  if _,err:=parseKernelLinkReply(b,1,77,"mrd0");err==nil{t.Fatal("owner/group/multiqueue count accepted")}
 })}
}
