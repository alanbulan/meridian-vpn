//go:build linux

package packetrelay

import (
 "bytes"
 "context"
 "encoding/binary"
 "errors"
 "os"
 "runtime"
 "syscall"
 "time"

 "golang.org/x/sys/unix"
)

var errTUNKernelObservation = errors.New("TUN kernel observation unavailable or changed")

// KernelNamespaceIdentity identifies a retained nsfs inode, not a host namespace.
type KernelNamespaceIdentity struct { Device, Inode uint64 }

// KernelLinkObservation is a comparable, historical projection of one GETLINK
// reply. Neither name nor ifindex is a device generation identity. Sequential
// matching observations cannot exclude ABA, name reuse, or concurrent mutation.
// Queue counts are absent for non-multiqueue devices; zero is not a measured count.
type KernelLinkObservation struct {
 Index int32
 Name string
 Type uint16
 Flags uint32
 MTU uint32
 Kind string
 TUNType uint8
 PI, VNetHeader, Persistent, MultiQueue bool
 QueueCountsPresent bool
 NumQueues, NumDisabledQueues uint32
}

type kernelNamespaceOps struct {
 stat func(int, *unix.Stat_t) error
 statfs func(int, *unix.Statfs_t) error
 fcntl func(uintptr, int, int) (int, error)
 ioctl func(int, uint) (int, error)
}

func realKernelNamespaceOps() kernelNamespaceOps {
 return kernelNamespaceOps{unix.Fstat, unix.Fstatfs, unix.FcntlInt, unix.IoctlRetInt}
}

func inspectNetworkNamespace(f *os.File) (KernelNamespaceIdentity, error) {
 if f == nil { return KernelNamespaceIdentity{}, errTUNKernelObservation }
 raw, err := f.SyscallConn()
 if err != nil { return KernelNamespaceIdentity{}, errors.Join(errTUNKernelObservation, err) }
 return inspectNetworkNamespaceRaw(raw, realKernelNamespaceOps())
}

func inspectNetworkNamespaceRaw(raw syscall.RawConn, ops kernelNamespaceOps) (KernelNamespaceIdentity, error) {
 var id KernelNamespaceIdentity
 if raw == nil { return id, errTUNKernelObservation }
 var inner error
 err := raw.Control(func(fd uintptr) {
  var st unix.Stat_t
  var fs unix.Statfs_t
  if inner = ops.stat(int(fd), &st); inner != nil { return }
  if inner = ops.statfs(int(fd), &fs); inner != nil { return }
  if fs.Type != unix.NSFS_MAGIC || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Ino == 0 {
   inner = errTUNKernelObservation; return
  }
  flags, e := ops.fcntl(fd, unix.F_GETFD, 0)
  if e != nil || flags&unix.FD_CLOEXEC == 0 { inner = errors.Join(errTUNKernelObservation, e); return }
  kind, e := ops.ioctl(int(fd), unix.NS_GET_NSTYPE)
  if e != nil || kind != unix.CLONE_NEWNET { inner = errors.Join(errTUNKernelObservation, e); return }
  id = KernelNamespaceIdentity{uint64(st.Dev), uint64(st.Ino)}
 })
 if err != nil || inner != nil { return KernelNamespaceIdentity{}, errors.Join(errTUNKernelObservation, err, inner) }
 return id, nil
}

// TUNGETDEVNETNS returns the device's current namespace under RTNL, with atomic
// CLOEXEC, and requires CAP_NET_ADMIN. The FD pins that namespace, not the TUN's
// placement. A non-nil file ALWAYS transfers ownership, including on error.
func openTUNNetworkNamespace(raw syscall.RawConn) (*os.File, KernelNamespaceIdentity, error) {
 return openTUNNetworkNamespaceWith(raw, unix.IoctlRetInt, os.NewFile, inspectNetworkNamespace)
}

func openTUNNetworkNamespaceWith(raw syscall.RawConn, ioctl func(int, uint) (int, error), wrap func(uintptr, string) *os.File, inspect func(*os.File) (KernelNamespaceIdentity, error)) (*os.File, KernelNamespaceIdentity, error) {
 var f *os.File
 var inner error
 if raw == nil { return nil, KernelNamespaceIdentity{}, errTUNKernelObservation }
 err := raw.Control(func(fd uintptr) {
  n, e := ioctl(int(fd), unix.TUNGETDEVNETNS)
  inner = e
  if e == nil && n >= 0 { f = wrap(uintptr(n), "meridian-tun-network-namespace") } else if e == nil { inner = errTUNKernelObservation }
 })
 if err != nil || inner != nil || f == nil { return f, KernelNamespaceIdentity{}, errors.Join(errTUNKernelObservation, err, inner) }
 id, err := inspect(f)
 if err != nil { return f, KernelNamespaceIdentity{}, errors.Join(errTUNKernelObservation, err) }
 return f, id, nil
}

// All dependencies are per-call and private. Production has no replaceable
// globals, arbitrary namespace provider/path, setns, dump, or mutation request.
type kernelLinkOps struct {
 namespace func() (KernelNamespaceIdentity, func() error, error)
 socket func() (int, error)
 bind func(int) error
 port func(int) (uint32, error)
 send func(int, []byte) error
 recv func(int, []byte) (int, int, unix.Sockaddr, error)
 poll func(int, int16, int) (int16, error)
 close func(int) error
 now func() time.Time
}

func realKernelLinkOps() kernelLinkOps {
 return kernelLinkOps{
  namespace: func() (KernelNamespaceIdentity, func() error, error) {
   f, err := os.OpenFile("/proc/thread-self/ns/net", os.O_RDONLY|unix.O_CLOEXEC, 0)
   if err != nil { return KernelNamespaceIdentity{}, nil, err }
   id, err := inspectNetworkNamespace(f)
   return id, f.Close, err
  },
  socket: func() (int, error) { return unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE) },
  bind: func(fd int) error { return unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) },
  port: func(fd int) (uint32, error) {
   a, err := unix.Getsockname(fd)
   if err != nil { return 0, err }
   n, ok := a.(*unix.SockaddrNetlink)
   if !ok || n.Family != unix.AF_NETLINK || n.Pid == 0 || n.Groups != 0 { return 0, errTUNKernelObservation }
   return n.Pid, nil
  },
  send: func(fd int, b []byte) error { return unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) },
  recv: func(fd int, b []byte) (int, int, unix.Sockaddr, error) { n, _, flags, from, err := unix.Recvmsg(fd, b, nil, 0); return n, flags, from, err },
  poll: func(fd int, events int16, ms int) (int16, error) {
   p := []unix.PollFd{{Fd: int32(fd), Events: events}}
   _, err := unix.Poll(p, ms)
   return p[0].Revents, err
  },
  close: unix.Close,
  now: time.Now,
 }
}

func readTUNKernelLink(ctx context.Context, expectedNS KernelNamespaceIdentity, name string) (KernelLinkObservation, error) {
 runtime.LockOSThread()
 defer runtime.UnlockOSThread()
 return readTUNKernelLinkWith(ctx, expectedNS, name, realKernelLinkOps())
}

func readTUNKernelLinkWith(ctx context.Context, expectedNS KernelNamespaceIdentity, name string, ops kernelLinkOps) (out KernelLinkObservation, resultErr error) {
 defer func() { if resultErr != nil { out = KernelLinkObservation{}; resultErr = errors.Join(errTUNKernelObservation, resultErr) } }()
 if ctx == nil || !tunResourceName.MatchString(name) || expectedNS.Inode == 0 { return out, errTUNKernelObservation }
 deadline := ops.now().Add(2*time.Second)
 if d, ok := ctx.Deadline(); ok && d.Before(deadline) { deadline = d }
 check := func() error {
  if err := ctx.Err(); err != nil { return err }
  if !ops.now().Before(deadline) { return context.DeadlineExceeded }
  return nil
 }
 if err := check(); err != nil { return out, err }
 // Retain every acquired namespace FD through socket I/O; cleanup uncertainty
 // invalidates the observation and is never retried using the numeric fd.
 var closers []func() error
 defer func() { for i := len(closers)-1; i >= 0; i-- { if err := closers[i](); err != nil { resultErr = errors.Join(resultErr, ErrCleanup, err) } } }()
 observeNS := func() error {
  id, closeNS, err := ops.namespace()
  if closeNS != nil { deferClose := closeNS; closers = append(closers, deferClose) }
  if err != nil || id != expectedNS { return errors.Join(errTUNKernelObservation, err) }
  return check()
 }
 if err := observeNS(); err != nil { return out, err }
 fd, err := ops.socket()
 if err != nil { return out, err }
 closers = append(closers, func() error { return ops.close(fd) })
 if err = observeNS(); err != nil { return out, err }
 if err = ops.bind(fd); err != nil { return out, err }
 port, err := ops.port(fd)
 if err != nil || port == 0 { return out, errors.Join(errTUNKernelObservation, err) }
 wait := func(events int16) error {
  if err := check(); err != nil { return err }
  left := deadline.Sub(ops.now())
  ms := int((left + time.Millisecond - 1)/time.Millisecond)
  if ms > 25 { ms = 25 }; if ms < 1 { ms = 1 }
  revents, err := ops.poll(fd, events, ms)
  if err != nil && !errors.Is(err, unix.EINTR) { return err }
  if revents & ^events != 0 { return errTUNKernelObservation }
  return check()
 }
 for seq := uint32(1); seq <= 2; seq++ {
  request := kernelLinkRequest(name, seq, port)
  for {
   if err = check(); err != nil { return out, err }
   err = ops.send(fd, request)
   if err == nil { break }
   if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) { return out, err }
   if err = wait(unix.POLLOUT); err != nil { return out, err }
  }
  buf := make([]byte, 65536)
  var current KernelLinkObservation
  for {
   if err = check(); err != nil { return out, err }
   n, flags, from, e := ops.recv(fd, buf)
   if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EINTR) {
    if err = wait(unix.POLLIN); err != nil { return out, err }; continue
   }
   if e != nil { return out, e }
   source, ok := from.(*unix.SockaddrNetlink)
   if !ok || source.Family != unix.AF_NETLINK || source.Pid != 0 || source.Groups != 0 || flags != 0 || n <= 0 || n > len(buf) { return out, errTUNKernelObservation }
   current, err = parseKernelLinkReply(buf[:n], seq, port, name)
   if err != nil { return out, err }
   break
  }
  if seq == 1 { out = current } else if current != out { return out, errTUNKernelObservation }
 }
 if err = observeNS(); err != nil { return out, err }
 return out, check()
}

func kernelAlign(n int) int { return (n + 3) &^ 3 }

func kernelLinkRequest(name string, seq, port uint32) []byte {
 n := 4 + len(name) + 1
 b := make([]byte, 32+kernelAlign(n))
 binary.NativeEndian.PutUint32(b, uint32(len(b)))
 binary.NativeEndian.PutUint16(b[4:], unix.RTM_GETLINK)
 binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST)
 binary.NativeEndian.PutUint32(b[8:], seq)
 binary.NativeEndian.PutUint32(b[12:], port)
 b[16] = unix.AF_UNSPEC
 binary.NativeEndian.PutUint16(b[32:], uint16(n))
 binary.NativeEndian.PutUint16(b[34:], unix.IFLA_IFNAME)
 copy(b[36:], name)
 return b
}

type kernelAttribute struct { flags uint16; value []byte }

// Unknown additive attributes are ignored only after bounded structural checks.
// This projection says nothing about omitted addresses, routes, XDP, or policy.
func kernelAttributes(b []byte, depth int) (map[uint16]kernelAttribute, error) {
 if depth > 8 { return nil, errTUNKernelObservation }
 attrs := make(map[uint16]kernelAttribute)
 for len(b) > 0 {
  if len(b) < 4 { return nil, errTUNKernelObservation }
  n := int(binary.NativeEndian.Uint16(b))
  tag := binary.NativeEndian.Uint16(b[2:])
  flags, kind := tag&0xc000, tag&0x3fff
  if n < 4 || n > len(b) || kernelAlign(n) > len(b) || flags&0x4000 != 0 || kind == 0 { return nil, errTUNKernelObservation }
  if _, exists := attrs[kind]; exists { return nil, errTUNKernelObservation }
  value := b[4:n]
  if flags&0x8000 != 0 { if err := validateKernelAttributeList(value, depth+1); err != nil { return nil, err } }
  attrs[kind] = kernelAttribute{flags, value}
  b = b[kernelAlign(n):]
 }
 return attrs, nil
}

// Unknown nested attributes can be lists (for example repeated ALT_IFNAME in
// PROP_LIST), not singleton dictionaries. Validate lengths and recursion here;
// interpreted LINKINFO/TUN schemas separately enforce duplicate-key rejection.
func validateKernelAttributeList(b []byte, depth int) error {
 if depth > 8 { return errTUNKernelObservation }
 for len(b) > 0 {
  if len(b) < 4 { return errTUNKernelObservation }
  n := int(binary.NativeEndian.Uint16(b))
  tag := binary.NativeEndian.Uint16(b[2:])
  if n < 4 || n > len(b) || kernelAlign(n) > len(b) || tag&0x4000 != 0 || tag&0x3fff == 0 { return errTUNKernelObservation }
  if tag&0x8000 != 0 { if err := validateKernelAttributeList(b[4:n], depth+1); err != nil { return err } }
  b = b[kernelAlign(n):]
 }
 return nil
}

func kernelString(a kernelAttribute) (string, bool) {
 b := a.value
 if a.flags != 0 || len(b) < 2 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 { return "", false }
 return string(b[:len(b)-1]), true
}

func parseKernelLinkReply(b []byte, seq, port uint32, name string) (KernelLinkObservation, error) {
 fail := func() (KernelLinkObservation, error) { return KernelLinkObservation{}, errTUNKernelObservation }
 if len(b) < 16 || int(binary.NativeEndian.Uint32(b)) != len(b) || len(b)%4 != 0 || binary.NativeEndian.Uint32(b[8:]) != seq || binary.NativeEndian.Uint32(b[12:]) != port { return fail() }
 typ, flags := binary.NativeEndian.Uint16(b[4:]), binary.NativeEndian.Uint16(b[6:])
 // No multipart/dump, echo, unsolicited notifications, or ACKs were requested.
 if typ == unix.NLMSG_ERROR {
  if len(b) < 36 || flags & ^uint16(unix.NLM_F_CAPPED|unix.NLM_F_ACK_TLVS) != 0 { return fail() }
  code := int32(binary.NativeEndian.Uint32(b[16:]))
  if code >= 0 || code < -4095 { return fail() }
  return KernelLinkObservation{}, errors.Join(errTUNKernelObservation, syscall.Errno(-code))
 }
 if typ != unix.RTM_NEWLINK || flags != 0 || len(b) < 32 || b[16] != unix.AF_UNSPEC || b[17] != 0 { return fail() }
 out := KernelLinkObservation{Index: int32(binary.NativeEndian.Uint32(b[20:])), Type: binary.NativeEndian.Uint16(b[18:]), Flags: binary.NativeEndian.Uint32(b[24:])}
 if out.Index <= 0 || out.Type != unix.ARPHRD_NONE { return fail() }
 attrs, err := kernelAttributes(b[32:], 0)
 if err != nil { return fail() }
 var ok bool
 out.Name, ok = kernelString(attrs[unix.IFLA_IFNAME])
 if !ok || out.Name != name || !tunResourceName.MatchString(out.Name) { return fail() }
 mtu := attrs[unix.IFLA_MTU]
 if mtu.flags != 0 || len(mtu.value) != 4 { return fail() }
 out.MTU = binary.NativeEndian.Uint32(mtu.value)
 if out.MTU == 0 { return fail() }
 info := attrs[unix.IFLA_LINKINFO]
 if len(info.value) == 0 { return fail() }
 nested, err := kernelAttributes(info.value, 1)
 if err != nil { return fail() }
 out.Kind, ok = kernelString(nested[unix.IFLA_INFO_KIND])
 if !ok || out.Kind != "tun" { return fail() }
 data := nested[unix.IFLA_INFO_DATA]
 if len(data.value) == 0 { return fail() }
 tun, err := kernelAttributes(data.value, 2)
 if err != nil { return fail() }
 // Linux v6.18 tun_fill_info uses u8 for type/booleans; owner/group and
 // optional queue counts use u32. Counts appear only with MULTI_QUEUE.
 for _, k := range []uint16{1, 2, 8, 9} {
  if a, exists := tun[k]; exists && (a.flags != 0 || len(a.value) != 4) { return fail() }
 }
 for k := uint16(3); k <= 7; k++ {
  a, exists := tun[k]
  if !exists || a.flags != 0 || len(a.value) != 1 { return fail() }
  if k == 3 { out.TUNType = a.value[0] } else if a.value[0] != 0 { return fail() }
 }
 if out.TUNType != unix.IFF_TUN { return fail() }
 // Strict resource mode is nonpersistent, no PI/vnet header, single queue.
 // Presence of either multiqueue-only count is incompatible, even if zero.
 if _, ok := tun[8]; ok { return fail() }; if _, ok := tun[9]; ok { return fail() }
 // Our fresh resource has no explicitly assigned owner/group.
 if _, ok := tun[1]; ok { return fail() }; if _, ok := tun[2]; ok { return fail() }
 return out, nil
}
