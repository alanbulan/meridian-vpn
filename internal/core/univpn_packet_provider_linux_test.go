//go:build linux

package core

import (
 "context"
 "errors"
 "io"
 "os"
 "syscall"
 "testing"
 "time"

 "mygo-vpn/internal/packetrelay"
)

const packetProviderSession = "0123456789abcdef0123456789abcdef"

func localTestPair() ([2]int, error) {
 return syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
}
func localTestWrap(f *os.File) (packetrelay.PacketIO, error) { return packetrelay.NewDatagramPackets(f) }

// These tests use real unnamed local socketpairs only. Failure to create one is
// a test failure, never a skip or evidence that host-network isolation passed.
func TestLocalPacketProviderRealPair(t *testing.T) {
 native, relay, err := (UniVPNLocalPacketProvider{}).AcquirePacket(context.Background(), packetProviderSession)
 if err != nil { t.Fatal(err) }
 defer native.Close(); defer relay.Close()
 for command, flag := range map[int]int{syscall.F_GETFD:syscall.FD_CLOEXEC, syscall.F_GETFL:syscall.O_NONBLOCK} {
  value, _, errno := syscall.Syscall(syscall.SYS_FCNTL, native.Fd(), uintptr(command), 0)
  if errno != 0 || int(value)&flag == 0 { t.Fatal("native endpoint missing required descriptor flag", errno) }
 }
 // The exact launcher duplication/validation path must accept the new endpoint.
 duplicate, err := duplicateUniVPNPacket(native)
 if err != nil { t.Fatal(err) }
 defer duplicate.owner.Close()
 if err = duplicate.file.SetReadDeadline(time.Now().Add(2*time.Second)); err != nil { t.Fatal(err) }
 // Keep datagrams separate: this must not behave like a byte stream.
 for _, message := range []string{"first", "second"} {
  if n, err := relay.WritePacket([]byte(message)); err != nil || n != len(message) { t.Fatal("write failed", n, err) }
 }
 buffer := make([]byte, 64)
 for _, want := range []string{"first", "second"} {
  n, err := duplicate.owner.ReadPacket(buffer)
  if err != nil || string(buffer[:n]) != want { t.Fatal("packet boundaries lost", err) }
 }
 if _, err = duplicate.owner.WritePacket([]byte("reply")); err != nil { t.Fatal(err) }
 // A bounded receive prevents a broken pair from hanging the test forever.
 done := make(chan error, 1)
 go func(){ n,e:=relay.ReadPacket(buffer);if e==nil && string(buffer[:n])!="reply" {e=errors.New("wrong paired endpoint")};done<-e }()
 select {case err=<-done: if err!=nil {t.Fatal(err)};case <-time.After(2*time.Second): relay.Close();t.Fatal("relay read did not return")}
}

func TestLocalPacketProviderCloseUnblocksRead(t *testing.T) {
 native, relay, err := (UniVPNLocalPacketProvider{}).AcquirePacket(context.Background(), packetProviderSession)
 if err != nil { t.Fatal(err) }; defer native.Close(); defer relay.Close()
 done := make(chan error,1)
 go func(){_,e:=relay.ReadPacket(make([]byte,32));done<-e}()
 if err=native.Close();err!=nil {t.Fatal(err)}
 select {case err=<-done:if !errors.Is(err,io.EOF) {t.Fatal("expected peer EOF",err)};case <-time.After(2*time.Second):relay.Close();t.Fatal("peer closure failed to wake reader")}
 if err=relay.Close();err!=nil {t.Fatal(err)}
 if err=relay.Close();err!=nil {t.Fatal("relay close is not idempotent",err)}
}

func TestLocalPacketProviderRejectsBeforeAllocation(t *testing.T) {
 for _, id := range []string{"", "session", "0123456789abcdef0123456789abcdeG"} {
  _,_,err:=acquireLocalPacket(context.Background(),id,func()([2]int,error){t.Fatal("allocated for bad identity");return [2]int{},nil},localTestWrap)
  if err==nil {t.Fatal("accepted bad identity")}
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 _,_,err:=acquireLocalPacket(ctx,packetProviderSession,func()([2]int,error){t.Fatal("allocated after cancellation");return [2]int{},nil},localTestWrap)
 if !errors.Is(err,context.Canceled) {t.Fatal(err)}
}

func TestLocalPacketProviderRollbackClosesBothEndpoints(t *testing.T) {
 for _, stage := range []string{"after-pair","wrap-failure","typed-nil-failure","typed-nil-success","after-wrap","close-uncertain"} {
  t.Run(stage,func(t *testing.T){
   ctx,cancel:=context.WithCancel(context.Background());defer cancel()
   var fds [2]int
   pair:=func()([2]int,error){var err error;fds,err=localTestPair();if stage=="after-pair" {cancel()};return fds,err}
   wrap:=func(f *os.File)(packetrelay.PacketIO,error){if stage=="wrap-failure" {return nil,errors.New("injected wrap failure")};if stage=="typed-nil-failure" {var p *packetrelay.DatagramPackets;return p,errors.New("typed nil wrapper failure")};if stage=="typed-nil-success" {var p *packetrelay.DatagramPackets;return p,nil};if stage=="close-uncertain" {f.Close();return nil,errors.New("injected premature close")};p,err:=localTestWrap(f);if stage=="after-wrap" {cancel()};return p,err}
   native,relay,err:=acquireLocalPacket(ctx,packetProviderSession,pair,wrap)
   if err==nil||native!=nil||relay!=nil {t.Fatal("partial allocation escaped",err)}
   if stage=="close-uncertain" {var cleanup *CleanupError;if !errors.As(err,&cleanup) {t.Fatal("uncertain close not reported",err)}}
   for _,fd:=range fds {_,_,errno:=syscall.Syscall(syscall.SYS_FCNTL,uintptr(fd),syscall.F_GETFD,0);if errno!=syscall.EBADF {t.Fatal("endpoint was not closed",errno)}}
  })
 }
}

func TestLocalPacketProviderAllocationFailure(t *testing.T) {
 want:=errors.New("allocation failed")
 n,r,err:=acquireLocalPacket(context.Background(),packetProviderSession,func()([2]int,error){return [2]int{},want},func(*os.File)(packetrelay.PacketIO,error){t.Fatal("wrapped after allocation failure");return nil,nil})
 if n!=nil||r!=nil||!errors.Is(err,want) {t.Fatal(err)}
}

func TestLocalPacketProviderCallsDoNotShareEndpoints(t *testing.T) {
 first, firstRelay, err := (UniVPNLocalPacketProvider{}).AcquirePacket(context.Background(),packetProviderSession)
 if err!=nil {t.Fatal(err)};defer first.Close();defer firstRelay.Close()
 second, secondRelay, err := (UniVPNLocalPacketProvider{}).AcquirePacket(context.Background(),packetProviderSession)
 if err!=nil {t.Fatal(err)};defer second.Close();defer secondRelay.Close()
 if _,err=firstRelay.WritePacket([]byte("first pair only"));err!=nil {t.Fatal(err)}
 raw,err:=second.SyscallConn();if err!=nil {t.Fatal(err)}
 var receiveErr error
 err=raw.Control(func(fd uintptr){_,_,_,_,receiveErr=syscall.Recvmsg(int(fd),make([]byte,32),nil,syscall.MSG_DONTWAIT)})
 if err!=nil||receiveErr!=syscall.EAGAIN {t.Fatal("packet leaked to another acquisition",err,receiveErr)}
}
