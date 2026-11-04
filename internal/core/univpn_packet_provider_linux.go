//go:build linux

package core

import (
 "context"
 "errors"
 "os"
 "syscall"

 "mygo-vpn/internal/packetrelay"
)

// UniVPNLocalPacketProvider creates a fresh private packet channel per call.
// It opens only an unnamed AF_UNIX socketpair, never a TUN, listener, IP socket,
// route or resolver. It does not establish host-network ownership or isolation
// and is not wired into the default application. No descriptors are retained.
// Session IDs label acquisition requests; they are not proof of authorization.
type UniVPNLocalPacketProvider struct{}

var _ UniVPNPacketProvider = UniVPNLocalPacketProvider{}

func (UniVPNLocalPacketProvider) AcquirePacket(ctx context.Context, sessionID string) (*os.File, packetrelay.PacketIO, error) {
 return acquireLocalPacket(ctx, sessionID, func() ([2]int, error) {
  // Both flags are atomic at creation; no inheritable/blocking interval.
  return syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
 }, func(f *os.File) (packetrelay.PacketIO, error) { return packetrelay.NewDatagramPackets(f) })
}

// Private injection seams exercise cancellation and partial-acquisition cleanup.
// socketpair transfers exactly two distinct new FDs on success and none on error.
// wrap follows NewDatagramPackets: ownership transfers only on success.
func acquireLocalPacket(ctx context.Context, sessionID string, pair func() ([2]int, error), wrap func(*os.File) (packetrelay.PacketIO, error)) (*os.File, packetrelay.PacketIO, error) {
 if err := ctx.Err(); err != nil { return nil, nil, err }
 if len(sessionID) != 32 { return nil, nil, errors.New("invalid packet session identity") }
 for _, c := range sessionID { if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') { return nil, nil, errors.New("invalid packet session identity") } }
 fds, err := pair()
 if err != nil { return nil, nil, err }
 native := os.NewFile(uintptr(fds[0]), "meridian-native-packet")
 relayFile := os.NewFile(uintptr(fds[1]), "meridian-relay-packet")
 var relay packetrelay.PacketIO
 rollback := func(cause error) (*os.File, packetrelay.PacketIO, error) {
  // A failed Close is uncertainty, not a reason to retry a recycled FD number.
  closeErr := native.Close()
  if !nilInterface(relay) { closeErr = errors.Join(closeErr, relay.Close()) } else { closeErr = errors.Join(closeErr, relayFile.Close()) }
  if closeErr != nil { cause = errors.Join(cause, &CleanupError{}) }
  return nil, nil, cause
 }
 if err = ctx.Err(); err != nil { return rollback(err) }
 relay, err = wrap(relayFile)
 if err != nil { relay = nil; return rollback(err) }
 if nilInterface(relay) { return rollback(errors.New("packet channel wrapper unavailable")) }
 if err = ctx.Err(); err != nil { return rollback(err) }
 return native, relay, nil
}
