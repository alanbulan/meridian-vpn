//go:build linux

package credentialstore

import (
 "context"
 "errors"
 "net"
 "os"
 "strconv"
 "strings"
 "syscall"

 "github.com/godbus/dbus/v5"
)

const servicePath dbus.ObjectPath = "/org/freedesktop/secrets"
const serviceInterface = "org.freedesktop.Secret.Service"
const itemInterface = "org.freedesktop.Secret.Item"
const collectionInterface = "org.freedesktop.Secret.Collection"

type secret struct {
 Session dbus.ObjectPath
 Parameters []byte
 Value []byte
 ContentType string
}

// bus is deliberately small so tests never need a real user's keyring.
type bus interface {
 call(context.Context, dbus.ObjectPath, string, []any, ...any) error
}
type systemBus struct { conn *dbus.Conn; owner string }
func (b systemBus) call(ctx context.Context, path dbus.ObjectPath, method string, args []any, out ...any) error {
 err := b.conn.Object(b.owner, path).CallWithContext(ctx, method, dbus.FlagNoAutoStart, args...).Store(out...)
 if err == nil { return nil }
 return classifyError(err)
}

func classifyError(err error) error {
 if err == nil { return nil }
 var remote dbus.Error
 var remotePointer *dbus.Error
 name := ""
 if errors.As(err, &remote) { name = remote.Name } else if errors.As(err, &remotePointer) && remotePointer != nil { name = remotePointer.Name }
 if name != "" {
  switch name {
  case "org.freedesktop.Secret.Error.IsLocked": return ErrLocked
  case "org.freedesktop.Secret.Error.NoSuchObject": return ErrNotFound
  }
 }
 return ErrUnavailable
}

// NewSystem performs no I/O and never starts/unlocks a keyring. Only the local
// user's standard Unix session bus is supported; TCP/environment-selected buses
// are deliberately rejected. A same-UID compromised desktop is out of scope.
func NewSystem() Store { return Store{run: systemRun} }

// Serialize in-process writes/reads. Other processes can still race: duplicate
// matches fail closed and are never repaired automatically.
var systemOperation = make(chan struct{}, 1)

func systemRun(ctx context.Context, op operation, key string, value []byte) ([]byte, error) {
 select { case systemOperation <- struct{}{}: case <-ctx.Done(): return nil, ctx.Err() }
 defer func(){ <-systemOperation }()
 uid := strconv.Itoa(os.Getuid())
 info, err := os.Stat("/run/user/"+uid)
 if err != nil { return nil, ErrUnavailable }
 stat, ok := info.Sys().(*syscall.Stat_t)
 if !ok || !info.IsDir() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 { return nil, ErrUnavailable }
 conn, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/user/"+uid+"/bus")
 if err != nil { return nil, ErrUnavailable }
 defer conn.Close()
 unix, ok := conn.(*net.UnixConn)
 if !ok { return nil, ErrUnavailable }
 raw, err := unix.SyscallConn()
 if err != nil { return nil, ErrUnavailable }
 var peer *syscall.Ucred
 var peerErr error
 if err = raw.Control(func(fd uintptr) { peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) }); err != nil || peerErr != nil || peer == nil || peer.Uid != uint32(os.Getuid()) { return nil, ErrUnavailable }
 if deadline, ok := ctx.Deadline(); ok { _ = conn.SetDeadline(deadline) }
 // Cancellation also interrupts synchronous SASL/Hello negotiation.
 stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
 defer stop()
 db, err := dbus.NewConn(conn, dbus.WithContext(ctx))
 if err != nil { return nil, ErrUnavailable }
 defer db.Close()
 if err = db.Auth([]dbus.Auth{dbus.AuthExternal(uid)}); err != nil { return nil, ErrUnavailable }
 if err = db.Hello(); err != nil { return nil, ErrUnavailable }
 var owner string
 if err = db.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, "org.freedesktop.secrets").Store(&owner); err != nil { return nil, ErrUnavailable }
 if !strings.HasPrefix(owner, ":") { return nil, ErrUnavailable }
 var ownerUID uint32
 if err = db.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, owner).Store(&ownerUID); err != nil || ownerUID != uint32(os.Getuid()) { return nil, ErrUnavailable }
 // Pin the unique owner for the operation rather than follow service replacement.
 return execute(ctx, systemBus{db, owner}, op, key, value)
}

func execute(ctx context.Context, b bus, op operation, key string, value []byte) ([]byte, error) {
 attrs := map[string]string{"application":"meridian-vpn", "kind":credentialKind, "reference":key}
 var unlocked, locked []dbus.ObjectPath
 if err := b.call(ctx, servicePath, serviceInterface+".SearchItems", []any{attrs}, &unlocked, &locked); err != nil { return nil, err }
 for _, path := range append(append([]dbus.ObjectPath(nil), unlocked...), locked...) {
  if path == "/" || !path.IsValid() { return nil, ErrUnavailable }
 }
 if len(locked) > 0 { return nil, ErrLocked }
 if len(unlocked) > 1 { return nil, ErrAmbiguous }
 if len(unlocked) == 0 && op != save { return nil, ErrNotFound }
 if op == remove {
  var prompt dbus.ObjectPath
  if err := b.call(ctx, unlocked[0], itemInterface+".Delete", nil, &prompt); err != nil { return nil, err }
  if prompt != "/" { return nil, ErrPromptRequired }
  return nil, nil
 }
 var collection dbus.ObjectPath
 if op == save && len(unlocked) == 0 {
  if err := b.call(ctx, servicePath, serviceInterface+".ReadAlias", []any{"default"}, &collection); err != nil { return nil, err }
  if collection == "/" || !collection.IsValid() { return nil, ErrUnavailable }
  var lockedValue dbus.Variant
  if err := b.call(ctx, collection, "org.freedesktop.DBus.Properties.Get", []any{collectionInterface, "Locked"}, &lockedValue); err != nil { return nil, err }
  isLocked, ok := lockedValue.Value().(bool)
  if !ok { return nil, ErrUnavailable }
  if isLocked { return nil, ErrLocked }
 }
 var session dbus.ObjectPath
 var output dbus.Variant
 // The specified plain algorithm relies on the local authenticated Unix bus.
 // No custom crypto is invented. See README for the threat model and release gate.
 if err := b.call(ctx, servicePath, serviceInterface+".OpenSession", []any{"plain", dbus.MakeVariant("")}, &output, &session); err != nil { return nil, err }
 negotiated, ok := output.Value().(string)
 if !ok || negotiated != "" { return nil, ErrUnavailable }
 if session == "/" || !session.IsValid() { return nil, ErrUnavailable }
 defer func() { _ = b.call(ctx, session, "org.freedesktop.Secret.Session.Close", nil) }()
 if op == load {
  var result secret
  if err := b.call(ctx, unlocked[0], itemInterface+".GetSecret", []any{session}, &result); err != nil { clear(result.Value); return nil, err }
  if result.Session != session || len(result.Parameters) != 0 || result.ContentType != "text/plain" || len(result.Value) == 0 || len(result.Value) > maxStoredBytes {
   clear(result.Value)
   return nil, ErrUnavailable
  }
  defer clear(result.Value)
  return decodePassword(key, result.Value)
 }
 encoded := encodePassword(key, value)
 defer clear(encoded)
 payload := secret{session, []byte{}, encoded, "text/plain"}
 if len(unlocked) == 1 {
  return nil, b.call(ctx, unlocked[0], itemInterface+".SetSecret", []any{payload})
 }
 props := map[string]dbus.Variant{
  itemInterface+".Label": dbus.MakeVariant("Meridian VPN password"),
  itemInterface+".Attributes": dbus.MakeVariant(attrs),
 }
 var item, prompt dbus.ObjectPath
 if err := b.call(ctx, collection, collectionInterface+".CreateItem", []any{props, payload, false}, &item, &prompt); err != nil { return nil, err }
 if prompt != "/" { return nil, ErrPromptRequired }
 if item == "/" || !item.IsValid() { return nil, ErrUnavailable }
 // A competing process can create another match. Never delete either record
 // or report a usable saved entry when the observed result is ambiguous.
 unlocked, locked = nil, nil
 if err := b.call(ctx, servicePath, serviceInterface+".SearchItems", []any{attrs}, &unlocked, &locked); err != nil { return nil, err }
 if len(locked) != 0 { return nil, ErrLocked }
 if len(unlocked) != 1 { return nil, ErrAmbiguous }
 if unlocked[0] != item { return nil, ErrUnavailable }
 return nil, nil
}
