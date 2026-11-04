// Package windowsvpn defines a fail-closed, injectable Windows RAS controller.
// It deliberately ships without a native driver or application wiring. Its
// tests never load RAS, create phonebook entries, or change system networking.
package windowsvpn

import (
 "bytes"
 "errors"
 "net"
 "strings"
 "unicode/utf16"
 "unicode/utf8"
)

var (
 ErrUnsupported = errors.New("Windows RAS adapter supports only L2TP/IPsec with MSCHAPv2")
 ErrAuthorization = errors.New("explicit network and Windows PSK storage authorization required")
 ErrBusy = errors.New("Windows VPN session or unresolved cleanup already exists")
 ErrCleanup = errors.New("Windows VPN cleanup is unconfirmed; reconnect is blocked")
 ErrUnavailable = errors.New("native Windows RAS driver is not installed")
 ErrOperation = errors.New("Windows VPN operation failed")
 ErrVerification = errors.New("Windows VPN connection identity or interface could not be verified")
)

// Request contains no secrets. A future core bridge must reject unimplemented
// profile options rather than silently dropping them when building a Request.
type Request struct {
 Protocol string
 Gateway string
 Username string
 Domain string
 Authentication string
}

// Consent is per operation, never serialized with a profile. PSKStorage grants
// saving the PSK in Windows RAS for this session and attempting removal on Stop.
// It does not promise that a crash cannot leave a stored key behind.
type Consent struct { NetworkChanges, PSKStorage bool }

type Secrets struct { Password, PSK []byte }

func validText(s string, max int) bool {
 if s == "" || !utf8.ValidString(s) || len(utf16.Encode([]rune(s))) > max { return false }
 return !strings.ContainsAny(s, "\x00\r\n")
}

func validate(r Request, s Secrets, consent Consent) error {
 if r.Protocol != "l2tp" || (r.Authentication != "" && r.Authentication != "mschapv2") { return ErrUnsupported }
 if !consent.NetworkChanges || !consent.PSKStorage { return ErrAuthorization }
 if !validText(r.Username, 256) || (r.Domain != "" && !validText(r.Domain, 15)) { return errors.New("invalid Windows VPN username or domain") }
 if !validText(r.Gateway, 253) { return errors.New("invalid Windows VPN gateway") }
 if net.ParseIP(r.Gateway) == nil {
  for _, label := range strings.Split(strings.TrimSuffix(r.Gateway, "."), ".") {
   if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return errors.New("invalid Windows VPN gateway") }
   for _, c := range label { if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') { return errors.New("invalid Windows VPN gateway") } }
  }
 }
 for _, secret := range [][]byte{s.Password, s.PSK} {
  if !utf8.Valid(secret) || len(secret) == 0 || len(secret) > 1024 || bytes.ContainsAny(secret, "\x00\r\n") || secretUnits(secret) > 256 { return errors.New("invalid Windows VPN secret") }
 }
 return nil
}

// Count UTF-16 units without converting a secret to an immutable Go string.
func secretUnits(value []byte) int {
 units := 0
 for len(value) > 0 {
  r, size := utf8.DecodeRune(value)
  units++
  if r > 0xffff { units++ }
  value = value[size:]
 }
 return units
}
