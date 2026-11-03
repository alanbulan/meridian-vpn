// Package credentialstore provides an opt-in system credential store. It is not
// connected to the UI: constructing a Store does not contact a keyring.
package credentialstore

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "net/url"
 "time"
 "strings"
 "unicode"
 "unicode/utf8"
)

var (
 ErrConsent = errors.New("credential operation requires explicit consent")
 ErrReference = errors.New("invalid credential reference")
 ErrSecret = errors.New("invalid credential value")
 ErrUnavailable = errors.New("system credential store unavailable or item inaccessible")
 ErrNotFound = errors.New("saved password not found")
 ErrLocked = errors.New("system credential store is locked")
 ErrAmbiguous = errors.New("multiple matching saved passwords")
 ErrPromptRequired = errors.New("system credential store requires user interaction")
 ErrUnsupported = errors.New("system credential store unsupported")
)

// MaxSecretBytes bounds application credential values.
const MaxSecretBytes = 4096
const maxOutput = MaxSecretBytes

// Reference binds a saved password to the exact endpoint, profile and identity.
// Changing any field intentionally makes old credentials inaccessible. It must
// be built from the final connection target, not an imported keyring reference.
// Only reusable login passwords are supported, never OTPs, cookies or tokens.
type Reference struct {
 ProfileID string
 Gateway string
 Protocol string
 Account string
}

func (r Reference) key() (string, error) {
 for _, field := range []string{r.ProfileID, r.Gateway, r.Protocol, r.Account} {
  if field == "" || len(field) > 2048 || !utf8.ValidString(field) || strings.IndexFunc(field, unicode.IsControl) >= 0 { return "", ErrReference }
 }
 u, err := url.Parse(r.Gateway)
 if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" { return "", ErrReference }
 // JSON preserves field boundaries, unlike concatenation with a separator.
 raw, _ := json.Marshal(r)
 digest := sha256.Sum256(raw)
 return hex.EncodeToString(digest[:]), nil
}

// Consent is one operation's explicit user decision. Callers must never derive
// it from connection permission, successful login, a saved preference, or a
// server-supplied form. Saving includes replacing the password at this reference.
// This is an API guard, not proof of a UI interaction or an OS security boundary.
type Consent uint8
const (
 NoConsent Consent = iota
 SavePassword
 UsePassword
 DeletePassword
)

type operation uint8
const (save operation = iota; load; remove)
type runner func(context.Context, operation, string, []byte) ([]byte, error)
type Store struct { run runner }

func (s Store) invoke(ctx context.Context, r Reference, action operation, input []byte) ([]byte, error) {
 key, err := r.key()
 if err != nil { return nil, err }
 if err := ctx.Err(); err != nil { return nil, err }
 if s.run == nil { return nil, ErrUnsupported }
 ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
 defer cancel()
 out, err := s.run(ctx, action, key, input)
 if err != nil || len(out) > maxOutput {
  clear(out)
  if ctx.Err() != nil { return nil, ctx.Err() }
  switch err {
  case ErrNotFound, ErrLocked, ErrAmbiguous, ErrPromptRequired: return nil, err
  default: return nil, ErrUnavailable
  }
 }
 return out, nil
}

func (s Store) Save(ctx context.Context, r Reference, secret []byte, consent Consent) error {
 if consent != SavePassword { return ErrConsent }
 if len(secret) == 0 || len(secret) > MaxSecretBytes { return ErrSecret }
 copySecret := append([]byte(nil), secret...)
 defer clear(copySecret)
 out, err := s.invoke(ctx, r, save, copySecret)
 clear(out)
 return err
}

// Load returns caller-owned bytes; clear them immediately after use. Loading
// is not consent to connect or replay a password to a server.
func (s Store) Load(ctx context.Context, r Reference, consent Consent) ([]byte, error) {
 if consent != UsePassword { return nil, ErrConsent }
 out, err := s.invoke(ctx, r, load, nil)
 if err != nil { return nil, err }
 if len(out) == 0 { clear(out); return nil, ErrSecret }
 return out, nil
}

func (s Store) Delete(ctx context.Context, r Reference, consent Consent) error {
 if consent != DeletePassword { return ErrConsent }
 out, err := s.invoke(ctx, r, remove, nil)
 clear(out)
 return err
}
