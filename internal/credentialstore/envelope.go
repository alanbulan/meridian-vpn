package credentialstore

import (
 "bytes"
 "encoding/base64"
)

// GNOME Secret Service currently returns text/plain even for binary input.
// Store an explicitly textual, versioned format instead of trusting an opaque
// content-type label as an encoding assertion. The namespace excludes old v1
// binary records, which were never enabled in the application.
const credentialKind = "login-password-base64-v2"
const envelopePrefix = "meridian-password-v2:"
const maxStoredBytes = len(envelopePrefix) + 64 + 1 + ((MaxSecretBytes + 2) / 3 * 4)

func encodePassword(key string, value []byte) []byte {
 header := envelopePrefix + key + ":"
 out := make([]byte,len(header)+base64.StdEncoding.EncodedLen(len(value)))
 copy(out,header)
 base64.StdEncoding.Encode(out[len(header):],value)
 return out
}

// decodePassword validates the exact version and reference binding, then only
// accepts canonical, padded base64 without whitespace or trailing material.
// The binding detects accidental cross-record reuse; it is not authentication
// against a malicious same-UID service that can read and rewrite both fields.
func decodePassword(key string, wire []byte) ([]byte,error) {
 header:=[]byte(envelopePrefix+key+":")
 if len(wire)>maxStoredBytes || !bytes.HasPrefix(wire,header) { return nil,ErrUnavailable }
 encoded:=wire[len(header):]
 if len(encoded)==0 || len(encoded)%4!=0 || bytes.IndexAny(encoded,"\r\n")>=0 { return nil,ErrUnavailable }
 decoded:=make([]byte,base64.StdEncoding.DecodedLen(len(encoded)))
 n,err:=base64.StdEncoding.Strict().Decode(decoded,encoded)
 if err!=nil || n==0 || n>MaxSecretBytes { clear(decoded);return nil,ErrUnavailable }
 return decoded[:n],nil
}
