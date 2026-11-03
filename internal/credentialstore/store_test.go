package credentialstore

import (
 "bytes"
 "context"
 "errors"
 "testing"
)

func reference() Reference { return Reference{"profile-a", "https://vpn.example", "anyconnect", "alice"} }

func TestConsentRequiredBeforeProvider(t *testing.T) {
 s := Store{run: func(context.Context, operation, string, []byte) ([]byte,error) { t.Fatal("provider called without consent"); return nil,nil }}
 for _, consent := range []Consent{NoConsent, UsePassword, DeletePassword} {
  if s.Save(context.Background(), reference(), []byte("synthetic"), consent) != ErrConsent { t.Fatal("save consent bypass") }
 }
 if _, err := s.Load(context.Background(), reference(), SavePassword); err != ErrConsent { t.Fatal(err) }
 if err := s.Delete(context.Background(), reference(), SavePassword); err != ErrConsent { t.Fatal(err) }
}
func TestReferenceExactBinding(t *testing.T) {
 original := reference(); key, _ := original.key()
 variants := []Reference{original, original, original, original}
 variants[0].ProfileID += "x"; variants[1].Gateway += "/"; variants[2].Protocol = "gp"; variants[3].Account = "bob"
 for _, r := range variants { other, err := r.key(); if err != nil || other == key { t.Fatal("reference collision") } }
 for _, gateway := range []string{"http://vpn.example", "https://alice:pass@vpn.example", "https://vpn.example?token=x", "https://vpn.example#x", "https:"} {
  r := original; r.Gateway = gateway
  if _, err := r.key(); err != ErrReference { t.Fatal("unsafe gateway accepted") }
 }
}
func TestSaveCopiesAndClearsOwnedSecret(t *testing.T) {
 original := []byte("synthetic-secret"); var observed []byte
 s := Store{run:func(_ context.Context, op operation, key string, input []byte)([]byte,error) {
  if op != save || len(key) != 64 || !bytes.Equal(input,original) { t.Fatal("wrong provider input") }
  observed = input; return nil,nil
 }}
 if err := s.Save(context.Background(),reference(), original, SavePassword); err != nil { t.Fatal(err) }
 if !bytes.Equal(original, []byte("synthetic-secret")) || !bytes.Equal(observed,make([]byte,len(observed))) { t.Fatal("incorrect ownership/erasure") }
}
func TestBoundErrorsAndCancellation(t *testing.T) {
 secret := []byte("sensitive provider error")
 s := Store{run:func(context.Context,operation,string,[]byte)([]byte,error){ return secret,errors.New(string(secret)) }}
 if _, err := s.Load(context.Background(),reference(),UsePassword); err != ErrUnavailable { t.Fatal("raw error exposed") }
 if !bytes.Equal(secret,make([]byte,len(secret))) { t.Fatal("error output retained") }
 s.run = func(context.Context,operation,string,[]byte)([]byte,error){ return make([]byte,MaxSecretBytes+1),nil }
 if _, err := s.Load(context.Background(),reference(),UsePassword); err != ErrUnavailable { t.Fatal("oversized value accepted") }
 ctx,cancel := context.WithCancel(context.Background()); cancel()
 s.run = func(context.Context,operation,string,[]byte)([]byte,error){ t.Fatal("cancelled provider called"); return nil,nil }
 if _, err := s.Load(ctx,reference(),UsePassword); err != context.Canceled { t.Fatal(err) }
}

func TestInvalidUTF8AndControlsCannotAliasIdentity(t *testing.T) {
 for _, invalid := range []string{string([]byte{0xff}),string([]byte{0xfe}),"alice\x00bob","alice\nbob"} {
  for field:=0;field<4;field++ {
   r:=reference()
   switch field {case 0:r.ProfileID=invalid;case 1:r.Gateway=invalid;case 2:r.Protocol=invalid;case 3:r.Account=invalid}
   if _,err:=r.key();err!=ErrReference { t.Fatal("invalid identity accepted") }
  }
 }
}
