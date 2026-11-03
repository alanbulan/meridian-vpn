package credentialstore

import (
 "bytes"
 "strings"
 "testing"
)

func TestEnvelopeRoundTrip(t *testing.T){
 key:=strings.Repeat("a",64)
 for _,value:=range [][]byte{[]byte("synthetic"),{0,0xff,0xfe,'\n','\r',0},bytes.Repeat([]byte{0xff},MaxSecretBytes)}{
  wire:=encodePassword(key,value)
  if len(wire)>maxStoredBytes{t.Fatal("valid envelope exceeded bound")}
  decoded,err:=decodePassword(key,wire)
  if err!=nil || !bytes.Equal(decoded,value){t.Fatal("binary password envelope failed")}
  clear(decoded);clear(wire)
 }
}
func TestEnvelopeRejectsInvalidVersionBindingAndEncoding(t *testing.T){
 key:=strings.Repeat("a",64);header:=envelopePrefix+key+":"
 cases:=[][]byte{
  []byte("synthetic-unversioned-password"),
  []byte("meridian-password-v1:"+key+":c3ludGhldGlj"),
  encodePassword(strings.Repeat("b",64),[]byte("synthetic")),
  []byte(header),[]byte(header+"YQ"),[]byte(header+"YR=="),
  []byte(header+"YQ==\n"),[]byte(header+"YQ==\r\n"),
  []byte(header+"YQ== "),[]byte(header+" YQ=="),[]byte(header+"YQ==\t"),
  []byte(header+"YQ==trailing"),[]byte(header+"!@#$"),
  encodePassword(key,bytes.Repeat([]byte{1},MaxSecretBytes+1)),
 }
 for _,wire:=range cases{out,err:=decodePassword(key,wire);if err!=ErrUnavailable || out!=nil{clear(out);t.Fatal("malformed envelope accepted")};clear(wire)}
}
