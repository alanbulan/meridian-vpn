package windowsvpn

import (
 "errors"
 "testing"
 "unicode/utf16"
 "unsafe"
)

func TestEntryNameSDKLayout(t *testing.T) {
 var entry nativeEntryName
 if entryNameSize != 1048 || unsafe.Offsetof(entry.Name) != 4 || unsafe.Offsetof(entry.Flags) != 520 || unsafe.Offsetof(entry.Phonebook) != 524 { t.Fatal("RASENTRYNAMEW SDK layout mismatch") }
}
func setEntry(raw *nativeEntryName,name,path string) {
 copy(raw.Name[:],utf16.Encode([]rune(name)))
 copy(raw.Phonebook[:],utf16.Encode([]rune(path)))
}
func TestEnumeratePhonebooksWithoutCredentials(t *testing.T) {
 calls:=0
 entries,err := enumerateEntries(func(buffer []nativeEntryName,size,count *uint32) uint32 {
  calls++
  if len(buffer)==0 { *size=2*entryNameSize; return rasBufferTooSmall }
  if buffer[0].Size != entryNameSize { t.Fatal("missing version size") }
  setEntry(&buffer[0],"Office",`C:\Users\Example\rasphone.pbk`)
  setEntry(&buffer[1],"Office",`C:\ProgramData\rasphone.pbk`)
  *count=2
  return 0
 })
 if err != nil || calls != 2 || len(entries)!=2 { t.Fatalf("enumeration: %v",err) }
 if entries[0].Name != entries[1].Name || entries[0].PhonebookPath == entries[1].PhonebookPath { t.Fatal("lost phonebook identity") }
}
func TestEnumerationEmptyAndFailure(t *testing.T) {
 entries,err:=enumerateEntries(func([]nativeEntryName,*uint32,*uint32) uint32 { return 0 })
 if err!=nil || len(entries)!=0 { t.Fatal(err) }
 for _, code:=range []uint32{5,632,87} {
  _,err:=enumerateEntries(func([]nativeEntryName,*uint32,*uint32) uint32 { return code })
  if !errors.Is(err,ErrEnumeration) { t.Fatal(err) }
 }
}
func TestEnumerationRejectsBadLengths(t *testing.T) {
 for _, size:=range []uint32{0,1,maxEntryBuffer+1,^uint32(0)} {
  _,err:=enumerateEntries(func(_ []nativeEntryName,s,c *uint32) uint32 { *s=size; return rasBufferTooSmall })
  if !errors.Is(err,ErrEnumeration) { t.Fatal(size,err) }
 }
 _,err:=enumerateEntries(func(buffer []nativeEntryName,size,count *uint32) uint32 {
  if len(buffer)==0 { *size=entryNameSize;return rasBufferTooSmall }
  *count=2; return 0
 })
 if !errors.Is(err,ErrEnumeration) { t.Fatal("accepted oversized count") }
}
func TestEnumerationRetryIsBounded(t *testing.T) {
 calls:=0
 _,err:=enumerateEntries(func(_ []nativeEntryName,size,count *uint32) uint32 {
  calls++; *size=uint32(calls)*entryNameSize; return rasBufferTooSmall
 })
 if !errors.Is(err,ErrEnumeration) || calls!=4 { t.Fatal(calls,err) }
}
func TestFixedUTF16StrictDecoding(t *testing.T) {
 for _, data:=range [][]uint16{{1},{0xd800,0},{0xdc00,0},{0xd800,'a',0}} {
  if _,ok:=fixedUTF16(data);ok { t.Fatal("accepted malformed text") }
 }
 value,ok:=fixedUTF16([]uint16{'V',0xd83c,0xdf10,0})
 if !ok || value!="V🌐" { t.Fatal(value,ok) }
}
func TestEnumerationRejectsMalformedStrings(t *testing.T) {
 for _, malformed:=range []string{"name","path","surrogate"} {
  _,err:=enumerateEntries(func(buffer []nativeEntryName,size,count *uint32) uint32 {
   if len(buffer)==0 { *size=entryNameSize;return rasBufferTooSmall }
   setEntry(&buffer[0],"Office",`C:\Example\rasphone.pbk`)
   switch malformed {
   case "name": for i:=range buffer[0].Name { buffer[0].Name[i]='X' }
   case "path": clear(buffer[0].Phonebook[:])
   case "surrogate": buffer[0].Name[0]=0xd800;buffer[0].Name[1]=0
   }
   *count=1;return 0
  })
  if !errors.Is(err,ErrEnumeration) { t.Fatal(malformed,err) }
 }
}
func TestEnumerationRetriesGrowingPhonebook(t *testing.T) {
 calls:=0
 entries,err:=enumerateEntries(func(buffer []nativeEntryName,size,count *uint32) uint32 {
  calls++
  if calls<3 { *size=uint32(calls)*entryNameSize;return rasBufferTooSmall }
  setEntry(&buffer[0],"Office",`C:\Example\rasphone.pbk`)
  *size=entryNameSize;*count=1;return 0
 })
 if err!=nil || len(entries)!=1 || calls!=3 { t.Fatal(calls,err) }
}
