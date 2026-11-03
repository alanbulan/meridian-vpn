package windowsvpn

import (
 "errors"
 "unicode/utf16"
 "unsafe"
)

// PhonebookEntry is read-only discovery metadata, not a verified VPN or permission
// to connect. Entry names are not globally unique: retain PhonebookPath as well.
// This API never reads saved usernames, passwords, or PSKs. Names and paths
// may nevertheless contain personal or organization information. Do not log,
// persist, export, or send them as telemetry automatically.
type PhonebookEntry struct {
 Name string
 PhonebookPath string
 Flags uint32
}

var ErrEnumeration = errors.New("Windows RAS phonebook enumeration failed")

// RASENTRYNAMEW (WINVER >= 0x500), using fixed-width UTF-16 fields. This
// structure has no pointers and the same layout on Windows 32/64-bit targets.
// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377267(v=vs.85)
type nativeEntryName struct {
 Size uint32
 Name [257]uint16
 Flags uint32
 Phonebook [261]uint16
}

const (
 entryNameSize = uint32(unsafe.Sizeof(nativeEntryName{}))
 rasBufferTooSmall = uint32(603)
 maxEntryBuffer = uint32(16 * 1024 * 1024)
)

type enumerateEntriesFunc func([]nativeEntryName, *uint32, *uint32) uint32

// enumerateEntries bounds both allocation and retries if another process changes
// phonebooks during discovery. Only ERROR_SUCCESS permits consuming returned data.
func enumerateEntries(call enumerateEntriesFunc) ([]PhonebookEntry,error) {
 var size,count uint32
 code := call(nil,&size,&count)
 if code == 0 && size == 0 && count == 0 { return []PhonebookEntry{},nil }
 if code != rasBufferTooSmall { return nil,ErrEnumeration }
 for attempt:=0; attempt<3; attempt++ {
  if size < entryNameSize || size > maxEntryBuffer { return nil,ErrEnumeration }
  allocated := (size + entryNameSize - 1) / entryNameSize
  buffer := make([]nativeEntryName,allocated)
  buffer[0].Size = entryNameSize
  capacity := uint32(len(buffer))*entryNameSize
  size,count = capacity,0
  code = call(buffer,&size,&count)
  if code == rasBufferTooSmall { continue }
  if code != 0 || size > capacity || uint64(count)*uint64(entryNameSize) > uint64(size) || count > uint32(len(buffer)) { return nil,ErrEnumeration }
  result := make([]PhonebookEntry,0,count)
  for _, raw := range buffer[:count] {
   name,ok := fixedUTF16(raw.Name[:]); if !ok || name == "" { return nil,ErrEnumeration }
   path,ok := fixedUTF16(raw.Phonebook[:]); if !ok || path == "" { return nil,ErrEnumeration }
   result = append(result,PhonebookEntry{Name:name,PhonebookPath:path,Flags:raw.Flags})
  }
  return result,nil
 }
 return nil,ErrEnumeration
}

func fixedUTF16(value []uint16) (string,bool) {
 for i,unit := range value {
  if unit != 0 { continue }
  data := value[:i]
  for n:=0;n<len(data);n++ {
   if data[n] >= 0xd800 && data[n] <= 0xdbff {
    n++
    if n >= len(data) || data[n] < 0xdc00 || data[n] > 0xdfff { return "",false }
   } else if data[n] >= 0xdc00 && data[n] <= 0xdfff { return "",false }
  }
  return string(utf16.Decode(data)),true
 }
 return "",false
}
