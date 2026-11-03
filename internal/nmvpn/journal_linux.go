//go:build linux

package nmvpn

import (
 "bytes"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "syscall"
)

const journalName = "journal.json"
const journalLimit = 64 * 1024

// FileJournal exclusively owns a private directory's journal until Close.
// The persistent lock inode must never be removed: unlinking it would allow two
// processes to lock different inodes. Callers must hold this instance throughout
// their management lifecycle, not merely while reading or writing the journal.
// Records contain identifiers only; credentials must never be added to Record.
type FileJournal struct {
 mu sync.Mutex
 dir *os.File
 lock *os.File
}

// NewFileJournal opens every path component without following symbolic links.
// Only the final component may be created. Every ancestor must be owned by
// root or the effective user; writable ancestors must be sticky. This prevents
// another UID replacing a directory and obtaining a different lock inode.
// The final directory must belong to
// the effective user and have exactly mode 0700.
func NewFileJournal(path string) (*FileJournal, error) {
 if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" { return nil, errors.New("journal requires a clean absolute private directory") }
 fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
 if err != nil { return nil, err }
 components := strings.Split(strings.TrimPrefix(path,"/"),"/")
 for i, component := range components {
  if e := trustedAncestor(fd); e != nil { syscall.Close(fd); return nil, e }
  next, e := syscall.Openat(fd,component,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0)
  if e == syscall.ENOENT && i == len(components)-1 {
   e = syscall.Mkdirat(fd,component,0700)
   if e == nil { e = syscall.Fsync(fd) }
   if e == nil || e == syscall.EEXIST { next,e = syscall.Openat(fd,component,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0) }
  }
  syscall.Close(fd)
  if e != nil { return nil,e };fd=next
 }
 dir := os.NewFile(uintptr(fd),path)
 fail := func(err error)(*FileJournal,error){return nil,errors.Join(err,dir.Close())}
 var st syscall.Stat_t
 if err=syscall.Fstat(fd,&st);err!=nil{return fail(err)}
 if st.Uid!=uint32(os.Geteuid()) || st.Mode&07777!=0700 {return fail(errors.New("journal directory must be owned by effective user with mode 0700"))}
 lockFD,err:=syscall.Openat(fd,".journal.lock",syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0600)
 if err!=nil{return fail(err)}
 lock:=os.NewFile(uintptr(lockFD),"journal lock")
 if err=privateRegular(lockFD);err==nil {err=syscall.Flock(lockFD,syscall.LOCK_EX|syscall.LOCK_NB)}
 if err!=nil {err=errors.Join(err,lock.Close());return fail(err)}
 return &FileJournal{dir:dir,lock:lock},nil
}

func trustedAncestor(fd int) error {
 var st syscall.Stat_t
 if err := syscall.Fstat(fd, &st); err != nil { return err }
 if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && st.Mode&syscall.S_ISVTX == 0) {
  return errors.New("journal ancestor is not a trusted stable directory")
 }
 return nil
}

func privateRegular(fd int) error {
 var st syscall.Stat_t
 if err:=syscall.Fstat(fd,&st);err!=nil{return err}
 if st.Mode&syscall.S_IFMT!=syscall.S_IFREG || st.Mode&07777!=0600 || st.Uid!=uint32(os.Geteuid()) || st.Nlink!=1 {return errors.New("journal file must be a private owned regular file with one link")}
 return nil
}

func (j *FileJournal) Load() (*Record,error) {
 j.mu.Lock();defer j.mu.Unlock()
 if j.dir==nil{return nil,os.ErrClosed}
 fd,err:=syscall.Openat(int(j.dir.Fd()),journalName,syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0)
 if err==syscall.ENOENT{return nil,nil};if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(fd),journalName);defer f.Close()
 if err=privateRegular(fd);err!=nil{return nil,err}
 data,err:=io.ReadAll(io.LimitReader(f,journalLimit+1));if err!=nil{return nil,err}
 if len(data)>journalLimit{return nil,errors.New("journal exceeds size limit")}
 if err=rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(data)));err!=nil{return nil,err}
 dec:=json.NewDecoder(bytes.NewReader(data));dec.DisallowUnknownFields()
 var r Record
 if err=dec.Decode(&r);err!=nil{return nil,fmt.Errorf("invalid journal: %w",err)}
 var extra any
 if err=dec.Decode(&extra);err!=io.EOF{return nil,errors.New("journal contains trailing JSON")}
 if err=validateRecord(r);err!=nil{return nil,err}
 return &r,nil
}

func (j *FileJournal) Save(r Record) error {
 j.mu.Lock();defer j.mu.Unlock()
 if j.dir==nil{return os.ErrClosed}
 if err:=validateRecord(r);err!=nil{return err}
 data,err:=json.Marshal(r);if err!=nil{return err}
 if len(data)+1>journalLimit{return errors.New("journal exceeds size limit")};data=append(data,'\n')
 var token [16]byte
 if _,err=rand.Read(token[:]);err!=nil{return err}
 name:=".journal-"+hex.EncodeToString(token[:])+".tmp"
 fd,err:=syscall.Openat(int(j.dir.Fd()),name,syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0600)
 if err!=nil{return err}
 f:=os.NewFile(uintptr(fd),name)
 // Cleanup never follows links and never retries a possibly recycled FD.
 defer syscall.Unlinkat(int(j.dir.Fd()),name)
 if err=syscall.Fchmod(fd,0600);err==nil {_,err=f.Write(data)}
 if err==nil {err=f.Sync()}
 err=errors.Join(err,f.Close());if err!=nil{return err}
 if err=syscall.Renameat(int(j.dir.Fd()),name,int(j.dir.Fd()),journalName);err!=nil{return err}
 // An error here is an uncertain durability result; the new record may exist.
 return j.dir.Sync()
}

func (j *FileJournal) Clear() error {
 j.mu.Lock();defer j.mu.Unlock()
 if j.dir==nil{return os.ErrClosed}
 err:=syscall.Unlinkat(int(j.dir.Fd()),journalName)
 if err!=nil && err!=syscall.ENOENT{return err}
 return j.dir.Sync()
}

// Close releases lifecycle exclusivity. It does not delete the record or lock.
func (j *FileJournal) Close() error {
 j.mu.Lock();defer j.mu.Unlock()
 if j.dir==nil{return nil}
 err:=errors.Join(j.lock.Close(),j.dir.Close())
 j.lock=nil;j.dir=nil
 return err
}

// encoding/json otherwise silently accepts duplicate keys with last-value wins.
func rejectDuplicateKeys(dec *json.Decoder) error {
 tok,err:=dec.Token();if err!=nil{return err}
 delim,ok:=tok.(json.Delim);if !ok{return nil}
 switch delim {
 case '{':
  seen:=make(map[string]bool)
  for dec.More(){key,err:=dec.Token();if err!=nil{return err};s,ok:=key.(string);if !ok{return errors.New("invalid journal key")}
   // encoding/json accepts case-insensitive Unicode aliases (for example long s).
   // Restrict keys to the exact schema before its struct decoder can fold them.
   switch s { case "Version", "Identity", "Phase", "BootID", "BusID", "Owner", "UUID", "ActivePath", "Session", "Interface": default: return errors.New("noncanonical journal key") }
   if seen[s]{return errors.New("duplicate journal key")};seen[s]=true;if err=rejectDuplicateKeys(dec);err!=nil{return err}}
 case '[':
  return errors.New("journal arrays are invalid")
 default:return errors.New("invalid journal delimiter")
 }
 _,err=dec.Token();return err
}
