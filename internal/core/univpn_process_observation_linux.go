//go:build linux

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// UniVPNObservedInode identifies an opened object in the observer's namespace.
// It neither identifies the initial host namespace nor confers any authority.
type UniVPNObservedInode struct {
	Device uint64
	Inode  uint64
}

// UniVPNObservedExecutable describes the opened current executable, not all
// mapped code, loader/libraries, or an immutable execution history.
type UniVPNObservedExecutable struct {
	UniVPNObservedInode
	UID, GID, Mode uint32
	Size           int64
	ModifiedSec    int64
	ModifiedNS     int64
	ChangedSec     int64
	ChangedNS      int64
	SHA256         string
}

// UniVPNNMProcessObservation contains two matching, bounded observations of the
// broker's original child after its native offer was bound. Reads are NOT atomic:
// exec-away-and-back and changes immediately after reading cannot be excluded.
// UID and matching executable bytes do not prove sandboxing, exclusive host
// networking, the complete applied policy, or any TUN/relay/cleanup authority.
// Namespace identities are relative observations, not proof of a host namespace.
// These reads do not exclude ptrace or mutation by another authorized privileged
// process, nor prove that the sampled bytes are the only code ever executed.
type UniVPNNMProcessObservation struct {
	Session        string
	PID            int
	StartTimeTicks uint64
	UID, GID       [4]uint32 // real, effective, saved and filesystem IDs
	Executable     UniVPNObservedExecutable
	NetworkNS      UniVPNObservedInode
	MountNS        UniVPNObservedInode
	UserNS         UniVPNObservedInode
	PIDNS          UniVPNObservedInode
}

var errUniVPNProcessObservation = errors.New("original native process observation unavailable")

const (
	uniVPNProcMagic       = 0x9fa0
	uniVPNNSMagic         = 0x6e736673
	uniVPNProcStatLimit   = 8192
	uniVPNProcStatusLimit = 65536
	uniVPNProcImageLimit  = 64 * 1024 * 1024
)

// The pointer is installed before Launch returns and before the sole Wait can
// start. Pin failure is retained here without losing ownership of a started
// child or changing Launch's established cleanup contract.
type uniVPNProcessObservation struct {
	mu     sync.Mutex
	dir    *os.File
	pid    int
	start  uint64
	err    error
	closed bool
	// Package-private fixture seam. Production always uses the real reader and
	// a verified fixed /proc handle. No caller can supply a PID, root or reader.
	read func(context.Context, *os.File, int) (UniVPNNMProcessObservation, error)
}

func pinUniVPNOriginalProcess(p *uniVPNExecProcess) *uniVPNProcessObservation {
	bad := func() *uniVPNProcessObservation {
		return &uniVPNProcessObservation{err: errUniVPNProcessObservation}
	}
	if p == nil || p.cmd == nil || p.cmd.Process == nil || p.cmd.Process.Pid <= 0 {
		return bad()
	}
	rootFD, err := syscall.Open("/proc", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return bad()
	}
	root := os.NewFile(uintptr(rootFD), "univpn-proc")
	defer root.Close()
	if !uniVPNObservedFilesystem(rootFD, uniVPNProcMagic) {
		return bad()
	}
	// A proc mount from another PID namespace must not reinterpret the PID
	// returned by os/exec. Following this fixed kernel self link is intentional.
	selfFD, err := syscall.Openat(rootFD, "self", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return bad()
	}
	self := os.NewFile(uintptr(selfFD), "univpn-proc-self")
	if !uniVPNObservedFilesystem(selfFD, uniVPNProcMagic) {
		self.Close()
		return bad()
	}
	selfStat, err := readUniVPNProcFile(context.Background(), self, "stat", uniVPNProcStatLimit)
	selfStatus, statusErr := readUniVPNProcFile(context.Background(), self, "status", uniVPNProcStatusLimit)
	self.Close()
	if err != nil || statusErr != nil || !validUniVPNProcSelfStatus(selfStatus, os.Getpid()) {
		return bad()
	}
	if _, err = parseUniVPNProcStat(selfStat, os.Getpid()); err != nil {
		return bad()
	}
	pid := p.cmd.Process.Pid
	fd, err := syscall.Openat(rootFD, strconv.Itoa(pid), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return bad()
	}
	dir := os.NewFile(uintptr(fd), "univpn-original-process")
	if !uniVPNObservedFilesystem(fd, uniVPNProcMagic) {
		dir.Close()
		return bad()
	}
	return newUniVPNProcessObservation(dir, pid, readUniVPNRealProcess)
}

// Takes ownership of dir even on failure. Only tests substitute the reader or
// directory; production acquisition above is fixed and private.
func newUniVPNProcessObservation(dir *os.File, pid int, read func(context.Context, *os.File, int) (UniVPNNMProcessObservation, error)) *uniVPNProcessObservation {
	o := &uniVPNProcessObservation{dir: dir, pid: pid, read: read}
	if dir == nil || pid <= 0 || read == nil {
		o.err = errUniVPNProcessObservation
	} else {
		var first, second []byte
		first, o.err = readUniVPNProcFile(context.Background(), dir, "stat", uniVPNProcStatLimit)
		if o.err == nil {
			o.start, o.err = parseUniVPNProcStat(first, pid)
		}
		if o.err == nil {
			second, o.err = readUniVPNProcFile(context.Background(), dir, "stat", uniVPNProcStatLimit)
		}
		if o.err == nil {
			var start uint64
			start, o.err = parseUniVPNProcStat(second, pid)
			if start != o.start {
				o.err = errUniVPNProcessObservation
			}
		}
	}
	if o.err != nil {
		if dir != nil {
			dir.Close()
		}
		o.dir = nil
		o.err = errUniVPNProcessObservation
	}
	return o
}

func (o *uniVPNProcessObservation) close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	dir := o.dir
	o.dir = nil
	o.closed = true
	o.mu.Unlock()
	if dir != nil {
		return dir.Close()
	}
	return nil
}

func (o *uniVPNProcessObservation) observe(ctx context.Context, digest string) (UniVPNNMProcessObservation, error) {
	zero := UniVPNNMProcessObservation{}
	if o == nil || ctx == nil || ctx.Err() != nil || len(digest) != 2*sha256.Size {
		return zero, errUniVPNProcessObservation
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
		return zero, errUniVPNProcessObservation
	}
	// Duplicate under a short lock. Hashing and proc reads never hold it, so
	// Wait can invalidate the observation promptly without waiting for I/O.
	o.mu.Lock()
	if o.closed || o.err != nil || o.dir == nil || o.read == nil {
		o.mu.Unlock()
		return zero, errUniVPNProcessObservation
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, o.dir.Fd(), syscall.F_DUPFD_CLOEXEC, 3)
	pid, start, read := o.pid, o.start, o.read
	o.mu.Unlock()
	if errno != 0 {
		return zero, errUniVPNProcessObservation
	}
	dir := os.NewFile(fd, "univpn-process-observation")
	defer dir.Close()
	first, err := read(ctx, dir, pid)
	if err != nil || first.PID != pid || first.StartTimeTicks != start || first.Executable.SHA256 != digest {
		return zero, errUniVPNProcessObservation
	}
	second, err := read(ctx, dir, pid)
	if err != nil || first != second || ctx.Err() != nil {
		return zero, errUniVPNProcessObservation
	}
	o.mu.Lock()
	closed := o.closed || o.err != nil
	o.mu.Unlock()
	if closed {
		return zero, errUniVPNProcessObservation
	}
	return second, nil
}

// ObserveNativeProcess is optional read-only diagnostics for this broker's
// original concrete worker. It does not implement HostBinding, grant a lease,
// authorize activation/publication, or make the application ready. No caller PID
// or arbitrary process provider is accepted. A bootstrap-to-native exec is
// expected: the frozen native digest is checked only here, after the bound offer.
// Reads are bounded and check cancellation between operations, but kernel file
// operations are not guaranteed to be interruptible on an unhealthy filesystem.
func (b *UniVPNNMBroker) ObserveNativeProcess(ctx context.Context) (UniVPNNMProcessObservation, error) {
	zero := UniVPNNMProcessObservation{}
	if b.lock(ctx) != nil {
		return zero, errUniVPNProcessObservation
	}
	p, ok := b.process.(*uniVPNExecProcess)
	if !ok || !b.processObservableLocked(p) {
		b.gate <- struct{}{}
		return zero, errUniVPNProcessObservation
	}
	digest, session := b.launcher.ExecutableSHA256, b.binding.Identity.Session
	b.gate <- struct{}{}
	result, err := p.observation.observe(ctx, digest)
	if err != nil || result.Executable.UID != 0 || result.Executable.Mode&(0022|syscall.S_ISUID|syscall.S_ISGID|syscall.S_ISVTX) != 0 {
		return zero, errUniVPNProcessObservation
	}
	if b.lock(ctx) != nil {
		return zero, errUniVPNProcessObservation
	}
	defer func() { b.gate <- struct{}{} }()
	if b.process != p || !b.processObservableLocked(p) || b.binding.Identity.Session != session || ctx.Err() != nil {
		return zero, errUniVPNProcessObservation
	}
	result.Session = session
	return result, nil
}

func (b *UniVPNNMBroker) processObservableLocked(p *uniVPNExecProcess) bool {
	if p == nil || p.exited == nil || p.observation == nil || b.launcher == nil || b.run == nil || b.run.Err() != nil || !b.prepared || !b.bound || b.stopTried || b.stopped || b.uncertain || !uniVPNNMNonce.MatchString(p.sessionID) || p.sessionID != b.binding.Identity.Session || p.sessionID != b.offer.Session {
		return false
	}
	select {
	case <-p.exited:
		return false
	default:
	}
	if b.waitDone == nil {
		return false
	}
	select {
	case <-b.waitDone:
		return false
	default:
		return true
	}
}

func uniVPNObservedFilesystem(fd int, magic int64) bool {
	var st syscall.Statfs_t
	return syscall.Fstatfs(fd, &st) == nil && int64(st.Type) == magic
}

func readUniVPNProcFile(ctx context.Context, dir *os.File, name string, limit int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || dir == nil || (name != "stat" && name != "status") {
		return nil, errUniVPNProcessObservation
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errUniVPNProcessObservation
	}
	f := os.NewFile(uintptr(fd), "univpn-proc-field")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errUniVPNProcessObservation
	}
	data, err := io.ReadAll(io.LimitReader(uniVPNObservationReader{ctx, f}, limit+1))
	if err != nil || int64(len(data)) > limit || ctx.Err() != nil {
		return nil, errUniVPNProcessObservation
	}
	return data, nil
}

type uniVPNObservationReader struct {
	ctx context.Context
	r   io.Reader
}

func (r uniVPNObservationReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func parseUniVPNProcStat(data []byte, pid int) (uint64, error) {
	text := string(data)
	prefix := strconv.Itoa(pid) + " ("
	end := strings.LastIndex(text, ") ")
	if pid <= 0 || !strings.HasPrefix(text, prefix) || end < len(prefix) || len(data) > uniVPNProcStatLimit || !strings.HasSuffix(text, "\n") {
		return 0, errUniVPNProcessObservation
	}
	fields := strings.Fields(text[end+2:])
	// Field 3 is state; field 22 is starttime. Modern Linux exposes at least
	// 52 fields. comm may contain whitespace/parentheses; split only its tail.
	if len(fields) < 50 || len(fields[0]) != 1 || !strings.Contains("RSDTtI", fields[0]) {
		return 0, errUniVPNProcessObservation
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, errUniVPNProcessObservation
	}
	return start, nil
}

func parseUniVPNProcStatus(data []byte, pid int) (uid, gid [4]uint32, err error) {
	bad := func() ([4]uint32, [4]uint32, error) {
		return [4]uint32{}, [4]uint32{}, errUniVPNProcessObservation
	}
	if len(data) == 0 || len(data) > uniVPNProcStatusLimit || data[len(data)-1] != '\n' {
		return bad()
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || (key != "Pid" && key != "Tgid" && key != "Uid" && key != "Gid") {
			continue
		}
		if seen[key] {
			return bad()
		}
		seen[key] = true
		fields := strings.Fields(value)
		if key == "Pid" || key == "Tgid" {
			if len(fields) != 1 || fields[0] != strconv.Itoa(pid) {
				return bad()
			}
			continue
		}
		if len(fields) != 4 {
			return bad()
		}
		var ids [4]uint32
		for i, field := range fields {
			n, e := strconv.ParseUint(field, 10, 32)
			if e != nil {
				return bad()
			}
			ids[i] = uint32(n)
		}
		if key == "Uid" {
			uid = ids
		} else {
			gid = ids
		}
	}
	if !seen["Pid"] || !seen["Tgid"] || !seen["Uid"] || !seen["Gid"] {
		return bad()
	}
	return uid, gid, nil
}

// Conservatively reject a proc view that can number the child differently from
// os/exec. In particular, an outer proc mount exposes more than one NSpid value
// for a caller in a nested PID namespace. Missing support also fails closed.
func validUniVPNProcSelfStatus(data []byte, pid int) bool {
	if pid <= 0 {
		return false
	}
	if _, _, err := parseUniVPNProcStatus(data, pid); err != nil {
		return false
	}
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || key != "NSpid" {
			continue
		}
		fields := strings.Fields(value)
		if seen || len(fields) != 1 || fields[0] != strconv.Itoa(pid) {
			return false
		}
		seen = true
	}
	return seen
}

func readUniVPNRealProcess(ctx context.Context, dir *os.File, pid int) (UniVPNNMProcessObservation, error) {
	return readUniVPNProcessSample(ctx, dir, pid, true)
}

// requireNSFS is false only in package-private temporary-file fixtures. The
// production reader above always requires real namespace handles.
func readUniVPNProcessSample(ctx context.Context, dir *os.File, pid int, requireNSFS bool) (UniVPNNMProcessObservation, error) {
	zero := UniVPNNMProcessObservation{}
	stat, err := readUniVPNProcFile(ctx, dir, "stat", uniVPNProcStatLimit)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	start, err := parseUniVPNProcStat(stat, pid)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	status, err := readUniVPNProcFile(ctx, dir, "status", uniVPNProcStatusLimit)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	uid, gid, err := parseUniVPNProcStatus(status, pid)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	image, err := readUniVPNProcessImage(ctx, dir)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	nsFD, err := syscall.Openat(int(dir.Fd()), "ns", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	ns := os.NewFile(uintptr(nsFD), "univpn-process-namespaces")
	defer ns.Close()
	result := UniVPNNMProcessObservation{PID: pid, StartTimeTicks: start, UID: uid, GID: gid, Executable: image}
	for name, destination := range map[string]*UniVPNObservedInode{"net": &result.NetworkNS, "mnt": &result.MountNS, "user": &result.UserNS, "pid": &result.PIDNS} {
		if ctx.Err() != nil {
			return zero, errUniVPNProcessObservation
		}
		// Only these fixed kernel namespace magic links may be followed.
		fd, e := syscall.Openat(nsFD, name, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if e != nil {
			return zero, errUniVPNProcessObservation
		}
		var st syscall.Stat_t
		e = syscall.Fstat(fd, &st)
		validFS := !requireNSFS || uniVPNObservedFilesystem(fd, uniVPNNSMagic)
		closeErr := syscall.Close(fd)
		if e != nil || closeErr != nil || !validFS || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Ino == 0 {
			return zero, errUniVPNProcessObservation
		}
		*destination = UniVPNObservedInode{Device: uint64(st.Dev), Inode: st.Ino}
	}
	// Bracket the sample as well as comparing the two complete samples.
	stat, err = readUniVPNProcFile(ctx, dir, "stat", uniVPNProcStatLimit)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	end, err := parseUniVPNProcStat(stat, pid)
	if err != nil || end != start || ctx.Err() != nil {
		return zero, errUniVPNProcessObservation
	}
	return result, nil
}

func readUniVPNProcessImage(ctx context.Context, dir *os.File) (UniVPNObservedExecutable, error) {
	zero := UniVPNObservedExecutable{}
	if ctx == nil || ctx.Err() != nil || dir == nil {
		return zero, errUniVPNProcessObservation
	}
	// exe is a fixed procfs magic link. Opening it pins the actual executable;
	// readlink text or a subsequently reopened pathname would not do that.
	fd, err := syscall.Openat(int(dir.Fd()), "exe", syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return zero, errUniVPNProcessObservation
	}
	f := os.NewFile(uintptr(fd), "univpn-process-executable")
	defer f.Close()
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Mode&0111 == 0 || before.Nlink == 0 || before.Size <= 0 || before.Size > uniVPNProcImageLimit {
		return zero, errUniVPNProcessObservation
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(uniVPNObservationReader{ctx, f}, uniVPNProcImageLimit+1))
	if err != nil || n != before.Size || syscall.Fstat(fd, &after) != nil || uniVPNObservedImage(before) != uniVPNObservedImage(after) || ctx.Err() != nil {
		return zero, errUniVPNProcessObservation
	}
	result := uniVPNObservedImage(after)
	result.SHA256 = hex.EncodeToString(h.Sum(nil))
	return result, nil
}

func uniVPNObservedImage(st syscall.Stat_t) UniVPNObservedExecutable {
	return UniVPNObservedExecutable{
		UniVPNObservedInode: UniVPNObservedInode{Device: uint64(st.Dev), Inode: st.Ino},
		UID:                 st.Uid, GID: st.Gid, Mode: st.Mode, Size: st.Size,
		ModifiedSec: int64(st.Mtim.Sec), ModifiedNS: int64(st.Mtim.Nsec),
		ChangedSec: int64(st.Ctim.Sec), ChangedNS: int64(st.Ctim.Nsec),
	}
}
