//go:build linux

package nmvpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	hostFileMaxFiles      = 16
	hostFileMaxBytes      = 64 * 1024
	hostFileMaxTotalBytes = 256 * 1024
	hostFileMaxDepth      = 32
	hostFileMaxPathBytes  = 4096
)

// HostFilePin identifies an explicitly provisioned file and its expected bytes.
// SHA256 must be exactly 64 lowercase hexadecimal characters. A manifest supplied
// by an untrusted caller is not trusted provisioning, even if every pin matches.
type HostFilePin struct {
	Path   string
	SHA256 string
}

// HostFileSnapshot is historical metadata, never file contents or host authority.
// It describes the retained inode observed during OpenHostFilePins. Use Check to
// revalidate it; neither operation prevents subsequent privileged writes.
type HostFileSnapshot struct {
	Path      string
	SHA256    string
	Device    uint64
	Inode     uint64
	Size      int64
	Mode      uint32
	OwnerUID  uint32
	OwnerGID  uint32
	LinkCount uint64
	Modified  time.Time
	Changed   time.Time
}

// HostFilePins retains read-only handles to files and every walked ancestor.
// It is not a HostAuthority or HostBinding. The caller's list cannot establish
// completeness of NM configuration fragments, dispatcher hooks, permissions or
// effective policy, process identity, network exclusivity, or readiness. This
// observer assumes trusted root and a trusted mount namespace/filesystem. It
// cannot prevent future writes, concurrent privileged namespace changes, or make
// sequential observations an atomic host-wide snapshot.
//
// Do not copy a HostFilePins value. Calls are serialized. A failed Check
// permanently invalidates the set; Close
// and explicitly open a new set rather than retrying an uncertain observation.
// Cancellation is checked between bounded operations, but cannot interrupt a
// filesystem syscall or mutex wait. Snapshots expose metadata only; this API
// never logs or writes file content. Unrelated ancestor changes also invalidate.
type HostFilePins struct {
	mu      sync.Mutex
	policy  hostFilePolicy
	files   []hostRetainedFile
	invalid error
	closed  bool
}

type hostFilePolicy struct {
	root       string
	uid        uint32
	production bool
}

type hostFileNode struct {
	file *os.File
	stat syscall.Stat_t
}

type hostRetainedFile struct {
	pin    HostFilePin
	digest [sha256.Size]byte
	nodes  []hostFileNode
}

// OpenHostFilePins only reads already-existing, explicitly pinned files. Real
// and effective UID must both be root. Paths must be clean, absolute, unique,
// and at most 4096 bytes / 32 components. All ancestors must be root-owned
// directories without group/world write access (including /tmp: no exception).
// Files must be root-owned regular files with one hard link, no group/world
// write access, and no set-ID/sticky bits. Owner write and execute bits are
// permitted: root writers remain trusted, and this API never executes anything.
// Symlinks are never followed. At most 16 files, 64 KiB per file and
// 256 KiB in total are accepted. No discovery, creation, chmod or repair occurs.
func OpenHostFilePins(ctx context.Context, pins []HostFilePin) (*HostFilePins, error) {
	return openHostFilePins(ctx, pins, hostFilePolicy{root: "/", uid: 0, production: true})
}

// The alternate root/UID exists solely for isolated package tests. Production
// callers have no override and always walk from the real filesystem root.
func openHostFilePins(ctx context.Context, pins []HostFilePin, policy hostFilePolicy) (*HostFilePins, error) {
	if err := hostFileContext(ctx); err != nil {
		return nil, err
	}
	if policy.production && (os.Getuid() != 0 || os.Geteuid() != 0) {
		return nil, errors.New("host file pins require real and effective root")
	}
	if !filepath.IsAbs(policy.root) || filepath.Clean(policy.root) != policy.root {
		return nil, errors.New("invalid host file root")
	}
	if len(pins) == 0 || len(pins) > hostFileMaxFiles {
		return nil, errors.New("host file pin count outside limits")
	}
	s := &HostFilePins{policy: policy}
	seen := make(map[string]bool)
	for _, pin := range pins {
		if _, err := hostFileComponents(pin.Path, policy.root); err != nil {
			return nil, err
		}
		if seen[pin.Path] {
			return nil, errors.New("duplicate host file path")
		}
		seen[pin.Path] = true
		if len(pin.SHA256) != 2*sha256.Size {
			return nil, errors.New("host file pin requires canonical SHA256")
		}
		digest, err := hex.DecodeString(pin.SHA256)
		if err != nil || len(digest) != sha256.Size || strings.ToLower(pin.SHA256) != pin.SHA256 {
			return nil, errors.New("host file pin requires canonical SHA256")
		}
		entry := hostRetainedFile{pin: pin}
		copy(entry.digest[:], digest)
		s.files = append(s.files, entry)
	}
	fail := func(err error) (*HostFilePins, error) { return nil, errors.Join(err, s.Close()) }
	identities := make(map[[2]uint64]bool)
	var total int64
	for i := range s.files {
		nodes, err := hostFileWalk(ctx, s.files[i].pin.Path, policy)
		if err != nil {
			return fail(err)
		}
		s.files[i].nodes = nodes
		st := nodes[len(nodes)-1].stat
		identity := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
		if identities[identity] {
			return fail(errors.New("duplicate host file inode"))
		}
		identities[identity] = true
		total += st.Size
		if total > hostFileMaxTotalBytes {
			return fail(errors.New("host file aggregate size exceeds limit"))
		}
	}
	if err := s.checkLocked(ctx); err != nil {
		return fail(err)
	}
	return s, nil
}

func hostFileContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("host file context is required")
	}
	return ctx.Err()
}

func hostFileComponents(path, root string) ([]string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > hostFileMaxPathBytes || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("host file requires a clean absolute bounded path")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, errors.New("host file is outside its trusted root")
	}
	parts := strings.Split(rel, "/")
	if len(parts) > hostFileMaxDepth {
		return nil, errors.New("host file path exceeds depth limit")
	}
	return parts, nil
}

func hostFileWalk(ctx context.Context, path string, policy hostFilePolicy) ([]hostFileNode, error) {
	parts, err := hostFileComponents(path, policy.root)
	if err != nil {
		return nil, err
	}
	var nodes []hostFileNode
	fail := func(err error) ([]hostFileNode, error) { return nil, errors.Join(err, hostFileCloseNodes(nodes)) }
	for i := -1; i < len(parts); i++ {
		if err := hostFileContext(ctx); err != nil {
			return fail(err)
		}
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		} else {
			// The owner/root-only contract permits suppressing read-atime writes.
			flags |= syscall.O_NOATIME
		}
		var fd int
		if i == -1 {
			fd, err = syscall.Open(policy.root, flags, 0)
		} else if i < len(parts)-1 {
			fd, err = syscall.Openat(int(nodes[len(nodes)-1].file.Fd()), parts[i], flags, 0)
		} else {
			fd, err = hostFileOpenRegular(int(nodes[len(nodes)-1].file.Fd()), parts[i], flags, policy)
		}
		if err != nil {
			return fail(fmt.Errorf("open pinned host file component: %w", err))
		}
		f := os.NewFile(uintptr(fd), "pinned host file component")
		nodes = append(nodes, hostFileNode{file: f})
		st := &nodes[len(nodes)-1].stat
		if err = syscall.Fstat(fd, st); err != nil {
			return fail(err)
		}
		if st.Uid != policy.uid {
			return fail(errors.New("host file component has untrusted owner"))
		}
		if i < len(parts)-1 {
			if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&0022 != 0 {
				return fail(errors.New("host file ancestor is not a stable trusted directory"))
			}
		} else if err := hostFileRegularStat(*st, policy); err != nil {
			return fail(err)
		}
	}
	if err := hostFileVerifyNodes(ctx, nodes); err != nil {
		return fail(err)
	}
	return nodes, nil
}

func hostFileRegularStat(st syscall.Stat_t, policy hostFilePolicy) error {
	if st.Uid != policy.uid || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07022 != 0 || st.Nlink != 1 || st.Size < 0 || st.Size > hostFileMaxBytes {
		return errors.New("host file must be a bounded trusted regular file with one link and safe permissions")
	}
	return nil
}

func hostFileOpenRegular(parent int, name string, flags int, policy hostFilePolicy) (int, error) {
	// Inspect with O_PATH first, so rejected devices/FIFOs/sockets are not
	// opened for I/O. Trusted root can still change the namespace; compare the
	// actual read handle with this observation, never trust the pathname alone.
	probe, err := syscall.Openat(parent, name, unix.O_PATH|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return -1, err
	}
	var before syscall.Stat_t
	err = syscall.Fstat(probe, &before)
	if err == nil {
		err = hostFileRegularStat(before, policy)
	}
	err = errors.Join(err, syscall.Close(probe))
	if err != nil {
		return -1, err
	}
	fd, err := syscall.Openat(parent, name, flags, 0)
	if err != nil {
		return -1, err
	}
	var after syscall.Stat_t
	err = syscall.Fstat(fd, &after)
	if err == nil && !hostFileSameStat(before, after) {
		err = errors.New("host file changed while opening")
	}
	if err != nil {
		return -1, errors.Join(err, syscall.Close(fd))
	}
	return fd, nil
}

func hostFileSameStat(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Ctim == b.Ctim && a.Mtim == b.Mtim && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink
}

func hostFileVerifyNodes(ctx context.Context, nodes []hostFileNode) error {
	for _, node := range nodes {
		if err := hostFileContext(ctx); err != nil {
			return err
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(int(node.file.Fd()), &st); err != nil {
			return err
		}
		if !hostFileSameStat(st, node.stat) {
			return errors.New("pinned host file component changed")
		}
	}
	return nil
}

func hostFileCloseNodes(nodes []hostFileNode) error {
	var err error
	for i := len(nodes) - 1; i >= 0; i-- {
		// Never retry Close: even an error can leave the descriptor recycled.
		err = errors.Join(err, nodes[i].file.Close())
	}
	return err
}

func hostFileHash(ctx context.Context, node hostFileNode, limit int64) ([sha256.Size]byte, int64, error) {
	var digest [sha256.Size]byte
	if err := hostFileVerifyNodes(ctx, []hostFileNode{node}); err != nil {
		return digest, 0, err
	}
	limit = min(limit, int64(hostFileMaxBytes))
	if node.stat.Size > limit {
		return digest, 0, errors.New("host file aggregate size exceeds limit")
	}
	h := sha256.New()
	var buf [16 * 1024]byte
	var offset int64
	for {
		if err := hostFileContext(ctx); err != nil {
			return digest, offset, err
		}
		// One extra byte detects growth; never read unboundedly to find EOF.
		count := min(int64(len(buf)), limit+1-offset)
		n, err := syscall.Pread(int(node.file.Fd()), buf[:int(count)], offset)
		if err != nil {
			return digest, offset, err
		}
		offset += int64(n)
		if offset > limit {
			return digest, offset, errors.New("host file read exceeds byte limit")
		}
		_, _ = h.Write(buf[:n])
		if n == 0 {
			break
		}
	}
	if err := hostFileVerifyNodes(ctx, []hostFileNode{node}); err != nil {
		return digest, offset, err
	}
	if offset != node.stat.Size {
		return digest, offset, errors.New("host file length changed while reading")
	}
	copy(digest[:], h.Sum(nil))
	return digest, offset, nil
}

func (s *HostFilePins) checkLocked(ctx context.Context) error {
	if err := hostFileContext(ctx); err != nil {
		return err
	}
	if s.policy.production && (os.Getuid() != 0 || os.Geteuid() != 0) {
		return errors.New("host file pins require real and effective root")
	}
	var total int64
	for _, entry := range s.files {
		if err := hostFileVerifyNodes(ctx, entry.nodes); err != nil {
			return err
		}
		fresh, err := hostFileWalk(ctx, entry.pin.Path, s.policy)
		if err != nil {
			return err
		}
		checkErr := func() error {
			if len(fresh) != len(entry.nodes) {
				return errors.New("pinned host file walk changed")
			}
			for i := range fresh {
				if !hostFileSameStat(fresh[i].stat, entry.nodes[i].stat) {
					return errors.New("pinned host file path identity changed")
				}
			}
			digest, n, err := hostFileHash(ctx, entry.nodes[len(entry.nodes)-1], hostFileMaxTotalBytes-total)
			if err != nil {
				return err
			}
			total += n
			if digest != entry.digest {
				return errors.New("pinned host file SHA256 mismatch")
			}
			if err := hostFileVerifyNodes(ctx, entry.nodes); err != nil {
				return err
			}
			return hostFileVerifyNodes(ctx, fresh)
		}()
		if err = errors.Join(checkErr, hostFileCloseNodes(fresh)); err != nil {
			return err
		}
	}
	// Detect an earlier member changing while a later member was inspected.
	for _, entry := range s.files {
		if err := hostFileVerifyNodes(ctx, entry.nodes); err != nil {
			return err
		}
	}
	return hostFileContext(ctx)
}

// Check re-walks every approved path from the root, compares every retained
// ancestor/file identity, and re-reads pinned bytes with before/after fstat.
// Any failure invalidates this set, including cancellation. It never refreshes
// the accepted baseline or silently switches to a replacement inode.
func (s *HostFilePins) Check(ctx context.Context) error {
	if s == nil {
		return os.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.files) == 0 {
		return os.ErrClosed
	}
	if s.invalid != nil {
		return s.invalid
	}
	if err := s.checkLocked(ctx); err != nil {
		s.invalid = fmt.Errorf("host file pins invalidated: %w", err)
		return s.invalid
	}
	return nil
}

// Snapshot returns an independent copy of historical metadata, not contents or
// a fresh validation. It refuses closed or invalidated sets.
func (s *HostFilePins) Snapshot() ([]HostFileSnapshot, error) {
	if s == nil {
		return nil, os.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.files) == 0 {
		return nil, os.ErrClosed
	}
	if s.invalid != nil {
		return nil, s.invalid
	}
	out := make([]HostFileSnapshot, 0, len(s.files))
	for _, entry := range s.files {
		st := entry.nodes[len(entry.nodes)-1].stat
		out = append(out, HostFileSnapshot{
			Path: entry.pin.Path, SHA256: entry.pin.SHA256,
			Device: uint64(st.Dev), Inode: uint64(st.Ino), Size: st.Size,
			Mode: st.Mode, OwnerUID: st.Uid, OwnerGID: st.Gid, LinkCount: uint64(st.Nlink),
			Modified: time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)),
			Changed:  time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
		})
	}
	return out, nil
}

// Close releases retained descriptors exactly once. It never changes a file.
func (s *HostFilePins) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	for _, entry := range s.files {
		err = errors.Join(err, hostFileCloseNodes(entry.nodes))
	}
	s.files = nil
	return err
}
