//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

const dispatcherMaxChildren = 4

// DispatcherDirectorySnapshot is copied historical directory metadata, not
// evidence that dispatcher processes have stopped or that the host is safe.
type DispatcherDirectorySnapshot struct {
	Path      string
	Device    uint64
	Inode     uint64
	Mode      uint32
	OwnerUID  uint32
	OwnerGID  uint32
	LinkCount uint64
	Modified  time.Time
	Changed   time.Time
}

// EmptyDispatcherObservation retains a conservative observation of the two
// fixed NetworkManager dispatcher roots. It accepts no hook files, including
// hidden, disabled, non-executable or symlinked hooks. Only the immediate empty
// pre-up.d, pre-down.d, no-wait.d and device directories may be present.
//
// This is NOT a HostAuthority, HostBinding, readiness gate, quiescence proof or
// network lease. Empty directories cannot exclude running or queued scripts,
// effects of earlier scripts, another NM build's search paths, or other policy
// sources. The observer assumes trusted root and a trusted mount namespace and
// filesystem. It neither identifies the initial host namespace nor excludes
// concurrent privileged mount changes. Equal sequential samples are not atomic
// and cannot prevent later changes or detect every transient change.
//
// Do not copy this value; copied and zero instances are rejected. Operations are
// serialized. Any failed Check, including
// cancellation, permanently invalidates the observation. There is no watcher or
// background goroutine: callers must explicitly Check and Close. Cancellation
// is checked between bounded operations, not during a filesystem syscall or a
// mutex wait. Even unrelated changes in retained ancestors invalidate the set.
type EmptyDispatcherObservation struct {
	self    *EmptyDispatcherObservation
	mu      sync.Mutex
	policy  hostFilePolicy
	roots   []dispatcherRetainedRoot
	invalid error
	closed  bool
}

type dispatcherRetainedDirectory struct {
	name string
	node hostFileNode
}

type dispatcherRetainedRoot struct {
	path     string
	nodes    []hostFileNode
	children []dispatcherRetainedDirectory
}

// OpenEmptyDispatcherObservation observes only /etc/NetworkManager/dispatcher.d
// and /usr/lib/NetworkManager/dispatcher.d. Both must exist. Real and effective
// UID must both be root. All ancestors and accepted directories must be
// root-owned directories, owner-readable/searchable, without set-ID/sticky bits
// or group/world write access. Symlinks are never followed. At most four known
// child directories per root and no deeper entries are accepted. A missing
// known child is accepted only through complete enumeration of its pinned parent.
//
// Opening performs repeat verification. It never creates directories, repairs
// permissions, reads or executes scripts, or mutates NetworkManager. There is
// deliberately no public path, UID, filesystem or provider override.
func OpenEmptyDispatcherObservation(ctx context.Context) (*EmptyDispatcherObservation, error) {
	return openEmptyDispatcherObservation(ctx, hostFilePolicy{root: "/", uid: 0, production: true})
}

// The alternate anchor and UID are private isolated-fixture seams only. Even
// fixtures use the same fixed relative paths and closed directory grammar.
func openEmptyDispatcherObservation(ctx context.Context, policy hostFilePolicy) (*EmptyDispatcherObservation, error) {
	if err := dispatcherPolicyContext(ctx, policy); err != nil {
		return nil, err
	}
	s := &EmptyDispatcherObservation{policy: policy}
	s.self = s
	var err error
	s.roots, err = dispatcherReadRoots(ctx, policy)
	if err != nil {
		return nil, err
	}
	if err := s.checkLocked(ctx); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func dispatcherPolicyContext(ctx context.Context, policy hostFilePolicy) error {
	if err := hostFileContext(ctx); err != nil {
		return err
	}
	if policy.production && (policy.root != "/" || policy.uid != 0 || os.Getuid() != 0 || os.Geteuid() != 0) {
		return errors.New("dispatcher observation requires the real root and real and effective root UID")
	}
	if !filepath.IsAbs(policy.root) || filepath.Clean(policy.root) != policy.root || len(policy.root) > hostFileMaxPathBytes {
		return errors.New("invalid dispatcher root")
	}
	return nil
}

func dispatcherKnownChild(name string) bool {
	switch name {
	case "pre-up.d", "pre-down.d", "no-wait.d", "device":
		return true
	}
	return false
}

func dispatcherDirectoryStat(st syscall.Stat_t, policy hostFilePolicy) error {
	if st.Uid != policy.uid || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&07022 != 0 || st.Mode&0500 != 0500 || st.Nlink == 0 {
		return errors.New("dispatcher component is not a trusted readable/searchable directory")
	}
	return nil
}

func dispatcherOpenDirectory(parent *os.File, name string, policy hostFilePolicy) (hostFileNode, error) {
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_DIRECTORY | syscall.O_NOATIME
	var fd int
	var err error
	if parent == nil {
		fd, err = syscall.Open(name, flags, 0)
	} else {
		fd, err = syscall.Openat(int(parent.Fd()), name, flags, 0)
	}
	if err != nil {
		return hostFileNode{}, fmt.Errorf("open dispatcher directory: %w", err)
	}
	node := hostFileNode{file: os.NewFile(uintptr(fd), "observed dispatcher directory")}
	err = syscall.Fstat(fd, &node.stat)
	if err == nil {
		err = dispatcherDirectoryStat(node.stat, policy)
	}
	if err != nil {
		return hostFileNode{}, errors.Join(err, node.file.Close())
	}
	return node, nil
}

func dispatcherWalk(ctx context.Context, path string, policy hostFilePolicy) ([]hostFileNode, error) {
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
		var parent *os.File
		name := policy.root
		if i >= 0 {
			parent, name = nodes[len(nodes)-1].file, parts[i]
		}
		node, err := dispatcherOpenDirectory(parent, name, policy)
		if err != nil {
			return fail(err)
		}
		nodes = append(nodes, node)
	}
	if err := hostFileVerifyNodes(ctx, nodes); err != nil {
		return fail(err)
	}
	return nodes, nil
}

// Reopen "." to get an independent directory stream, never reuse a retained
// stream's EOF/offset. Read at most limit+1 names; the extra entry rejects a
// directory exceeding the closed grammar without unbounded enumeration.
func dispatcherReadNames(ctx context.Context, node hostFileNode, limit int, policy hostFilePolicy) ([]string, error) {
	if err := hostFileVerifyNodes(ctx, []hostFileNode{node}); err != nil {
		return nil, err
	}
	stream, err := dispatcherOpenDirectory(node.file, ".", policy)
	if err != nil {
		return nil, err
	}
	var names []string
	readErr := func() error {
		if !hostFileSameStat(stream.stat, node.stat) {
			return errors.New("dispatcher directory changed before enumeration")
		}
		entries, err := stream.file.ReadDir(limit + 1)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(entries) > limit {
			return errors.New("dispatcher directory exceeds entry limit")
		}
		if err == nil {
			if err := hostFileContext(ctx); err != nil {
				return err
			}
			more, err := stream.file.ReadDir(1)
			if len(more) != 0 || !errors.Is(err, io.EOF) {
				return errors.Join(errors.New("dispatcher enumeration did not end within limit"), err)
			}
		}
		seen := make(map[string]bool, len(entries))
		for _, entry := range entries {
			name := entry.Name()
			if !dispatcherKnownChild(name) || seen[name] {
				return errors.New("unknown or duplicate dispatcher entry")
			}
			seen[name] = true
			names = append(names, name)
		}
		sort.Strings(names)
		return hostFileVerifyNodes(ctx, []hostFileNode{node, stream})
	}()
	if err := errors.Join(readErr, stream.file.Close()); err != nil {
		return nil, err
	}
	return names, nil
}

func dispatcherReadRoots(ctx context.Context, policy hostFilePolicy) ([]dispatcherRetainedRoot, error) {
	var roots []dispatcherRetainedRoot
	fail := func(err error) ([]dispatcherRetainedRoot, error) {
		return nil, errors.Join(err, dispatcherCloseRoots(roots))
	}
	// This fixed list cannot be replaced by a caller manifest or mutable global.
	for _, relative := range []string{"etc/NetworkManager/dispatcher.d", "usr/lib/NetworkManager/dispatcher.d"} {
		path := filepath.Join(policy.root, relative)
		nodes, err := dispatcherWalk(ctx, path, policy)
		if err != nil {
			return fail(err) // ENOENT is uncertainty, never an empty root.
		}
		roots = append(roots, dispatcherRetainedRoot{path: path, nodes: nodes})
		root := &roots[len(roots)-1]
		names, err := dispatcherReadNames(ctx, nodes[len(nodes)-1], dispatcherMaxChildren, policy)
		if err != nil {
			return fail(err)
		}
		for _, name := range names {
			if err := hostFileContext(ctx); err != nil {
				return fail(err)
			}
			node, err := dispatcherOpenDirectory(nodes[len(nodes)-1].file, name, policy)
			if err != nil {
				return fail(err)
			}
			root.children = append(root.children, dispatcherRetainedDirectory{name: name, node: node})
			if _, err := dispatcherReadNames(ctx, node, 0, policy); err != nil {
				return fail(err)
			}
		}
	}
	if err := dispatcherVerifyRoots(ctx, roots); err != nil {
		return fail(err)
	}
	return roots, nil
}

func dispatcherVerifyRoots(ctx context.Context, roots []dispatcherRetainedRoot) error {
	for _, root := range roots {
		if err := hostFileVerifyNodes(ctx, root.nodes); err != nil {
			return err
		}
		for _, child := range root.children {
			if err := hostFileVerifyNodes(ctx, []hostFileNode{child.node}); err != nil {
				return err
			}
		}
	}
	return hostFileContext(ctx)
}

func dispatcherCloseRoots(roots []dispatcherRetainedRoot) error {
	var err error
	for i := len(roots) - 1; i >= 0; i-- {
		root := roots[i]
		for j := len(root.children) - 1; j >= 0; j-- {
			err = errors.Join(err, root.children[j].node.file.Close())
		}
		err = errors.Join(err, hostFileCloseNodes(root.nodes))
	}
	return err
}

func (s *EmptyDispatcherObservation) checkLocked(ctx context.Context) error {
	if err := dispatcherPolicyContext(ctx, s.policy); err != nil {
		return err
	}
	if err := dispatcherVerifyRoots(ctx, s.roots); err != nil {
		return err
	}
	fresh, err := dispatcherReadRoots(ctx, s.policy)
	if err != nil {
		return err
	}
	checkErr := func() error {
		if len(fresh) != len(s.roots) {
			return errors.New("dispatcher root set changed")
		}
		for i, root := range s.roots {
			other := fresh[i]
			if root.path != other.path || len(root.nodes) != len(other.nodes) || len(root.children) != len(other.children) {
				return errors.New("dispatcher directory set changed")
			}
			for j, node := range root.nodes {
				if !hostFileSameStat(node.stat, other.nodes[j].stat) {
					return errors.New("dispatcher path identity changed")
				}
			}
			for j, child := range root.children {
				if child.name != other.children[j].name || !hostFileSameStat(child.node.stat, other.children[j].node.stat) {
					return errors.New("dispatcher child identity changed")
				}
			}
		}
		// Revisit earlier objects after observing later ones. This detects
		// observed drift, not every possible privileged transient change.
		if err := dispatcherVerifyRoots(ctx, s.roots); err != nil {
			return err
		}
		return dispatcherVerifyRoots(ctx, fresh)
	}()
	closeErr := dispatcherCloseRoots(fresh)
	return errors.Join(checkErr, closeErr, hostFileContext(ctx))
}

// Check re-walks the fixed paths and completely re-enumerates the bounded
// directory grammar against the retained original identities. Any error latches;
// there is no baseline refresh or fallback to accepting a missing root.
func (s *EmptyDispatcherObservation) Check(ctx context.Context) error {
	if s == nil || s.self != s {
		return os.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.roots) == 0 {
		return os.ErrClosed
	}
	if s.invalid != nil {
		return s.invalid
	}
	if err := s.checkLocked(ctx); err != nil {
		s.invalid = fmt.Errorf("dispatcher observation invalidated: %w", err)
		return s.invalid
	}
	return nil
}

// Snapshot returns copied historical metadata for both roots and each present
// accepted child. It is not a fresh check and omits all unobserved policy sources.
func (s *EmptyDispatcherObservation) Snapshot() ([]DispatcherDirectorySnapshot, error) {
	if s == nil || s.self != s {
		return nil, os.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.roots) == 0 {
		return nil, os.ErrClosed
	}
	if s.invalid != nil {
		return nil, s.invalid
	}
	var out []DispatcherDirectorySnapshot
	add := func(path string, st syscall.Stat_t) {
		out = append(out, DispatcherDirectorySnapshot{
			Path: path, Device: uint64(st.Dev), Inode: uint64(st.Ino), Mode: st.Mode,
			OwnerUID: st.Uid, OwnerGID: st.Gid, LinkCount: uint64(st.Nlink),
			Modified: time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)),
			Changed:  time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
		})
	}
	for _, root := range s.roots {
		add(root.path, root.nodes[len(root.nodes)-1].stat)
		for _, child := range root.children {
			add(filepath.Join(root.path, child.name), child.node.stat)
		}
	}
	return out, nil
}

// Close releases all retained descriptors once, joining any close errors. Copied
// and zero instances cannot release the original observation's descriptors. It
// changes no directory and never executes or stops a dispatcher process.
func (s *EmptyDispatcherObservation) Close() error {
	if s == nil {
		return nil
	}
	if s.self != s {
		return os.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := dispatcherCloseRoots(s.roots)
	s.roots = nil
	return err
}
