//go:build linux

package autostart

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const maxEntrySize = 16 * 1024

func checkExecutable(path string) error {
	dir, err := walkDirectory(filepath.Dir(path), false, -1)
	if err != nil {
		return fmt.Errorf("open autostart executable directory: %w", err)
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open autostart executable: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 || (st.Uid != uint32(os.Geteuid()) && st.Uid != 0) {
		return fmt.Errorf("%w: executable must be a regular executable owned by this user or root, without group/world write permission", ErrUnsafePath)
	}
	return nil
}

// walkDirectory pins each component with openat + O_NOFOLLOW, avoiding symlink
// substitution and path-based TOCTOU outside the checked directory. Config and
// autostart directories must belong to this user; trusted ancestors may belong
// to root. A root-owned sticky ancestor (e.g. /tmp for isolated tests) is safe
// for traversal, but is never accepted as the config/autostart directory.
func (m *Manager) directory(create bool) (*os.File, error) {
	path := filepath.Join(m.configDir, "autostart")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return walkDirectory(path, create, len(parts)-2)
}

// userOnlyStart is the first component which must belong to the current UID;
// -1 allows root-owned ancestors throughout (for installed executables).
func walkDirectory(path string, create bool, userOnlyStart int) (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		return current, nil
	}
	for i, part := range parts {
		next, openErr := syscall.Openat(int(current.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if errors.Is(openErr, syscall.ENOENT) && create {
			// Do not create anything in a shared or foreign-owned parent, even
			// when it is safe merely to traverse (for example /tmp).
			if err := safeDirectory(current, true); err != nil {
				current.Close()
				return nil, err
			}
			if err := syscall.Mkdirat(int(current.Fd()), part, 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
				current.Close()
				return nil, err
			}
			next, openErr = syscall.Openat(int(current.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		}
		current.Close()
		if openErr != nil {
			if errors.Is(openErr, syscall.ENOENT) {
				return nil, os.ErrNotExist
			}
			return nil, fmt.Errorf("%w: cannot open directory component %q without following links: %v", ErrUnsafePath, part, openErr)
		}
		current = os.NewFile(uintptr(next), part)
		if err := safeDirectory(current, userOnlyStart >= 0 && i >= userOnlyStart); err != nil {
			current.Close()
			return nil, err
		}
	}
	return current, nil
}

func safeDirectory(f *os.File, userOnly bool) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	uid := uint32(os.Geteuid())
	if !ok || !info.IsDir() || (st.Uid != uid && (userOnly || st.Uid != 0)) {
		return fmt.Errorf("%w: directory is not owned by the expected user", ErrUnsafePath)
	}
	if info.Mode().Perm()&0022 != 0 && (userOnly || st.Uid != 0 || info.Mode()&os.ModeSticky == 0) {
		return fmt.Errorf("%w: directory is writable by another user or group", ErrUnsafePath)
	}
	return nil
}

func lockDirectory(dir *os.File, exclusive bool) error {
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(dir.Fd()), mode|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrBusy
		}
		return err
	}
	return nil
}

func readEntry(dir *os.File) (string, os.FileInfo, error) {
	fd, err := syscall.Openat(int(dir.Fd()), FileName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("%w: cannot safely open entry: %v", ErrForeignEntry, err)
	}
	f := os.NewFile(uintptr(fd), FileName)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Size() > maxEntrySize {
		return "", nil, fmt.Errorf("%w: unexpected owner, permissions, file type or size", ErrForeignEntry)
	}
	content, err := io.ReadAll(io.LimitReader(f, maxEntrySize+1))
	if err != nil {
		return "", nil, err
	}
	if len(content) > maxEntrySize {
		return "", nil, ErrForeignEntry
	}
	executable, err := ownedExecutable(content)
	return executable, info, err
}

func (m *Manager) readRegistration() (string, error) {
	dir, err := m.directory(false)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := lockDirectory(dir, false); err != nil {
		return "", err
	}
	executable, _, err := readEntry(dir)
	return executable, err
}

func (m *Manager) enable(content []byte) error {
	dir, err := m.directory(true)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := lockDirectory(dir, true); err != nil {
		return err
	}
	registered, _, err := readEntry(dir)
	if err != nil {
		return err
	}
	if registered == m.executable {
		return nil
	}
	if registered != "" {
		return ErrDifferentExecutable
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tempName := fmt.Sprintf(".meridian-autostart-%x.tmp", random)
	fd, err := syscall.Openat(int(dir.Fd()), tempName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	temp := os.NewFile(uintptr(fd), tempName)
	defer temp.Close()
	defer syscall.Unlinkat(int(dir.Fd()), tempName)
	if err := temp.Chmod(0600); err != nil {
		return err
	}
	if _, err := temp.Write(content); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	// linkat publishes complete bytes atomically and never overwrites even an
	// entry created by another process after our initial inspection.
	if err := linkAt(int(dir.Fd()), tempName, FileName); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("%w: destination appeared while enabling", ErrForeignEntry)
		}
		return err
	}
	if err := syscall.Unlinkat(int(dir.Fd()), tempName); err != nil {
		return fmt.Errorf("autostart created but temporary link cleanup failed: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("autostart created but directory sync failed: %w", err)
	}
	return nil
}

func (m *Manager) disable() error {
	dir, err := m.directory(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := lockDirectory(dir, true); err != nil {
		return err
	}
	registered, before, err := readEntry(dir)
	if err != nil || registered == "" {
		return err
	}
	// Serialize our own processes and recheck the descriptor identity/content
	// immediately before unlinking. The private owner-writable directory is the
	// trust boundary; arbitrary hostile code running as this same UID is not.
	again, after, err := readEntry(dir)
	if err != nil {
		return err
	}
	if again != registered || after == nil || !os.SameFile(before, after) {
		return fmt.Errorf("%w: entry changed while disabling", ErrForeignEntry)
	}
	if err := syscall.Unlinkat(int(dir.Fd()), FileName); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("autostart removed but directory sync failed: %w", err)
	}
	return nil
}

func linkAt(dirfd int, oldName, newName string) error {
	old, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	new, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(old)), uintptr(dirfd), uintptr(unsafe.Pointer(new)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
