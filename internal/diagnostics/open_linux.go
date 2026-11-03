//go:build linux

package diagnostics

import (
	"os"
	"syscall"
)

// O_NONBLOCK prevents a descriptor replaced with a FIFO after Lstat from
// blocking this read-only probe. O_NOFOLLOW rejects a replacement symlink.
func openDescriptor(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
