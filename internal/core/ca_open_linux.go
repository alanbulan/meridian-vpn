//go:build linux

package core

import (
	"os"
	"syscall"
)

// Refuse symlinks and never block on a FIFO swapped in after validation.
func openCAFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
