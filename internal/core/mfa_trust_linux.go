//go:build linux

package core

import (
	"os"
	"path/filepath"
	"syscall"
)

// This is install-path hygiene, not a signature/identity claim. The user's own
// account and administrator remain trusted. Avoid writable ancestor swaps.
func trustedMFAHelperPath(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	first := true
	for {
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return false
		}
		native, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (native.Uid != 0 && native.Uid != uint32(os.Geteuid())) {
			return false
		}
		if first {
			if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
				return false
			}
			first = false
		} else if !st.IsDir() {
			return false
		}
		parent := filepath.Dir(path)
		if parent == path {
			return true
		}
		path = parent
	}
}
