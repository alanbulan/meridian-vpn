package main

import (
	"errors"
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
)

func samePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil || aa == bb {
		return true
	}
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}

// saveNewConfig uses Store for validation, serialization and mode-0600 atomic
// writing, then publishes via an exclusive hard link. Unlike Rename, Link can
// never overwrite an existing file/symlink, even if created after our check.
// The temporary file lives in the target directory so publication is same-FS.
// Filesystems without hard-link support fail closed without changing output.
func saveNewConfig(path string, cfg core.Config) error {
	if path == "" {
		return errors.New("empty output path")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".meridianctl-*")
	if err != nil {
		return err
	}
	staging := f.Name()
	defer os.Remove(staging)
	if err := f.Close(); err != nil {
		return err
	}
	if err := (core.Store{Path: staging}).Save(cfg); err != nil {
		return err
	}
	return os.Link(staging, path)
}
