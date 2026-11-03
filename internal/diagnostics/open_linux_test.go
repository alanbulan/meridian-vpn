//go:build linux

package diagnostics

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLinuxDescriptorRejectsSymlinkAndOpensFIFOWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openDescriptor(link); err == nil {
		f.Close()
		t.Fatal("symlink followed")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	// A blocking open would hang until another writer appeared. The production
	// helper is nonblocking and the subsequent regular-file check rejects this.
	f, err := openDescriptor(fifo)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Mode().IsRegular() {
		t.Fatal("FIFO not identifiable after opening")
	}
	if _, err := readBoundedFile(fifo, 100); err == nil {
		t.Fatal("FIFO accepted as metadata")
	}
}
