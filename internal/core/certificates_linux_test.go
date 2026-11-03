//go:build linux

package core

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCertificateRejectsFIFOAndSymlink(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe.pem")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if ValidateCAFile(fifo) == nil {
		t.Fatal("FIFO accepted")
	}
	link := filepath.Join(t.TempDir(), "link.pem")
	if e := os.Symlink(caFixture(t), link); e != nil {
		t.Fatal(e)
	}
	if ValidateCAFile(link) == nil {
		t.Fatal("symlink accepted")
	}
}

func TestClientCertificateRejectsFIFOAndSymlink(t *testing.T) {
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	for _, private := range []bool{false, true} {
		original := p.ClientCertificate
		if private {
			original = p.ClientKey
		}
		link := filepath.Join(t.TempDir(), "link.pem")
		if e := os.Symlink(original, link); e != nil {
			t.Fatal(e)
		}
		bad := p
		if private {
			bad.ClientKey = link
		} else {
			bad.ClientCertificate = link
		}
		if ValidateClientCertificate(bad) == nil {
			t.Fatal("symlink accepted")
		}
		fifo := filepath.Join(t.TempDir(), "pipe.pem")
		if e := syscall.Mkfifo(fifo, 0600); e != nil {
			t.Fatal(e)
		}
		if private {
			bad.ClientKey = fifo
		} else {
			bad.ClientCertificate = fifo
		}
		if ValidateClientCertificate(bad) == nil {
			t.Fatal("FIFO accepted")
		}
	}
}
