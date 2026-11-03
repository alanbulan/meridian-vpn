//go:build !linux

package autostart

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformNeverCreatesAnything(t *testing.T) {
	m, err := New(Options{ConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Status()
	if err != nil || s.Supported || s.Enabled || s.Path != "" {
		t.Fatalf("unsupported status: %+v %v", s, err)
	}
	if _, err := m.Preview(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("preview: %v", err)
	}
	if err := m.Enable(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("enable: %v", err)
	}
	if err := m.Disable(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("disable: %v", err)
	}
}
