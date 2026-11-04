package main

import (
	"mygo-vpn/internal/buildinfo"
	"testing"
)

func TestApplicationVersion(t *testing.T) {
	old, shared := version, buildinfo.Version
	t.Cleanup(func() { version, buildinfo.Version = old, shared })
	version, buildinfo.Version = "", "0.1.0-alpha.1"
	if got := applicationVersion(); got != buildinfo.Version {
		t.Fatal(got)
	}
	version = "legacy"
	if got := applicationVersion(); got != "legacy" {
		t.Fatal(got)
	}
}
