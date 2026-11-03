//go:build !linux

package diagnostics

import "os"

// Non-Linux reports skip plugin inspection; this fallback keeps file helpers
// portable for builds and tests without offering a non-Linux VPN backend.
func openDescriptor(path string) (*os.File, error) { return os.Open(path) }
