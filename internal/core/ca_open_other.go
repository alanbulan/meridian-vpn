//go:build !linux

package core

import "os"

func openCAFile(path string) (*os.File, error) { return os.Open(path) }
