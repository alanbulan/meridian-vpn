//go:build !linux

package core

func trustedMFAHelperPath(string) bool { return false }
