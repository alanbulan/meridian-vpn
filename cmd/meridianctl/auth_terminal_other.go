//go:build !linux || (!amd64 && !arm64)

package main

func openAuthTerminal() (authTerminal, error) { return nil, errTerminalAuth }
