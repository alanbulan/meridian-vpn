// meridianctl provides headless configuration and read-only readiness workflows.
// It deliberately has no connect/disconnect command or credential input.
package main

import (
	"context"
	"os"
)

// Set at build time with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	os.Exit(newApplication().run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
