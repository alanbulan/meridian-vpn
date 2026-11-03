// meridianctl provides configuration, read-only readiness and owned foreground VPN sessions.
package main

import (
	"context"
	"os"
)

// Set at build time with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	ctx, stop := commandSignalContext(context.Background())
	code := newApplication().run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
