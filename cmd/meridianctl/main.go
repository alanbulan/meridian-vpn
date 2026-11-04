// meridianctl provides configuration, read-only readiness and owned foreground VPN sessions.
package main

import (
	"context"
	"mygo-vpn/internal/buildinfo"
	"os"
)

// Set at build time with -ldflags '-X main.version=...'.
var version = ""

func applicationVersion() string {
	if version != "" {
		return version
	} // Compatibility with existing -X main.version builds.
	return buildinfo.Version
}

func main() {
	ctx, stop := commandSignalContext(context.Background())
	code := newApplication().run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
