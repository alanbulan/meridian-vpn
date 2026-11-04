//go:build darwin

package macosvpn

import (
	"context"
	"io"
	"os/exec"
	"time"
)

// ReadDNSConfiguration runs only Apple's fixed read-only scutil --dns command.
// No service ID, target name, credential, input script or environment injection
// is passed. It sends no DNS query and performs no resolver configuration write.
// Cancellation kills the child and WaitDelay bounds pipe-drain waiting, not all
// possible kernel scheduling delays. Output is memory-bounded and never logged.
func ReadDNSConfiguration(ctx context.Context) (DNSReadback, error) {
	if ctx == nil {
		return DNSReadback{}, ErrDNSReadback
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns")
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	var out boundedDNSOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil || ctx.Err() != nil || out.overflow {
		return DNSReadback{}, ErrDNSReadback
	}
	return parseDNSReadback(out.Bytes())
}
