// meridian-ras-inspect is an explicit, read-only Windows acceptance probe.
// It never dials, reads credentials, writes profiles or changes network policy.
package main

import "os"

func main() {
	os.Exit(newProbe().run(os.Args[1:], os.Stdout, os.Stderr))
}
