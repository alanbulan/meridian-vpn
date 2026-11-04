// Package buildinfo identifies a build without consulting user configuration.
package buildinfo

// Set by the versioned packaging build. Plain go build remains a development build.
var Version = "dev"
var Commit = "unknown"
