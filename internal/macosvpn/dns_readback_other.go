//go:build !darwin

package macosvpn

import "context"

func ReadDNSConfiguration(context.Context) (DNSReadback, error) { return DNSReadback{}, ErrDNSReadback }
