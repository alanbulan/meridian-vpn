//go:build !darwin

package macosvpn

import "context"

func readKernelRoutesNative(context.Context) (KernelRouteReadback, error) {
	return KernelRouteReadback{}, ErrRouteReadback
}
