//go:build windows

package windowsvpn

import (
	"sync"
	"syscall"
)

// Only explicit access allocates the one process-lifetime Go callback stub.
// Nothing loads Rasapi32, starts a service or invokes a VPN operation here.
var systemCallback struct {
	once sync.Once
	address uintptr
	err error
}

var systemCallbackRouter = newCallbackRouter()

// nativeRASCallback exposes no exported/application entry point. Its signature
// is the seven scalar arguments of SDK RASDIALFUNC2 (WINAPI/stdcall on x86).
// uintptr matches machine-word transport; DWORD/UINT arguments use low 32 bits.
func nativeRASCallback() (uintptr, error) {
	systemCallback.once.Do(func() {
		defer func() {
			if recover() != nil { systemCallback.address = 0; systemCallback.err = errCallback }
		}()
		systemCallback.address = syscall.NewCallback(routeRASCallback)
		if systemCallback.address == 0 { systemCallback.err = errCallback }
	})
	return systemCallback.address, systemCallback.err
}

func routeRASCallback(id, subEntry, handle, message, state, code, extendedCode uintptr) (result uintptr) {
	// No panic may unwind through the native callback frame. Returning zero
	// only suppresses future notifications; no native cleanup is inferred.
	defer func() {
		if recover() != nil {
			result = 0
			// Even an unexpected fault while recording failure must not unwind
			// through Windows. Marking the route is best-effort on this path.
			defer func() { _ = recover() }()
			systemCallbackRouter.fault(id)
		}
	}()
	return systemCallbackRouter.dispatch(id, callbackEvent{
		subEntry: uint32(subEntry), handle: handle, message: uint32(message),
		state: uint32(state), code: uint32(code), extendedCode: uint32(extendedCode),
	})
}
