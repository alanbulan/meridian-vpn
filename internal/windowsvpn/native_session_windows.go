//go:build windows

package windowsvpn

// bindWindowsNativeSession supplies the one actual process callback router and
// trampoline to the injected transports. Addresses must already be resolved
// from trusted system DLLs; this function loads no DLL and performs no RAS or
// adapter query. There is no exported or application-default construction path.
func bindWindowsNativeSession(dial, hangup, projection uintptr, b nativeSessionBindings) (*borrowedCoordinator, error) {
	calls, err := nativeRASTransport(dial, hangup)
	if err != nil {
		return nil, err
	}
	project, err := nativeProjectionIPv4(projection)
	if err != nil {
		return nil, err
	}
	notifier, err := nativeRASCallback()
	if err != nil {
		return nil, err
	}
	b.calls = calls
	b.projection = project
	b.router = systemCallbackRouter
	b.notifier = notifier
	return newBoundNativeSession(b)
}

// Binds the actual IP Helper inventory transport as well as RAS procedures.
// All addresses are explicit; no function is executed until the caller starts
// or inspects a session. System-DLL resolution/application enablement is separate.
func bindWindowsNativeAPIs(dial, hangup, projection, adapters uintptr, b nativeSessionBindings) (*borrowedCoordinator, error) {
	inventory, err := nativeAdapterInventory(adapters)
	if err != nil {
		return nil, err
	}
	b.interfaces = inventory
	return bindWindowsNativeSession(dial, hangup, projection, b)
}
