package macosvpn

import "errors"

type inspectionAPI struct {
	interfaceConfiguration         func(uintptr) uintptr
	interfaceExtendedConfiguration func(uintptr, uintptr) uintptr
	numberTypeID                   func() uintptr
	numberIsFloatType              func(uintptr) uint8
	numberGetValue                 func(uintptr, int, *int64) uint8
}

func (n *nativeConnection) readConfiguration() (ServiceConfiguration, error) {
	return inspectConfigurationWithAPI(n.a, n.serviceID)
}

// Each sample opens fresh preferences. No CopyPassword, Keychain, dictionary
// enumeration/serialization, preferences write or connection start/stop API.
// GetConfiguration dictionaries may contain secret fields in native memory;
// only the three named non-secret fields below are extracted into Go.
func inspectConfigurationWithAPI(a *nativeAPI, id string) (ServiceConfiguration, error) {
	out := ServiceConfiguration{ServiceID: id}
	fail := errors.New("system VPN diagnostic configuration is unavailable")
	name := a.createString(0, "Meridian read-only service configuration", utf8Encoding)
	if name == 0 {
		return out, fail
	}
	defer a.release(name)
	prefs := a.preferencesCreate(0, name, 0)
	if prefs == 0 {
		return out, fail
	}
	defer a.release(prefs)
	sid := a.createString(0, id, utf8Encoding)
	if sid == 0 {
		return out, fail
	}
	defer a.release(sid)
	service := a.serviceCopy(prefs, sid)
	if service == 0 {
		return out, fail
	}
	defer a.release(service)
	if a.serviceEnabled(service) == 0 {
		return out, fail
	}
	iface := a.serviceInterface(service)
	if iface == 0 || a.stringValue(a.interfaceType(iface)) != "PPP" {
		return out, fail
	}
	lower := a.lowerInterface(iface)
	if lower == 0 || a.stringValue(a.interfaceType(lower)) != "L2TP" {
		return out, fail
	}
	ppp := a.interfaceConfiguration(iface)
	out.Gateway = a.stringValue(a.dictionaryItem(ppp, "CommRemoteAddress"))
	var err error
	out.PPPAuthentication, err = a.stringArray(a.dictionaryItem(ppp, "AuthProtocol"))
	if err != nil {
		return out, fail
	}
	key := a.createString(0, "IPSec", utf8Encoding)
	if key == 0 {
		return out, fail
	}
	defer a.release(key)
	ipsec := a.interfaceExtendedConfiguration(iface, key)
	out.IPSecAuthentication = a.stringValue(a.dictionaryItem(ipsec, "AuthenticationMethod"))
	if err = validateDiagnosticConfig(out, id); err != nil {
		return ServiceConfiguration{}, err
	}
	return out, nil
}
func (n *nativeConnection) readConnectTime() (int64, error) {
	a := n.a
	fail := errors.New("system VPN generation is unavailable")
	ext := a.copyExtendedStatus(n.ref)
	if ext == 0 {
		return 0, fail
	}
	defer a.release(ext)
	value := a.dictionaryItem(a.dictionaryItem(ext, "PPP"), "ConnectTime")
	if value == 0 || a.typeID(value) != a.numberTypeID() || a.numberIsFloatType(value) != 0 {
		return 0, fail
	}
	var result int64
	// kCFNumberSInt64Type = 4; CFNumberType is CFIndex (pointer-width signed).
	if a.numberGetValue(value, 4, &result) == 0 || result <= 0 {
		return 0, fail
	}
	return result, nil
}
