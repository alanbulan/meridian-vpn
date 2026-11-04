package macosvpn

import "errors"

type evidenceAPI struct {
	typeID             func(uintptr) uintptr
	dictionaryTypeID   func() uintptr
	arrayTypeID        func() uintptr
	stringTypeID       func() uintptr
	dictionaryValue    func(uintptr, uintptr) uintptr
	arrayCount         func(uintptr) int
	arrayValue         func(uintptr, int) uintptr
	copyServiceID      func(uintptr) uintptr
	copyExtendedStatus func(uintptr) uintptr
	storeCreate        func(uintptr, uintptr, uintptr, uintptr) uintptr
	storeCopyValue     func(uintptr, uintptr) uintptr
}

func (a *nativeAPI) dictionaryItem(dict uintptr, key string) uintptr {
	if dict == 0 || a.typeID(dict) != a.dictionaryTypeID() {
		return 0
	}
	k := a.createString(0, key, utf8Encoding)
	if k == 0 {
		return 0
	}
	defer a.release(k)
	return a.dictionaryValue(dict, k)
}
func (a *nativeAPI) stringValue(v uintptr) string {
	if v == 0 || a.typeID(v) != a.stringTypeID() {
		return ""
	}
	return a.text(v)
}
func (a *nativeAPI) stringArray(v uintptr) ([]string, error) {
	if v == 0 || a.typeID(v) != a.arrayTypeID() {
		return nil, errors.New("missing VPN address array")
	}
	count := a.arrayCount(v)
	if count < 1 || count > 16 {
		return nil, errors.New("invalid VPN address array length")
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		text := a.stringValue(a.arrayValue(v, i))
		if text == "" {
			return nil, errors.New("invalid VPN address array element")
		}
		out = append(out, text)
	}
	return out, nil
}
func (n *nativeConnection) readSystemEvidence() (systemEvidence, error) {
	a := n.a
	out := systemEvidence{requestedID: n.serviceID}
	id := a.copyServiceID(n.ref)
	if id == 0 {
		return out, errors.New("system VPN service identity is unavailable")
	}
	defer a.release(id)
	out.actualID = a.stringValue(id)
	if out.actualID != out.requestedID {
		return out, errors.New("system VPN service identity changed")
	}
	ext := a.copyExtendedStatus(n.ref)
	if ext == 0 {
		return out, errors.New("system VPN extended status is unavailable")
	}
	defer a.release(ext)
	ipv4 := a.dictionaryItem(ext, "IPv4")
	var err error
	out.extendedAddresses, err = a.stringArray(a.dictionaryItem(ipv4, "Addresses"))
	if err != nil {
		return out, err
	}
	name := a.createString(0, "Meridian read-only VPN inspection", utf8Encoding)
	if name == 0 {
		return out, errors.New("could not allocate inspection name")
	}
	defer a.release(name)
	store := a.storeCreate(0, name, 0, 0)
	if store == 0 {
		return out, errors.New("system network state is unavailable")
	}
	defer a.release(store)
	key := a.createString(0, "State:/Network/Service/"+out.actualID+"/IPv4", utf8Encoding)
	if key == 0 {
		return out, errors.New("could not allocate service state key")
	}
	defer a.release(key)
	state := a.storeCopyValue(store, key)
	if state == 0 {
		return out, errors.New("service IPv4 state is unavailable")
	}
	defer a.release(state)
	out.interfaceName = a.stringValue(a.dictionaryItem(state, "InterfaceName"))
	out.serviceAddresses, err = a.stringArray(a.dictionaryItem(state, "Addresses"))
	return out, err
}
