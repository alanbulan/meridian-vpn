//go:build darwin

package macosvpn

import "github.com/ebitengine/purego"

func bindEvidenceAPI(a *nativeAPI, cf, sc uintptr) {
	purego.RegisterLibFunc(&a.typeID, cf, "CFGetTypeID")
	purego.RegisterLibFunc(&a.dictionaryTypeID, cf, "CFDictionaryGetTypeID")
	purego.RegisterLibFunc(&a.arrayTypeID, cf, "CFArrayGetTypeID")
	purego.RegisterLibFunc(&a.stringTypeID, cf, "CFStringGetTypeID")
	purego.RegisterLibFunc(&a.dictionaryValue, cf, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&a.arrayCount, cf, "CFArrayGetCount")
	purego.RegisterLibFunc(&a.arrayValue, cf, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&a.copyServiceID, sc, "SCNetworkConnectionCopyServiceID")
	purego.RegisterLibFunc(&a.copyExtendedStatus, sc, "SCNetworkConnectionCopyExtendedStatus")
	purego.RegisterLibFunc(&a.storeCreate, sc, "SCDynamicStoreCreate")
	purego.RegisterLibFunc(&a.storeCopyValue, sc, "SCDynamicStoreCopyValue")
}
