//go:build darwin

package macosvpn

import "github.com/ebitengine/purego"

func bindInspectionAPI(a *nativeAPI, cf, sc uintptr) {
	purego.RegisterLibFunc(&a.interfaceConfiguration, sc, "SCNetworkInterfaceGetConfiguration")
	purego.RegisterLibFunc(&a.interfaceExtendedConfiguration, sc, "SCNetworkInterfaceGetExtendedConfiguration")
	purego.RegisterLibFunc(&a.numberTypeID, cf, "CFNumberGetTypeID")
	purego.RegisterLibFunc(&a.numberIsFloatType, cf, "CFNumberIsFloatType")
	purego.RegisterLibFunc(&a.numberGetValue, cf, "CFNumberGetValue")
}
func openInspectionNative(id string) (inspectionConnection, error) {
	n, err := openNative(id)
	if err != nil {
		return nil, err
	}
	return n.(*nativeConnection), nil
}
