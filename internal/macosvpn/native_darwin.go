//go:build darwin

package macosvpn

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

var apiOnce sync.Once
var sharedAPI *nativeAPI
var apiError error

func loadAPI() (*nativeAPI, error) {
	apiOnce.Do(func() {
		// Framework handles stay loaded for the process lifetime, like the functions.
		defer func() {
			if recover() != nil {
				sharedAPI = nil
				apiError = errors.New("required SystemConfiguration API is unavailable")
			}
		}()
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			apiError = errors.New("CoreFoundation is unavailable")
			return
		}
		sc, err := purego.Dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			apiError = errors.New("SystemConfiguration is unavailable")
			return
		}
		a := &nativeAPI{}
		purego.RegisterLibFunc(&a.release, cf, "CFRelease")
		purego.RegisterLibFunc(&a.createString, cf, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&a.stringLength, cf, "CFStringGetLength")
		purego.RegisterLibFunc(&a.stringCString, cf, "CFStringGetCString")
		purego.RegisterLibFunc(&a.preferencesCreate, sc, "SCPreferencesCreate")
		purego.RegisterLibFunc(&a.serviceCopy, sc, "SCNetworkServiceCopy")
		purego.RegisterLibFunc(&a.serviceEnabled, sc, "SCNetworkServiceGetEnabled")
		purego.RegisterLibFunc(&a.serviceInterface, sc, "SCNetworkServiceGetInterface")
		purego.RegisterLibFunc(&a.interfaceType, sc, "SCNetworkInterfaceGetInterfaceType")
		purego.RegisterLibFunc(&a.lowerInterface, sc, "SCNetworkInterfaceGetInterface")
		purego.RegisterLibFunc(&a.createConnection, sc, "SCNetworkConnectionCreateWithServiceID")
		purego.RegisterLibFunc(&a.status, sc, "SCNetworkConnectionGetStatus")
		purego.RegisterLibFunc(&a.start, sc, "SCNetworkConnectionStart")
		purego.RegisterLibFunc(&a.stop, sc, "SCNetworkConnectionStop")
		bindEvidenceAPI(a, cf, sc)
		bindInspectionAPI(a, cf, sc)
		sharedAPI = a
	})
	return sharedAPI, apiError
}
func openNative(id string) (connection, error) {
	a, err := loadAPI()
	if err != nil {
		return nil, err
	}
	return openWithAPI(a, id)
}

// Assert pointer-width assumptions in supported 64-bit Darwin builds.
var _ [8 - unsafe.Sizeof(uintptr(0))]byte
var _ [unsafe.Sizeof(uintptr(0)) - 8]byte
