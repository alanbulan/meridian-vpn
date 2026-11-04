//go:build !darwin

package macosvpn

import "errors"

func openNative(string) (connection, error) {
	return nil, errors.New("SystemConfiguration L2TP control requires macOS")
}

func openInspectionNative(string) (inspectionConnection, error) {
	return nil, errors.New("SystemConfiguration L2TP inspection requires macOS")
}
