//go:build !linux

package packetrelay

import (
	"errors"
	"os"
)

func verifyPacketDevice(*os.File) error { return errors.New("verified packet devices require Linux") }
