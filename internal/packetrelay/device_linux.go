//go:build linux

package packetrelay

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// TUNGETIFF only inspects an existing descriptor; no device is created or
// configured. Exact flags refuse TAP, PI, VNET_HDR and MULTI_QUEUE modes.
func verifyPacketDevice(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	err = raw.Control(func(fd uintptr) {
		var ifr [40]byte
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(0x800454d2), uintptr(unsafe.Pointer(&ifr[0])))
		if errno != 0 {
			opErr = errno
			return
		}
		flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
		if flags != 0x1001 {
			opErr = errors.New("packet device must be single-queue IFF_TUN|IFF_NO_PI without virtual headers")
		}
	})
	return errors.Join(err, opErr)
}
