//go:build !linux

package packetrelay

import (
	"errors"
	"os"
)

type DatagramPackets struct{}

func NewDatagramPackets(*os.File) (*DatagramPackets, error) {
	return nil, errors.New("verified packet sockets require Linux")
}
func (*DatagramPackets) ReadPacket([]byte) (int, error)  { return 0, ErrRejected }
func (*DatagramPackets) WritePacket([]byte) (int, error) { return 0, ErrRejected }
func (*DatagramPackets) Close() error                    { return nil }
