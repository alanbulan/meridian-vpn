//go:build linux

package nmvpn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/godbus/dbus/v5"
)

type nmReadFailure struct{ err error }

func (r nmReadFailure) Read([]byte) (int, error) { return 0, r.err }

// PinnedBus adopts a raw socket through NewConn's generic transport. Closing
// that socket can interrupt any message byte, including header-to-body padding.
// v5.2.2 panicked outside its decoder recovery scope at this exact boundary.
// This deterministic regression needs no bus, goroutine scheduling or host I/O.
func TestPinnedBusDecoderTruncatedHeaderPadding(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		msg := &dbus.Message{
			Type: dbus.TypeMethodCall,
			Headers: map[dbus.HeaderField]dbus.Variant{
				dbus.FieldPath:   dbus.MakeVariant(dbus.ObjectPath("/")),
				dbus.FieldMember: dbus.MakeVariant("X"),
			},
		}
		var encoded bytes.Buffer
		if err := msg.EncodeTo(&encoded, order); err != nil {
			t.Fatal(err)
		}
		packet := encoded.Bytes()
		headerEnd := 16 + int(order.Uint32(packet[12:16]))
		padding := (8 - headerEnd%8) % 8
		if padding == 0 || headerEnd+padding != len(packet) {
			t.Fatal("fixture did not exercise final header padding")
		}
		if _, err := dbus.DecodeMessage(bytes.NewReader(packet)); err != nil {
			t.Fatal("complete fixture rejected", err)
		}
		for _, failure := range []error{net.ErrClosed, io.EOF} {
			for available := 0; available < padding; available++ {
				reader := io.MultiReader(bytes.NewReader(packet[:headerEnd+available]), nmReadFailure{failure})
				decoded, err := dbus.DecodeMessage(reader)
				if decoded != nil || !errors.Is(err, failure) {
					t.Fatalf("padding=%d available=%d: expected terminal read error, got %v", padding, available, err)
				}
			}
		}
	}
}
