//go:build linux

package packetrelay

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func kernelSetRecord(index int32, name string) KernelPolicyRecord {
	data := make([]byte, 16)
	binary.NativeEndian.PutUint32(data[4:], uint32(index))
	data = append(data, kernelTestAttr(unix.IFLA_IFNAME, []byte(name+"\x00"))...)
	return KernelPolicyRecord{Type: unix.RTM_NEWLINK, Data: data}
}

func TestKernelLinkSetMembershipValidation(t *testing.T) {
	for _, mode := range []string{"success", "empty", "duplicate index", "duplicate name", "zero index", "negative index", "wrong type", "wrong family", "reserved", "missing name", "unterminated name", "embedded nul", "slash", "space", "invalid UTF8", "long name", "limit"} {
		t.Run(mode, func(t *testing.T) {
			records := []KernelPolicyRecord{kernelSetRecord(9, "meridian0"), kernelSetRecord(1, "lo")}
			switch mode {
			case "empty":
				records = nil
			case "duplicate index":
				records[1] = kernelSetRecord(9, "other0")
			case "duplicate name":
				records[1] = kernelSetRecord(1, "meridian0")
			case "zero index":
				records[1] = kernelSetRecord(0, "lo")
			case "negative index":
				records[1] = kernelSetRecord(-1, "lo")
			case "wrong type":
				records[1].Type = unix.RTM_NEWADDR
			case "wrong family":
				records[1].Data[0] = unix.AF_INET
			case "reserved":
				records[1].Data[1] = 1
			case "missing name":
				records[1].Data = records[1].Data[:16]
			case "unterminated name":
				records[1].Data[22] = 1
			case "embedded nul":
				records[1] = kernelSetRecord(1, "l\x00o")
			case "slash":
				records[1] = kernelSetRecord(1, "l/o")
			case "space":
				records[1] = kernelSetRecord(1, "l o")
			case "invalid UTF8":
				records[1] = kernelSetRecord(1, "l\xff")
			case "long name":
				records[1] = kernelSetRecord(1, "1234567890123456")
			case "limit":
				records = make([]KernelPolicyRecord, 1025)
			}
			got, err := parseKernelLinkSet(records)
			if mode == "success" {
				if err != nil || !reflect.DeepEqual(got, []KernelLinkIdentity{{Index: 1, Name: "lo"}, {Index: 9, Name: "meridian0"}}) {
					t.Fatal(got, err)
				}
			} else if err == nil || got != nil {
				t.Fatal("partial membership accepted", got, err)
			}
		})
	}
}

func TestKernelLinkSetConcreteTransportAndToken(t *testing.T) {
	for _, mode := range []string{"success", "incomplete", "changed namespace", "cleanup failure", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ns := KernelNamespaceIdentity{Device: 1, Inode: 2}
			opened, closed, sockets, sends, reads := 0, 0, 0, 0, 0
			ops := kernelLinkOps{
				namespace: func() (KernelNamespaceIdentity, func() error, error) {
					opened++
					id := ns
					if mode == "changed namespace" && opened == 3 {
						id.Inode++
					}
					return id, func() error { closed++; return nil }, nil
				},
				socket: func() (int, error) { return 7, nil }, bind: func(int) error { return nil }, port: func(int) (uint32, error) { return 99, nil },
				send: func(_ int, b []byte) error {
					sends++
					if len(b) != 32 || binary.NativeEndian.Uint16(b[4:]) != unix.RTM_GETLINK || binary.NativeEndian.Uint16(b[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_DUMP || b[16] != unix.AF_UNSPEC {
						t.Fatal("non-complete or non-read-only request")
					}
					if mode == "canceled" {
						cancel()
					}
					return nil
				},
				recv: func(_ int, b []byte) (int, int, unix.Sockaddr, error) {
					reads++
					if reads > 1 && mode == "incomplete" {
						return 0, 0, nil, unix.ENOBUFS
					}
					if reads == 1 {
						r := kernelSetRecord(1, "lo")
						v := make([]byte, 16)
						binary.NativeEndian.PutUint32(v, uint32(16+len(r.Data)))
						binary.NativeEndian.PutUint16(v[4:], r.Type)
						binary.NativeEndian.PutUint16(v[6:], unix.NLM_F_MULTI)
						binary.NativeEndian.PutUint32(v[8:], 1)
						binary.NativeEndian.PutUint32(v[12:], 99)
						v = append(v, r.Data...)
						copy(b, v)
						return len(v), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, nil
					}
					v := policyDone(1, 99)
					copy(b, v)
					return len(v), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, nil
				}, poll: func(int, int16, int) (int16, error) { return 0, nil },
				close: func(int) error {
					sockets++
					if mode == "cleanup failure" {
						return errors.New("injected close")
					}
					return nil
				}, now: func() time.Time { return time.Unix(100, 0) },
			}
			token, err := observeKernelLinkSetWith(ctx, ns, ops)
			if mode == "success" {
				if err != nil || token == nil || reads != 2 {
					t.Fatal(token, err)
				}
				snapshot, e := token.Snapshot()
				if e != nil || snapshot.Namespace != ns || len(snapshot.Links) != 1 {
					t.Fatal(snapshot, e)
				}
				snapshot.Links[0].Name = "changed"
				again, _ := token.Snapshot()
				if again.Links[0].Name != "lo" {
					t.Fatal("snapshot aliases token")
				}
				copyToken := *token
				if _, e := copyToken.Snapshot(); e == nil {
					t.Fatal("copied token accepted")
				}
			} else if token != nil || err == nil {
				t.Fatal("invalid dump produced token", token, err)
			}
			if closed != opened || sockets != 1 || sends != 1 {
				t.Fatal("transport handles leaked/retried")
			}
			if mode == "cleanup failure" && !errors.Is(err, ErrCleanup) {
				t.Fatal("cleanup uncertainty lost")
			}
		})
	}
	for _, token := range []*KernelLinkSet{nil, {}} {
		if _, err := token.Snapshot(); err == nil {
			t.Fatal("forged token accepted")
		}
	}
}

func TestKernelLinkSetRejectsNonReadOnlyRequests(t *testing.T) {
	for _, spec := range []kernelDumpSpec{{unix.RTM_NEWLINK, unix.AF_UNSPEC}, {unix.RTM_GETLINK, unix.AF_INET}, {unix.RTM_GETROUTE, unix.AF_UNSPEC}} {
		if got, err := observeKernelRecordsWith(context.Background(), KernelNamespaceIdentity{Inode: 1}, kernelLinkOps{}, []kernelDumpSpec{spec}); err == nil || got.Records != nil {
			t.Fatal("invalid transport plan admitted")
		}
	}
}
