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

func policyReply(kind uint16, family byte, seq, port uint32) []byte {
	b := kernelPolicyRequest(kind, family, seq, port)
	binary.NativeEndian.PutUint16(b[4:], kind-2)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_MULTI)
	return b
}
func policyDone(seq, port uint32) []byte {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint32(b, 20)
	binary.NativeEndian.PutUint16(b[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_MULTI)
	binary.NativeEndian.PutUint32(b[8:], seq)
	binary.NativeEndian.PutUint32(b[12:], port)
	return b
}

func TestKernelPolicyReplyValidation(t *testing.T) {
	for _, kind := range []uint16{unix.RTM_GETADDR, unix.RTM_GETROUTE, unix.RTM_GETRULE} {
		for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
			b := append(policyReply(kind, family, 7, 99), policyDone(7, 99)...)
			r, done, err := parseKernelPolicyReply(b, kind, family, 7, 99)
			if err != nil || !done || len(r) != 1 || r[0].Type != kind-2 || r[0].Data[0] != family {
				t.Fatal("valid dump rejected", err)
			}
			b[16] = 0
			if r[0].Data[0] != family {
				t.Fatal("record aliases receive buffer")
			}
		}
	}
	for name, change := range map[string]func([]byte) []byte{
		"sequence":      func(b []byte) []byte { b[8]++; return b },
		"port":          func(b []byte) []byte { b[12]++; return b },
		"interrupted":   func(b []byte) []byte { b[6] |= unix.NLM_F_DUMP_INTR; return b },
		"filtered":      func(b []byte) []byte { b[6] |= unix.NLM_F_DUMP_FILTERED; return b },
		"not multipart": func(b []byte) []byte { b[6] = 0; return b },
		"wrong family":  func(b []byte) []byte { b[16] = unix.AF_INET6; return b },
		"wrong type":    func(b []byte) []byte { b[4] = unix.RTM_NEWADDR; return b },
		"error":         func(b []byte) []byte { b[4] = unix.NLMSG_ERROR; return b },
		"truncated":     func(b []byte) []byte { return b[:len(b)-1] },
		"after done":    func(b []byte) []byte { return append(policyDone(7, 99), b...) },
		"failed done":   func(b []byte) []byte { d := policyDone(7, 99); d[16] = 1; return append(b, d...) },
		"malformed attr": func(b []byte) []byte {
			b = append(b, 3, 0, 1, 0)
			binary.NativeEndian.PutUint32(b, uint32(len(b)))
			return b
		},
	} {
		t.Run(name, func(t *testing.T) {
			if r, _, err := parseKernelPolicyReply(change(policyReply(unix.RTM_GETROUTE, unix.AF_INET, 7, 99)), unix.RTM_GETROUTE, unix.AF_INET, 7, 99); err == nil || r != nil {
				t.Fatal("malformed dump accepted")
			}
		})
	}
	b := policyReply(unix.RTM_GETROUTE, unix.AF_INET, 7, 99)
	b = append(b, 8, 0, 123, 0, 1, 2, 3, 4)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	r, _, err := parseKernelPolicyReply(b, unix.RTM_GETROUTE, unix.AF_INET, 7, 99)
	if err != nil || !reflect.DeepEqual(r[0].Data[12:], b[28:]) {
		t.Fatal("unknown policy data lost")
	}
}

func TestKernelPolicyReadbackBoundaries(t *testing.T) {
	for _, mode := range []string{"success", "empty", "multipart", "retry send", "retry receive", "retry interrupted", "poll failure", "foreign sender", "truncated", "namespace changed", "namespace close failure", "socket close failure", "canceled", "receive failure", "interrupted", "budget", "byte budget", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ns := KernelNamespaceIdentity{Device: 1, Inode: 2}
			now := time.Unix(100, 0)
			var request []byte
			reads, sends, opened, nsClosed, socketClosed := 0, 0, 0, 0, 0
			requestReads := 0
			ops := kernelLinkOps{
				namespace: func() (KernelNamespaceIdentity, func() error, error) {
					opened++
					id := ns
					if mode == "namespace changed" && opened == 3 {
						id.Inode++
					}
					return id, func() error {
						nsClosed++
						if mode == "namespace close failure" {
							return errors.New("close")
						}
						return nil
					}, nil
				},
				socket: func() (int, error) { return 42, nil },
				bind:   func(int) error { return nil },
				port:   func(int) (uint32, error) { return 99, nil },
				send: func(_ int, b []byte) error {
					sends++
					requestReads = 0
					request = append([]byte(nil), b...)
					if sends == 1 && (mode == "retry send" || mode == "poll failure") {
						return unix.EAGAIN
					}
					if sends == 1 && mode == "retry interrupted" {
						return unix.EINTR
					}
					if mode == "canceled" {
						cancel()
					}
					if mode == "timeout" {
						now = now.Add(3 * time.Second)
					}
					if binary.NativeEndian.Uint16(b[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_DUMP {
						t.Fatal("mutation flags sent")
					}
					return nil
				},
				recv: func(_ int, b []byte) (int, int, unix.Sockaddr, error) {
					reads++
					requestReads++
					if reads == 1 && mode == "retry receive" {
						return 0, 0, nil, unix.EAGAIN
					}
					if reads == 1 && mode == "retry interrupted" {
						return 0, 0, nil, unix.EINTR
					}
					if mode == "receive failure" {
						return 0, 0, nil, unix.ENOBUFS
					}
					seq := binary.NativeEndian.Uint32(request[8:])
					v := policyReply(binary.NativeEndian.Uint16(request[4:]), request[16], seq, 99)
					if mode == "interrupted" {
						v[6] |= unix.NLM_F_DUMP_INTR
					}
					if mode == "empty" || (mode == "multipart" && requestReads == 2) {
						v = policyDone(seq, 99)
					} else if mode == "multipart" {
						// The terminator arrives in the next datagram.
					} else if mode == "byte budget" {
						// One large unknown attribute reaches the byte cap before
						// the record cap. It is retained, never policy-approved.
						a := make([]byte, 60000)
						binary.NativeEndian.PutUint16(a, uint16(len(a)))
						binary.NativeEndian.PutUint16(a[2:], 123)
						v = append(v, a...)
						binary.NativeEndian.PutUint32(v, uint32(len(v)))
					} else if mode == "budget" {
						one := append([]byte(nil), v...)
						for len(v)+len(one) <= len(b) {
							v = append(v, one...)
						}
					} else {
						v = append(v, policyDone(seq, 99)...)
					}
					copy(b, v)
					sender := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
					if mode == "foreign sender" {
						sender.Pid = 123
					}
					flags := 0
					if mode == "truncated" {
						flags = unix.MSG_TRUNC
					}
					return len(v), flags, sender, nil
				},
				poll: func(int, int16, int) (int16, error) {
					if mode == "poll failure" {
						return unix.POLLERR, nil
					}
					return 0, nil
				},
				close: func(int) error {
					socketClosed++
					if mode == "socket close failure" {
						return errors.New("close")
					}
					return nil
				},
				now: func() time.Time { return now },
			}
			got, err := observeKernelPolicyWith(ctx, ns, ops)
			if mode == "success" || mode == "empty" || mode == "multipart" || mode == "retry send" || mode == "retry receive" || mode == "retry interrupted" {
				wantRecords, wantReads, wantSends := 6, 6, 6
				if mode == "retry send" || mode == "retry interrupted" {
					wantSends++
				}
				if mode == "retry receive" || mode == "retry interrupted" {
					wantReads++
				}
				if mode == "empty" {
					wantRecords = 0
				}
				if mode == "multipart" {
					wantReads = 12
				}
				if err != nil || got.Namespace != ns || len(got.Records) != wantRecords || sends != wantSends || reads != wantReads {
					t.Fatal("incomplete policy observation", got, err)
				}
			} else if err == nil || got.Namespace != (KernelNamespaceIdentity{}) || got.Records != nil {
				t.Fatal("partial or invalid observation escaped", got, err)
			}
			if opened != nsClosed || socketClosed != 1 {
				t.Fatal("retained descriptors not closed exactly once")
			}
			if (mode == "namespace close failure" || mode == "socket close failure") && !errors.Is(err, ErrCleanup) {
				t.Fatal("cleanup uncertainty lost")
			}
		})
	}
}
