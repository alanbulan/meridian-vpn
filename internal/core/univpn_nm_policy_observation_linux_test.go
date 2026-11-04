//go:build linux

package core

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"mygo-vpn/internal/packetrelay"
)

func TestUniVPNNMKernelPolicyObservation(t *testing.T) {
	for _, mode := range []string{"success", "first read", "policy error", "cleanup error", "wrong namespace", "second read", "changed link", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f, l, kernel := uniVPNKernelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			link := func(ctx context.Context) (UniVPNNMKernelObservation, error) {
				calls++
				if (mode == "first read" && calls == 1) || (mode == "second read" && calls == 2) {
					return UniVPNNMKernelObservation{}, errors.New("injected")
				}
				return l.observeKernelLink(ctx, func(context.Context) (packetrelay.TUNKernelObservation, error) {
					value := kernel
					if mode == "changed link" && calls == 2 {
						value.Link.MTU++
					}
					return value, nil
				})
			}
			data := []byte{1, 2, 3}
			policy := func(ctx context.Context, ns packetrelay.KernelNamespaceIdentity) (packetrelay.KernelPolicyObservation, error) {
				if ns != kernel.Namespace {
					t.Fatal("namespace not derived from original TUN")
				}
				if mode == "cleanup error" {
					return packetrelay.KernelPolicyObservation{}, packetrelay.ErrCleanup
				}
				if mode == "policy error" {
					return packetrelay.KernelPolicyObservation{}, errors.New("injected")
				}
				if mode == "wrong namespace" {
					ns.Inode++
				}
				if mode == "canceled" {
					cancel()
				}
				return packetrelay.KernelPolicyObservation{Namespace: ns, Records: []packetrelay.KernelPolicyRecord{{Type: 24, Data: data}}}, nil
			}
			got, err := l.observeKernelPolicy(ctx, link, policy)
			if mode == "success" {
				if err != nil || calls != 2 || got.Policy.Namespace != kernel.Namespace || len(got.Policy.Records) != 1 {
					t.Fatal("lost policy association", got, err)
				}
				got.Policy.Records[0].Data[0] = 99
				if data[0] != 1 {
					t.Fatal("policy records alias source")
				}
			} else if err == nil || !reflect.DeepEqual(got, UniVPNNMPolicyObservation{}) {
				t.Fatal("partial policy observation escaped", got, err)
			}
			if mode == "cleanup error" && !errors.Is(err, packetrelay.ErrCleanup) {
				t.Fatal("cleanup uncertainty lost")
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}

func TestUniVPNNMKernelPolicyRejectsMissingInputs(t *testing.T) {
	var missing *UniVPNNMLocalBinding
	for _, binding := range []*UniVPNNMLocalBinding{nil, {}, {self: missing}} {
		if got, err := binding.ObserveKernelPolicy(context.Background()); err == nil || !reflect.DeepEqual(got, UniVPNNMPolicyObservation{}) {
			t.Fatal("invalid original owner accepted")
		}
	}
}
