package macosvpn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
)

var ErrPolicyReadback = errors.New("独立网络策略读回不完整或观测期间发生变化")

// NetworkPolicySnapshot combines independent kernel routes and consolidated
// DNS resolver configuration. It is diagnostic evidence, not a policy approval:
// route selection metrics, per-app rules, actual DNS query routing and IPv6
// packet-filter enforcement are not represented, and no atomic snapshot exists.
type NetworkPolicySnapshot struct {
	Routes      KernelRouteReadback
	DNS         DNSReadback
	Fingerprint [32]byte
}
type NetworkRestorationComparison struct {
	RepresentedRouteAndResolverStateEqual bool
	CompleteCleanupVerified               bool // Always false; omitted kernel/policy state matters.
}

func policyReadbackFingerprint(routes KernelRouteReadback, dns DNSReadback) ([32]byte, error) {
	var zero [32]byte
	if len(routes.Records) > MaxKernelRouteRecords || routes.Bytes < 0 || routes.Bytes > MaxKernelRouteBytes || len(dns.Resolvers) > 128 {
		return zero, ErrPolicyReadback
	}
	routeRows := make([]string, 0, len(routes.Records))
	for _, record := range routes.Records {
		if !record.Prefix.IsValid() || record.InterfaceIndex <= 0 {
			return zero, ErrPolicyReadback
		}
		data, err := json.Marshal(record)
		if err != nil {
			return zero, ErrPolicyReadback
		}
		routeRows = append(routeRows, string(data))
	}
	dnsRows := make([]string, 0, len(dns.Resolvers))
	for _, resolver := range dns.Resolvers {
		if len(resolver.Nameservers) > 16 || len(resolver.SearchDomains) > 16 || len(resolver.Flags) > 5 || len(resolver.Domain) > 253 || len(resolver.Options) > 32 {
			return zero, ErrPolicyReadback
		}
		data, err := json.Marshal(resolver)
		if err != nil || len(data) > 16384 {
			return zero, ErrPolicyReadback
		}
		dnsRows = append(dnsRows, string(data))
	}
	// RIB ordering is not policy, but DNS resolver ordering can be. Preserve DNS
	// record order, nameserver/search order and every represented field.
	slices.Sort(routeRows)
	data, err := json.Marshal(struct{ Routes, DNS []string }{routeRows, dnsRows})
	if err != nil {
		return zero, ErrPolicyReadback
	}
	return sha256.Sum256(data), nil
}
func ReadNetworkPolicySnapshot(ctx context.Context) (NetworkPolicySnapshot, error) {
	return readNetworkPolicySnapshot(ctx, ReadKernelRoutes, ReadDNSConfiguration)
}
func readNetworkPolicySnapshot(ctx context.Context, routes func(context.Context) (KernelRouteReadback, error), dns func(context.Context) (DNSReadback, error)) (NetworkPolicySnapshot, error) {
	var zero NetworkPolicySnapshot
	if ctx == nil || routes == nil || dns == nil {
		return zero, ErrPolicyReadback
	}
	var previous [32]byte
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			return zero, ErrPolicyReadback
		}
		r, err := routes(ctx)
		if err != nil {
			return zero, ErrPolicyReadback
		}
		if ctx.Err() != nil {
			return zero, ErrPolicyReadback
		}
		d, err := dns(ctx)
		if err != nil || ctx.Err() != nil {
			return zero, ErrPolicyReadback
		}
		fingerprint, err := policyReadbackFingerprint(r, d)
		if err != nil {
			return zero, err
		}
		if i == 1 {
			if previous != fingerprint {
				return zero, ErrPolicyReadback
			}
			return NetworkPolicySnapshot{r, d, fingerprint}, nil
		}
		previous = fingerprint
	}
	return zero, ErrPolicyReadback
}

// CompareNetworkRestoration reports only equality of the represented snapshots.
// It must never be used as policyVerifier.restored: interface disappearance,
// generation ownership, omitted metrics, resolver provenance and packet filters
// remain separate requirements. It never restores/writes a global baseline.
func CompareNetworkRestoration(before, after NetworkPolicySnapshot) (NetworkRestorationComparison, error) {
	a, err := policyReadbackFingerprint(before.Routes, before.DNS)
	if err != nil {
		return NetworkRestorationComparison{}, err
	}
	b, err := policyReadbackFingerprint(after.Routes, after.DNS)
	if err != nil {
		return NetworkRestorationComparison{}, err
	}
	if a != before.Fingerprint || b != after.Fingerprint {
		return NetworkRestorationComparison{}, ErrPolicyReadback
	}
	return NetworkRestorationComparison{RepresentedRouteAndResolverStateEqual: a == b}, nil
}
