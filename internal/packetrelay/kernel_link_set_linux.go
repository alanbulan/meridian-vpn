//go:build linux

package packetrelay

import (
	"context"
	"encoding/binary"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// KernelLinkIdentity is historical membership/name metadata, not a device
// generation ID. Ifindexes and names can be reused between sequential reads.
type KernelLinkIdentity struct {
	Index int32
	Name  string
}

type KernelLinkSetSnapshot struct {
	Namespace KernelNamespaceIdentity
	Links     []KernelLinkIdentity
}

// KernelLinkSet is a non-owning historical token from a complete kernel dump.
// Public callers cannot construct a valid token or replace its retained list.
// It is not a lease or proof that membership remains unchanged after the read.
type KernelLinkSet struct {
	self     *KernelLinkSet
	snapshot KernelLinkSetSnapshot
}

func (s *KernelLinkSet) Snapshot() (KernelLinkSetSnapshot, error) {
	if s == nil || s.self != s {
		return KernelLinkSetSnapshot{}, errTUNKernelObservation
	}
	return KernelLinkSetSnapshot{Namespace: s.snapshot.Namespace, Links: append([]KernelLinkIdentity(nil), s.snapshot.Links...)}, nil
}

// ObserveKernelLinkSet reads every link in the independently identified current
// network namespace, without entering namespaces or changing networking. It uses
// the same bounded kernel-only multipart transport as the policy reader. No
// caller-selected subset or interface-name discovery replaces the complete dump.
// Namespace identity alone does not establish initial-host provenance.
func ObserveKernelLinkSet(ctx context.Context, expected KernelNamespaceIdentity) (*KernelLinkSet, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return observeKernelLinkSetWith(ctx, expected, realKernelLinkOps())
}

func observeKernelLinkSetWith(ctx context.Context, expected KernelNamespaceIdentity, ops kernelLinkOps) (*KernelLinkSet, error) {
	observed, err := observeKernelRecordsWith(ctx, expected, ops, []kernelDumpSpec{{unix.RTM_GETLINK, unix.AF_UNSPEC}})
	if err != nil {
		return nil, err
	}
	links, err := parseKernelLinkSet(observed.Records)
	if err != nil {
		return nil, err
	}
	s := &KernelLinkSet{snapshot: KernelLinkSetSnapshot{Namespace: observed.Namespace, Links: links}}
	s.self = s
	return s, nil
}

func parseKernelLinkSet(records []KernelPolicyRecord) ([]KernelLinkIdentity, error) {
	if len(records) == 0 || len(records) > 1024 {
		return nil, errTUNKernelObservation
	}
	seenIndexes, seenNames := map[int32]bool{}, map[string]bool{}
	links := make([]KernelLinkIdentity, 0, len(records))
	for _, record := range records {
		if record.Type != unix.RTM_NEWLINK || len(record.Data) < 16 || record.Data[0] != unix.AF_UNSPEC || record.Data[1] != 0 {
			return nil, errTUNKernelObservation
		}
		index := int32(binary.NativeEndian.Uint32(record.Data[4:]))
		attrs, err := kernelAttributes(record.Data[16:], 0)
		if err != nil {
			return nil, err
		}
		value, ok := attrs[unix.IFLA_IFNAME]
		if !ok || value.flags != 0 || len(value.value) < 2 || len(value.value) > 16 || value.value[len(value.value)-1] != 0 {
			return nil, errTUNKernelObservation
		}
		name := string(value.value[:len(value.value)-1])
		if index <= 0 || seenIndexes[index] || seenNames[name] || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00/ \t\r\n") {
			return nil, errTUNKernelObservation
		}
		seenIndexes[index], seenNames[name] = true, true
		links = append(links, KernelLinkIdentity{Index: index, Name: name})
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Index < links[j].Index })
	return links, nil
}
