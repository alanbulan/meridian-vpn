//go:build linux

package core

import (
	"os/exec"

	"mygo-vpn/internal/packetrelay"
)

// This witness is installed only by the concrete launch path, after pair
// acquisition, native duplication and fixed-FD wiring. It retains identities,
// never duplicates, uses or closes either endpoint. It is not host authority.
type uniVPNPacketProvenance struct {
	process *uniVPNExecProcess
	child   *packetrelay.DatagramPackets
	session string
	claimed bool // protected by process.packetMu; permanent after local attempt
}

func retainUniVPNPacketProvenance(p *uniVPNExecProcess, provider UniVPNPacketProvider, native uniVPNPacketNative) error {
	concrete, ok := provider.(*UniVPNPacketPairProvider)
	if !ok {
		return nil // Existing trusted providers do not gain concrete-pair proof.
	}
	if concrete == nil || concrete.self != concrete || p == nil || p.packetPair != nil || p.cmd == nil || p.offer == nil || !validUniVPNPacketSession(p.sessionID) || native.file == nil || nilInterface(native.owner) || len(p.cmd.ExtraFiles) != 4 || p.cmd.ExtraFiles[3] != native.file {
		return errUniVPNNM
	}
	child, ok := p.packet.(*packetrelay.DatagramPackets)
	if !ok || child == nil {
		return errUniVPNNM
	}
	p.packetPair = &uniVPNPacketProvenance{process: p, child: child, session: p.sessionID}
	return nil
}

// Keep acquisition provenance and optional structural wrapping in one tested
// orchestration step. The bootstrap appends its root/image handles after the
// four transport slots. No command starts here; Launch retains rollback duties.
func prepareUniVPNPacketProcess(p *uniVPNExecProcess, provider UniVPNPacketProvider, native uniVPNPacketNative, digest string) error {
	if p == nil || p.cmd == nil {
		return errUniVPNNM
	}
	if err := retainUniVPNPacketProvenance(p, provider, native); err != nil {
		return err
	}
	if worker, ok := p.isolation.(interface{ wrap(*exec.Cmd, string) error }); ok {
		return worker.wrap(p.cmd, digest)
	}
	return nil
}
