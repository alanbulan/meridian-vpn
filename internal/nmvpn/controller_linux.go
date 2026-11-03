//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// Identity is assigned and verified by the trusted broker/NM adapter, not the
// desktop or remote gateway. BootID and BusID prevent name reuse after either
// a host reboot or a bus daemon restart within the same boot. BusID is GetId,
// NOT Peer.GetMachineId or the per-address authentication GUID.
// Session is a fresh broker generation, not a reusable connection UUID.
type Identity struct {
	BootID, BusID, Owner, UUID, ActivePath, Session, Interface string
}
type Record struct {
	Version  int
	Identity Identity
	Phase    string
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var ownerPattern = regexp.MustCompile(`^:[0-9]+\.[0-9]+$`)
var activePattern = regexp.MustCompile(`^/org/freedesktop/NetworkManager/ActiveConnection/[0-9]+$`)

func validateRecord(r Record) error {
	i := r.Identity
	if r.Version != 1 || (r.Phase != "intent" && r.Phase != "published" && r.Phase != "quarantine") || !uuidPattern.MatchString(i.BootID) || !sessionPattern.MatchString(i.BusID) || !uuidPattern.MatchString(i.UUID) || len(i.Owner) > 64 || !ownerPattern.MatchString(i.Owner) || len(i.ActivePath) > 128 || !activePattern.MatchString(i.ActivePath) || !sessionPattern.MatchString(i.Session) || !linkPattern.MatchString(i.Interface) || i.Interface == "lo" {
		return errors.New("invalid NM journal identity or phase")
	}
	return nil
}

// Peer is a SECURITY BOUNDARY, not implemented by this package. A production
// implementation must pin the authenticated system-bus NM owner and verify the
// whole identity on EVERY operation, including after an owner-change event.
// It must also reject a profile whose applied routes, DNS, default-route or IPv6
// settings add anything outside the approved configuration: NM can merge profile
// settings with these plugin payloads. The identity alone does not prove policy.
// Publish emits Plugin.Config then Plugin.Ip4Config only to that owner, never a
// broadcast. Its success is not activation proof. Withdraw deactivates only this
// exact generation and stops/joins its native worker and relay. All operations
// must honor context cancellation/deadlines without background mutations.
// ProveAbsent must read back removal of this session's link, routes, DNS, active
// connection and
// workers, not just disappearance of an NM object. No matching means no mutation.
type Peer interface {
	Check(context.Context, Identity) error
	Publish(context.Context, Identity, string, map[string]dbus.Variant) error
	Withdraw(context.Context, Identity) error
	ProveAbsent(context.Context, Identity) error
}

// Journal must belong to exactly ONE Controller for its entire lifecycle.
// Sharing an instance across Controllers defeats transaction serialization even
// if individual journal methods are locked. It must have durable Save/Clear and must
// reject corruption. FileJournal supplies this without storing addresses/secrets.
type Journal interface {
	Load() (*Record, error)
	Save(Record) error
	Clear() error
}

type Controller struct {
	mu      sync.Mutex
	peer    Peer
	journal Journal
	blocked bool // prevents reuse even when an attempted journal write failed
}

func nilValue(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func NewController(p Peer, j Journal) (*Controller, error) {
	if nilValue(p) || nilValue(j) {
		return nil, errors.New("trusted NM peer and journal required")
	}
	return &Controller{peer: p, journal: j}, nil
}

// Publish writes intent BEFORE either signal. It leaves the journal in place
// until Stop/Reconcile proves cleanup. Callers must not turn this into core.Ready.
func (c *Controller) Publish(ctx context.Context, id Identity, offer Offer, policy Policy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.blocked {
		return errors.New("NM controller quarantined")
	}
	old, err := c.journal.Load()
	if err != nil || old != nil {
		c.blocked = true
		return errors.New("NM reconciliation required")
	}
	r := Record{Version: 1, Identity: id, Phase: "intent"}
	if validateRecord(r) != nil || offer.Session != id.Session || offer.Interface != id.Interface {
		return errors.New("NM offer identity mismatch")
	}
	config, err := Encode(offer, policy)
	if err != nil {
		return err
	}
	if c.peer.Check(ctx, id) != nil {
		return errors.New("NM identity unavailable")
	}
	c.blocked = true
	if c.journal.Save(r) != nil {
		return errors.New("NM intent persistence failed")
	}
	for _, signal := range []struct {
		name   string
		values map[string]dbus.Variant
	}{{"Config", config.General}, {"Ip4Config", config.IPv4}} {
		if c.peer.Check(ctx, id) != nil || c.peer.Publish(ctx, id, signal.name, signal.values) != nil {
			return c.failed(r)
		}
	}
	if ctx.Err() != nil || c.peer.Check(ctx, id) != nil {
		return c.failed(r)
	}
	r.Phase = "published"
	if c.journal.Save(r) != nil {
		return c.failed(r)
	}
	return nil
}

// failed uses its own bounded context: caller cancellation must not skip cleanup.
// Peer errors are intentionally not exposed; they may contain credential material.
func (c *Controller) failed(r Record) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c.cleanup(ctx, r) != nil {
		return errors.New("NM publication failed; cleanup quarantined")
	}
	return errors.New("NM publication failed; cleanup verified")
}
func (c *Controller) cleanup(ctx context.Context, r Record) error {
	c.blocked = true
	r.Phase = "quarantine"
	// Failure to persist quarantine does not erase the earlier durable intent.
	persistErr := c.journal.Save(r)
	if ctx.Err() != nil {
		return errors.New("NM cleanup context expired")
	}
	if c.peer.Check(ctx, r.Identity) != nil {
		return errors.New("NM identity changed; reconciliation blocked")
	}
	if c.peer.Withdraw(ctx, r.Identity) != nil {
		return errors.New("NM withdrawal uncertain")
	}
	if c.peer.ProveAbsent(ctx, r.Identity) != nil {
		return errors.New("NM removal unproven")
	}
	// If quarantine write failed, keep the original record even after clean readback.
	if persistErr != nil {
		return errors.New("NM quarantine persistence failed")
	}
	if c.journal.Clear() != nil {
		return errors.New("NM cleanup journal clearance failed")
	}
	c.blocked = false
	return nil
}

// Reconcile never replays configuration after restart. Changed boot/owner/session
// identity stays quarantined for a future explicit recovery adapter; it must not
// target a replacement session or reconstruct ownership from a device name.
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, err := c.journal.Load()
	if err != nil {
		c.blocked = true
		return errors.New("NM journal unreadable")
	}
	if r == nil {
		if c.blocked {
			return errors.New("NM uncertain journal state; restart and inspection required")
		}
		return nil
	}
	if validateRecord(*r) != nil {
		c.blocked = true
		return errors.New("NM journal invalid")
	}
	return c.cleanup(ctx, *r)
}

// Stop is reconciliation of the persisted generation. Its caller should supply
// a fresh bounded cleanup context, not an already-cancelled connection context.
func (c *Controller) Stop(ctx context.Context) error { return c.Reconcile(ctx) }
