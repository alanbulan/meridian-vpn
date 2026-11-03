//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
)

var injectedError = errors.New("synthetic-password-never-expose")

type memoryJournal struct {
	r                 *Record
	trace             *[]string
	loadErr, clearErr error
	saves             int
	failSave          int
	writeOnError      bool
}

func (j *memoryJournal) Load() (*Record, error) {
	*j.trace = append(*j.trace, "load")
	if j.loadErr != nil {
		return nil, j.loadErr
	}
	if j.r == nil {
		return nil, nil
	}
	r := *j.r
	return &r, nil
}
func (j *memoryJournal) Save(r Record) error {
	*j.trace = append(*j.trace, "save:"+r.Phase)
	j.saves++
	if j.saves == j.failSave {
		if j.writeOnError {
			j.r = &r
		}
		return injectedError
	}
	j.r = &r
	return nil
}
func (j *memoryJournal) Clear() error {
	*j.trace = append(*j.trace, "clear")
	if j.clearErr != nil {
		return j.clearErr
	}
	j.r = nil
	return nil
}

type fakePeer struct {
	trace                  *[]string
	id                     Identity
	checks                 int
	failCheckFrom          int
	failPublish            string
	withdrawErr, absentErr error
	cancel                 context.CancelFunc
	seenCleanupContext     bool
}

func (p *fakePeer) Check(ctx context.Context, id Identity) error {
	*p.trace = append(*p.trace, "check")
	p.checks++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if id != p.id || (p.failCheckFrom > 0 && p.checks >= p.failCheckFrom) {
		return injectedError
	}
	return nil
}
func (p *fakePeer) Publish(ctx context.Context, id Identity, name string, values map[string]dbus.Variant) error {
	*p.trace = append(*p.trace, "publish:"+name)
	if id != p.id || ctx.Err() != nil || len(values) == 0 {
		return injectedError
	}
	if name == p.failPublish {
		if p.cancel != nil {
			p.cancel()
		}
		return injectedError
	}
	return nil
}
func (p *fakePeer) Withdraw(ctx context.Context, id Identity) error {
	*p.trace = append(*p.trace, "withdraw")
	_, bounded := ctx.Deadline()
	p.seenCleanupContext = bounded && ctx.Err() == nil
	if ctx.Err() != nil || id != p.id {
		return injectedError
	}
	return p.withdrawErr
}
func (p *fakePeer) ProveAbsent(ctx context.Context, id Identity) error {
	*p.trace = append(*p.trace, "absent")
	if ctx.Err() != nil || id != p.id {
		return injectedError
	}
	return p.absentErr
}
func controllerFixture(t *testing.T) (*Controller, *fakePeer, *memoryJournal, *[]string) {
	t.Helper()
	trace := []string{}
	p := &fakePeer{trace: &trace, id: journalFixture().Identity}
	j := &memoryJournal{trace: &trace}
	c, err := NewController(p, j)
	if err != nil {
		t.Fatal(err)
	}
	return c, p, j, &trace
}
func publishFixture(c *Controller, p *fakePeer) error {
	o, policy := configFixture()
	return c.Publish(context.Background(), p.id, o, policy)
}
func safeError(t *testing.T, err error) {
	t.Helper()
	if err == nil || strings.Contains(err.Error(), injectedError.Error()) {
		t.Fatal("missing error or leaked peer details", err)
	}
}

func TestControllerPersistsBeforePublishingAndCleansBeforeReuse(t *testing.T) {
	c, p, j, trace := controllerFixture(t)
	if err := publishFixture(c, p); err != nil {
		t.Fatal(err)
	}
	want := []string{"load", "check", "save:intent", "check", "publish:Config", "check", "publish:Ip4Config", "check", "save:published"}
	if !reflect.DeepEqual(*trace, want) {
		t.Fatal("publication order", *trace)
	}
	if j.r == nil || j.r.Phase != "published" {
		t.Fatal("published record missing")
	}
	safeError(t, publishFixture(c, p))
	if !reflect.DeepEqual(*trace, want) {
		t.Fatal("duplicate publication performed I/O")
	}
	*trace = nil
	if err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*trace, []string{"load", "save:quarantine", "check", "withdraw", "absent", "clear"}) {
		t.Fatal("cleanup order", *trace)
	}
	if j.r != nil {
		t.Fatal("cleanup retained successful record")
	}
	if err := publishFixture(c, p); err != nil {
		t.Fatal("controller did not become reusable", err)
	}
}

func TestControllerPrepublicationFailuresDoNotMutateNetwork(t *testing.T) {
	for _, kind := range []string{"load", "identity", "offer", "check", "intent", "uncertain intent", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			c, p, j, trace := controllerFixture(t)
			o, policy := configFixture()
			id := p.id
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "load":
				j.loadErr = injectedError
			case "identity":
				id.BusID = ""
			case "offer":
				o.Session = strings.Repeat("a", 32)
			case "check":
				p.failCheckFrom = 1
			case "intent":
				j.failSave = 1
			case "uncertain intent":
				j.failSave = 1
				j.writeOnError = true
			case "cancel":
				cancel()
			}
			safeError(t, c.Publish(ctx, id, o, policy))
			for _, event := range *trace {
				if strings.HasPrefix(event, "publish:") || event == "withdraw" {
					t.Fatal("network operation before durable intent", *trace)
				}
			}
			if kind == "intent" || kind == "uncertain intent" {
				safeError(t, publishFixture(c, p))
			}
		})
	}
}

func TestControllerPublicationFailureUsesFreshCleanupContext(t *testing.T) {
	for _, signal := range []string{"Config", "Ip4Config"} {
		t.Run(signal, func(t *testing.T) {
			c, p, j, trace := controllerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p.failPublish = signal
			p.cancel = cancel
			o, policy := configFixture()
			safeError(t, c.Publish(ctx, p.id, o, policy))
			if !p.seenCleanupContext || j.r != nil || c.blocked {
				t.Fatal("cancel prevented verified cleanup", *trace)
			}
		})
	}
}

func TestControllerKeepsUncertainCleanupQuarantined(t *testing.T) {
	for _, kind := range []string{"withdraw", "absent", "quarantine save", "clear", "published save", "owner lost"} {
		t.Run(kind, func(t *testing.T) {
			c, p, j, trace := controllerFixture(t)
			if kind == "published save" {
				j.failSave = 2
				p.absentErr = injectedError
				safeError(t, publishFixture(c, p))
			} else {
				if err := publishFixture(c, p); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "withdraw":
					p.withdrawErr = injectedError
				case "absent":
					p.absentErr = injectedError
				case "quarantine save":
					j.failSave = 3
				case "clear":
					j.clearErr = injectedError
				case "owner lost":
					p.failCheckFrom = p.checks + 1
				}
				safeError(t, c.Stop(context.Background()))
			}
			if j.r == nil || !c.blocked {
				t.Fatal("lost uncertain recovery evidence", *trace)
			}
			before := len(*trace)
			safeError(t, publishFixture(c, p))
			if len(*trace) != before {
				t.Fatal("quarantined controller performed I/O")
			}
			if kind == "owner lost" {
				for _, event := range *trace {
					if event == "withdraw" {
						t.Fatal("withdrew different owner")
					}
				}
			}
		})
	}
}

func TestControllerRestartReconcilesWithoutReplay(t *testing.T) {
	for _, phase := range []string{"intent", "published", "quarantine"} {
		t.Run(phase, func(t *testing.T) {
			c, p, j, trace := controllerFixture(t)
			r := journalFixture()
			r.Phase = phase
			j.r = &r
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if j.r != nil || c.blocked {
				t.Fatal("same generation not cleaned")
			}
			for _, event := range *trace {
				if strings.HasPrefix(event, "publish:") {
					t.Fatal("restart replayed configuration")
				}
			}
			if p.checks != 1 {
				t.Fatal("identity not checked")
			}
		})
	}
}

func TestControllerRestartRejectsEveryIdentityChange(t *testing.T) {
	changes := map[string]func(*Identity){
		"boot":        func(i *Identity) { i.BootID = "abcdef01-2345-6789-abcd-0123456789ab" },
		"bus":         func(i *Identity) { i.BusID = strings.Repeat("a", 32) },
		"owner":       func(i *Identity) { i.Owner = ":1.43" },
		"UUID":        func(i *Identity) { i.UUID = "abcdef01-2345-6789-abcd-0123456789ab" },
		"active path": func(i *Identity) { i.ActivePath = "/org/freedesktop/NetworkManager/ActiveConnection/8" },
		"session":     func(i *Identity) { i.Session = strings.Repeat("b", 32) },
		"interface":   func(i *Identity) { i.Interface = "meridian1" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, p, j, trace := controllerFixture(t)
			r := journalFixture()
			j.r = &r
			change(&p.id)
			safeError(t, c.Reconcile(context.Background()))
			if j.r == nil || j.r.Phase != "quarantine" {
				t.Fatal("changed identity not retained")
			}
			for _, event := range *trace {
				if event == "withdraw" || event == "absent" || event == "clear" {
					t.Fatal("mutated after identity loss", *trace)
				}
			}
		})
	}
}

func TestControllerRejectsCorruptRecordAndExpiredCleanup(t *testing.T) {
	c, _, j, trace := controllerFixture(t)
	j.r = &Record{}
	safeError(t, c.Reconcile(context.Background()))
	if !reflect.DeepEqual(*trace, []string{"load"}) {
		t.Fatal("corrupt record caused side effect", *trace)
	}
	c, _, j, trace = controllerFixture(t)
	r := journalFixture()
	j.r = &r
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	safeError(t, c.Stop(ctx))
	if !reflect.DeepEqual(*trace, []string{"load", "save:quarantine"}) {
		t.Fatal("expired cleanup contacted peer", *trace)
	}
}

func TestControllerConcurrentPublishHasOneGeneration(t *testing.T) {
	c, p, j, trace := controllerFixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- publishFixture(c, p) }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 || j.r == nil {
		t.Fatal("concurrent publications admitted")
	}
	count := 0
	for _, event := range *trace {
		if event == "publish:Config" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("configuration emitted twice")
	}
}

func TestControllerRejectsTypedNilDependencies(t *testing.T) {
	_, p, j, _ := controllerFixture(t)
	var missingPeer *fakePeer
	var missingJournal *memoryJournal
	for _, pair := range []struct {
		p Peer
		j Journal
	}{{nil, j}, {missingPeer, j}, {p, nil}, {p, missingJournal}} {
		if c, err := NewController(pair.p, pair.j); err == nil || c != nil {
			t.Fatal("accepted nil dependency")
		}
	}
}

func TestControllerIdentityLossDuringPublicationStopsImmediately(t *testing.T) {
	for _, check := range []int{2, 3, 4} {
		t.Run(string(rune('0'+check)), func(t *testing.T) {
			c, p, j, trace := controllerFixture(t)
			p.failCheckFrom = check
			safeError(t, publishFixture(c, p))
			if j.r == nil || j.r.Phase != "quarantine" || !c.blocked {
				t.Fatal("lost identity not quarantined")
			}
			published := 0
			for _, event := range *trace {
				if strings.HasPrefix(event, "publish:") {
					published++
				}
				if event == "withdraw" || event == "absent" || event == "clear" {
					t.Fatal("cleanup mutated after identity loss", *trace)
				}
			}
			if published != check-2 {
				t.Fatal("continued publishing after identity loss", *trace)
			}
		})
	}
}

func TestControllerPublishedSaveFailureCanCleanSafely(t *testing.T) {
	c, p, j, trace := controllerFixture(t)
	j.failSave = 2
	safeError(t, publishFixture(c, p))
	if j.r != nil || c.blocked || !p.seenCleanupContext {
		t.Fatal("successful cleanup not recorded", *trace)
	}
	if err := publishFixture(c, p); err != nil {
		t.Fatal("verified cleanup did not allow reuse", err)
	}
}

func TestControllerUncertainClearCannotReopenGeneration(t *testing.T) {
	c, p, j, _ := controllerFixture(t)
	if err := publishFixture(c, p); err != nil {
		t.Fatal(err)
	}
	j.clearErr = injectedError
	safeError(t, c.Stop(context.Background()))
	// Model an unlink that happened even though directory fsync returned an error.
	j.r = nil
	j.clearErr = nil
	safeError(t, c.Reconcile(context.Background()))
	safeError(t, publishFixture(c, p))
}
