//go:build linux

package nmvpn

import "testing"

func activationRecordFixture() ActivationRecord {
 return ActivationRecord{Version: 1, BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", BusID: "0123456789abcdef0123456789abcdef", Owner: ":1.2", PluginOwner: ":1.3", UUID: "12345678-1234-1234-1234-123456789abc", Interface: "meridian0", Nonce: "fedcba9876543210fedcba9876543210", Phase: "add-intent"}
}
func TestActivationRecordStages(t *testing.T) {
 for _, phase := range []string{"add-intent", "added", "activate-intent", "activated", "correlated", "quarantine"} {
  for settings := 0; settings < 2; settings++ {
   for active := 0; active < 2; active++ {
    r := activationRecordFixture(); r.Phase = phase
    if settings != 0 { r.ConnectionPath = "/org/freedesktop/NetworkManager/Settings/7" }
    if active != 0 { r.ActivePath = "/org/freedesktop/NetworkManager/ActiveConnection/9" }
    want := false
    switch phase {
    case "add-intent": want = settings == 0 && active == 0
    case "added", "activate-intent": want = settings == 1 && active == 0
    case "activated", "correlated": want = settings == 1 && active == 1
    case "quarantine": want = active == 0 || settings == 1
    }
    if got := validateActivationRecord(r) == nil; got != want { t.Fatalf("phase=%s settings=%d active=%d valid=%v", phase, settings, active, got) }
   }
  }
 }
}
func TestActivationRecordRejectsMalformedPins(t *testing.T) {
 for _, mutate := range []func(*ActivationRecord){
  func(r *ActivationRecord){r.Version=2}, func(r *ActivationRecord){r.BootID=""},
  func(r *ActivationRecord){r.BusID=""}, func(r *ActivationRecord){r.Owner=NMName},
  func(r *ActivationRecord){r.PluginOwner=PluginService}, func(r *ActivationRecord){r.Nonce=""},
  func(r *ActivationRecord){r.Interface="lo"}, func(r *ActivationRecord){r.UUID=""},
  func(r *ActivationRecord){r.Phase="done"}, func(r *ActivationRecord){r.ConnectionPath="/"},
 } { r:=activationRecordFixture(); mutate(&r); if validateActivationRecord(r)==nil {t.Fatal("invalid record accepted")} }
}
