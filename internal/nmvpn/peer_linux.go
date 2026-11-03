//go:build linux

package nmvpn

import (
	"context"
	"net/netip"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// Binding is broker-owned evidence, not a claim from the desktop/gateway. The
// plugin connection must be the exact sender NM associated with this activation.
// UUID and device name alone do not identify that activation or its worker.
type Binding struct {
	Identity Identity
	ConnectionPath dbus.ObjectPath
	PluginOwner string
}

// Broker is the remaining host-authority boundary. Verify must bind immutable,
// authenticated incoming Connect evidence (sender, applied profile and local
// plugin connection), boot/session, real link/worker handles and this exact offer.
// ValidateProfile may check captured settings but is not evidence of their origin.
// The broker must also exclude global NM/dispatcher policy that adds networking.
// Stop joins only these worker/relay handles. ProveAbsent independently proves
// link/routes/DNS/workers gone for this generation, not just an NM object's loss.
// All methods must honor context, retain recovery authority after Stop, and never
// substitute another generation. No production implementation is supplied here.
type Broker interface {
	Verify(context.Context,Binding,Offer) error
	Stop(context.Context,Binding) error
	ProveAbsent(context.Context,Binding) error
}

// DBusPeer implements the NM wire half of Peer, conditional on a real trusted
// Broker. Success is not activation/readiness or an exclusive network lease.
// One peer owns one PinnedBus and one activation; it is not reusable after Stop.
type DBusPeer struct {
	mu sync.Mutex
	bus *PinnedBus
	broker Broker
	binding Binding
	offer Offer
	config Config
	stage int
	withdrawAttempted bool
	workerStopped bool
	localStopAttempted bool
}

var settingsPathPattern=regexp.MustCompile(`^/org/freedesktop/NetworkManager/Settings/[0-9]+$`)

func copyOffer(o Offer)Offer{
	o.Routes=append([]netip.Prefix(nil),o.Routes...)
	o.DNS=append([]netip.Addr(nil),o.DNS...)
	o.Domains=append([]string(nil),o.Domains...)
	return o
}

func NewDBusPeer(ctx context.Context,bus *PinnedBus,broker Broker,binding Binding,offer Offer,policy Policy)(*DBusPeer,error){
	if bus==nil || nilValue(broker) || validateRecord(Record{Version:1,Identity:binding.Identity,Phase:"intent"})!=nil || (len(binding.ConnectionPath)>128 || !settingsPathPattern.MatchString(string(binding.ConnectionPath))) || !validPluginOwner(binding.PluginOwner) || binding.PluginOwner!=bus.UniqueName() || binding.Identity.BusID!=bus.pin.BusID || binding.Identity.Owner!=bus.pin.Owner || offer.Session!=binding.Identity.Session || offer.Interface!=binding.Identity.Interface{return nil,errPeer}
	config,err:=Encode(offer,policy)
	if err!=nil{return nil,errPeer}
	p:=&DBusPeer{bus:bus,broker:broker,binding:binding,offer:copyOffer(offer),config:config}
	if err:=p.Check(ctx,binding.Identity);err!=nil{return nil,errPeer}
	return p,nil
}

func(p *DBusPeer)bound(id Identity)bool{return id==p.binding.Identity}
func(p *DBusPeer)verifyBroker(ctx context.Context)error{
	// The broker gets its own copy; neither it nor a caller can mutate the frozen
	// plan used to compare and emit payloads, including nested route slices.
	if err:=p.broker.Verify(ctx,p.binding,copyOffer(p.offer));err!=nil{return errPeer}
	if ctx.Err()!=nil{return errPeer}
	return nil
}

func(p *DBusPeer)checkLocked(ctx context.Context)error{
	if !p.bus.claimed || p.bus.check(ctx,true)!=nil || p.verifyBroker(ctx)!=nil{return errPeer}
	if !p.withdrawAttempted {
		var properties map[string]dbus.Variant
		if p.bus.call(ctx,p.binding.Identity.Owner,dbus.ObjectPath(p.binding.Identity.ActivePath),propertiesInterface+".GetAll",[]any{ActiveInterface},&properties)!=nil || len(properties)>64{return errPeer}
		if !profileEqual(properties["Uuid"],p.binding.Identity.UUID) || !profileEqual(properties["Type"],"vpn") || !profileEqual(properties["Vpn"],true) || !profileEqual(properties["Connection"],p.binding.ConnectionPath){return errPeer}
		var settings map[string]map[string]dbus.Variant
		if p.bus.call(ctx,p.binding.Identity.Owner,p.binding.ConnectionPath,SettingsInterface+".GetSettings",nil,&settings)!=nil || ValidateProfile(settings,p.binding.Identity)!=nil{return errPeer}
		present,err:=p.activePresent(ctx)
		if err!=nil || !present{return errPeer}
	}
	return p.bus.check(ctx,true)
}

func(p *DBusPeer)Check(ctx context.Context,id Identity)error{
	p.mu.Lock();defer p.mu.Unlock()
	if !p.bound(id){return errPeer}
	return p.bus.run(ctx,func(ctx context.Context)error{return p.checkLocked(ctx)})
}

func(p *DBusPeer)Publish(ctx context.Context,id Identity,member string,values map[string]dbus.Variant)error{
	p.mu.Lock();defer p.mu.Unlock()
	if !p.bound(id) || p.withdrawAttempted || p.localStopAttempted || p.workerStopped{return errPeer}
	var expected map[string]dbus.Variant
	if member=="Config" && p.stage==0 {expected=p.config.General} else if member=="Ip4Config" && p.stage==1 {expected=p.config.IPv4} else {return errPeer}
	if !reflect.DeepEqual(values,expected){return errPeer}
	return p.bus.run(ctx,func(ctx context.Context)error{
		if p.checkLocked(ctx)!=nil{return errPeer}
		// Advance before I/O: even an uncertain send is never automatically replayed.
		p.stage++
		if p.bus.emit(ctx,member,expected)!=nil{return errPeer}
		return p.bus.check(ctx,true)
	})
}

func(p *DBusPeer)activePresent(ctx context.Context)(bool,error){
	var variant dbus.Variant
	if p.bus.call(ctx,p.binding.Identity.Owner,NMPath,propertiesInterface+".Get",[]any{NMName,"ActiveConnections"},&variant)!=nil{return false,errPeer}
	paths,ok:=variant.Value().([]dbus.ObjectPath)
	if !ok || variant.Signature().String()!="ao" || len(paths)>4096{return false,errPeer}
	seen:=make(map[dbus.ObjectPath]bool,len(paths))
	present:=false
	for _,path:=range paths{
		if !path.IsValid() || path=="/" || seen[path]{return false,errPeer}
		seen[path]=true
		if string(path)==p.binding.Identity.ActivePath{present=true}
	}
	return present,nil
}

func(p *DBusPeer)Withdraw(ctx context.Context,id Identity)error{
	p.mu.Lock();defer p.mu.Unlock()
	if !p.bound(id){return errPeer}
	return p.bus.run(ctx,func(ctx context.Context)error{
		if p.checkLocked(ctx)!=nil{return errPeer}
		var deactivateErr error
		if !p.withdrawAttempted {
			p.withdrawAttempted=true
			deactivateErr=p.bus.call(ctx,p.binding.Identity.Owner,NMPath,NMName+".DeactivateConnection",[]any{dbus.ObjectPath(id.ActivePath)})
		} else {
			// A timed-out call may have executed. Never send it a second time.
			present,err:=p.activePresent(ctx)
			if err!=nil || present{return errPeer}
		}
		// Even if NM's reply is uncertain, stop only the independently verified
		// local generation. Raw NM errors never escape or become absence proof.
		if p.verifyBroker(ctx)!=nil{return errPeer}
		if !p.workerStopped {
			if p.broker.Stop(ctx,p.binding)!=nil{return errPeer}
			p.workerStopped=true
		}
		if deactivateErr!=nil{return errPeer}
		return p.bus.check(ctx,true)
	})
}

func(p *DBusPeer)ProveAbsent(ctx context.Context,id Identity)error{
	p.mu.Lock();defer p.mu.Unlock()
	if !p.bound(id) || !p.withdrawAttempted || !p.workerStopped{return errPeer}
	return p.bus.run(ctx,func(ctx context.Context)error{
		if p.bus.check(ctx,true)!=nil || p.verifyBroker(ctx)!=nil{return errPeer}
		present,err:=p.activePresent(ctx)
		if err!=nil || present{return errPeer}
		if p.broker.ProveAbsent(ctx,p.binding)!=nil{return errPeer}
		// Sequential, independent observations. This is deliberately not an
		// atomic lease; the trusted broker retains generation/handle authority.
		present,err=p.activePresent(ctx)
		if err!=nil || present{return errPeer}
		return p.bus.check(ctx,true)
	})
}

// StopLocal is independent of NM/bus reachability. It can only stop the broker's
// exact local generation and never clears journal/network uncertainty. This is
// also the fallback after cancellation has irreversibly closed the private bus.
func(p *DBusPeer)StopLocal(ctx context.Context,id Identity)error{
	p.mu.Lock();defer p.mu.Unlock()
	if !p.bound(id){return errPeer}
	ctx,cancel:=context.WithTimeout(ctx,10*time.Second);defer cancel()
	p.localStopAttempted=true
	if p.verifyBroker(ctx)!=nil{return errPeer}
	if !p.workerStopped {
		if p.broker.Stop(ctx,p.binding)!=nil{return errPeer}
		p.workerStopped=true
	}
	if ctx.Err()!=nil{return errPeer}
	return nil
}
