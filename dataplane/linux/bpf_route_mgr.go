// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intdataplane

import (
	"net"
	"sync"
	"time"

	"github.com/projectcalico/felix/ifacemonitor"

	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/proto"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type bpfRouteManager struct {
	myNodename string

	ipPools      map[string]bpfIPAMPool
	ipPoolsDirty bool

	// Tracking for local host IPs.
	localHostIPs      map[string]set.Set
	localHostRoutes   map[routes.Key]routes.Value
	localHostIPsDirty bool

	// Tracking for remote host IPs.
	remoteHostIPs      map[string]string
	remoteHostRoutes   map[routes.Key]routes.Value
	remoteHostIPsDirty bool

	// Tracking for local workload IPs.
	localIfaceToIfIndex map[string]int
	localWorkloads      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	localWorkloadRoutes map[routes.Key]routes.Value
	localWorkloadsDirty bool

	// desiredRoutes contains the complete, desired state of the dataplane map.
	desiredRoutes map[routes.Key]routes.Value
	routeMap      bpf.Map

	dirtyRoutes     set.Set
	resyncScheduled bool

	cbLck           sync.RWMutex
	hostIPsUpdateCB func([]net.IP)
	routesUpdateCB  func(routes.Key, routes.Value)
	routesDeleteCB  func(routes.Key)
}

func newBPFRouteManager(myNodename string, mc *bpf.MapContext) *bpfRouteManager {
	return &bpfRouteManager{
		myNodename:          myNodename,
		ipPools:             map[string]bpfIPAMPool{},
		desiredRoutes:       map[routes.Key]routes.Value{},
		localIfaceToIfIndex: map[string]int{},
		localHostIPs:        map[string]set.Set{},
		remoteHostIPs:       map[string]string{},
		localWorkloads:      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		routeMap:            routes.Map(mc),
		dirtyRoutes:         set.New(),
		resyncScheduled:     true,
	}
}

func (m *bpfRouteManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// Updates to local IPs.  We use these to include host IPs in the map.
	case *ifaceUpdate:
		m.onIfaceUpdate(msg)
	case *ifaceAddrsUpdate:
		m.onIfaceAddrsUpdate(msg)

	case *proto.IPAMPoolUpdate:
		m.onIPAMPoolUpdate(msg)
	case *proto.IPAMPoolRemove:
		m.onIPAMPoolRemove(msg)

	// Updates for remote IPAM blocks and remote workloads with borrowed IPs.  These tell us
	// which host owns each IP block/IP.
	case *proto.RouteUpdate:
		m.onRouteUpdate(msg)
	case *proto.RouteRemove:
		m.onRouteRemove(msg)

	// Updates for local workload endpoints only.  We use these to create local workload routes.
	case *proto.WorkloadEndpointUpdate:
		m.onWorkloadEndpointUpdate(msg)
	case *proto.WorkloadEndpointRemove:
		m.onWorkloadEndpointRemove(msg)

	// Updates for all Calico hosts giving us the host's node IP.
	case *proto.HostMetadataUpdate:
		m.onHostMetadataUpdate(msg)
	case *proto.HostMetadataRemove:
		m.onHostMetadataRemove(msg)
	}
}

func (m *bpfRouteManager) CompleteDeferredWork() error {
	var numAdds, numDels uint
	startTime := time.Now()

	err := m.routeMap.EnsureExists()
	if err != nil {
		log.WithError(err).Panic("Failed to create route map")
	}

	if m.ipPoolsDirty {
		// TODO handle IPAM routes
		// TODO insert routes for the IPAM pools themselves.
		m.localWorkloadsDirty = true
		m.localHostIPsDirty = true
		m.remoteHostIPsDirty = true
		m.ipPoolsDirty = false
	}

	if m.localWorkloadsDirty {
		m.recalculateWorkloads()
		m.localWorkloadsDirty = false
	}

	if m.localHostIPsDirty {
		m.recalculateLocalHostIPs()
		m.localHostIPsDirty = false
	}

	if m.remoteHostIPsDirty {
		m.recalculateRemoteHostIPs()
		m.remoteHostIPsDirty = false
	}

	debug := log.GetLevel() >= log.DebugLevel
	if m.resyncScheduled {
		log.Info("Doing full resync of BPF IP sets map")

		// Mark all desired routes as dirty.
		m.dirtyRoutes.Clear()
		for k := range m.desiredRoutes {
			m.dirtyRoutes.Add(k)
		}

		// Scan the dataplane, discarding any routes that are already correct.
		err := m.routeMap.Iter(func(k, v []byte) {
			var key routes.Key
			var value routes.Value
			copy(key[:], k)
			copy(value[:], v)

			if desired, ok := m.desiredRoutes[key]; ok && desired == value {
				// Route is already correct.
				if debug {
					log.WithField("k", key).Debug("Route already correct.")
				}
				m.dirtyRoutes.Discard(key)
			} else if ok {
				// Route is present but incorrect (and we'll have marked it dirty above).
				if debug {
					log.WithField("k", key).Debug("Route present but incorrect.")
				}
			} else {
				// Route is not in the desired map so it needs to be deleted.
				if debug {
					log.WithField("k", key).Debug("Unexpected route in dataplane.")
				}
				m.dirtyRoutes.Add(key)
			}
		})
		if err != nil {
			log.WithError(err).Panic("Failed to scan BPF map.")
		}
		m.resyncScheduled = false
	}

	m.dirtyRoutes.Iter(func(item interface{}) error {
		key := item.(routes.Key)
		value, present := m.desiredRoutes[key]
		if !present {
			// Delete the key.
			numDels++
			err := m.routeMap.Delete(key[:])
			if err != nil {
				log.WithFields(log.Fields{"key": key}).Error("Failed to delete from BPF map")
				m.resyncScheduled = true
				return nil
			}
			return set.RemoveItem
		}

		// If we get here, we're doing an update.
		numAdds++
		err := m.routeMap.Update(key[:], value[:])
		if err != nil {
			log.WithFields(log.Fields{"key": key}).Error("Failed to update BPF map")
			m.resyncScheduled = true
			return nil
		}
		return set.RemoveItem
	})

	duration := time.Since(startTime)
	if numDels > 0 || numAdds > 0 {
		log.WithFields(log.Fields{
			"timeTaken": duration,
			"numAdds":   numAdds,
			"numDels":   numDels,
		}).Info("Completed updates to BPF routes.")
	}

	return nil
}

func (m *bpfRouteManager) onIfaceUpdate(msg *ifaceUpdate) {
	// We're interested in the mapping from interface name to interface index.
	if msg.State == ifacemonitor.StateUp {
		oldIdx, ok := m.localIfaceToIfIndex[msg.Name]
		if !ok || oldIdx != msg.Index {
			m.localIfaceToIfIndex[msg.Name] = msg.Index
			m.localWorkloadsDirty = true
		}
	} else {
		_, ok := m.localIfaceToIfIndex[msg.Name]
		if ok {
			delete(m.localIfaceToIfIndex, msg.Name)
			m.localWorkloadsDirty = true
		}
	}
}

func (m *bpfRouteManager) onIfaceAddrsUpdate(update *ifaceAddrsUpdate) {
	if update.Addrs == nil {
		delete(m.localHostIPs, update.Name)
	} else {
		ipsCopy := update.Addrs.Copy()
		m.localHostIPs[update.Name] = ipsCopy
	}
	m.localHostIPsDirty = true
}

func (m *bpfRouteManager) recalculateLocalHostIPs() {
	// Host IP updates are assumed to be rare and small so we recalculate the whole lot on any change.
	// onIPSetUpdate will do the delta calculation so we won't churn the data in any case.
	oldRoutes := m.localHostRoutes
	newRoutes := map[routes.Key]routes.Value{}

	netIPs := []net.IP{}

	for iface, ips := range m.localHostIPs {
		logCxt := log.WithField("iface", iface)
		logCxt.Debug("Adding IPs from interface")
		ips.Iter(func(item interface{}) error {
			ipStr := item.(string)
			cidr := ip.MustParseCIDROrIP(ipStr)
			v4CIDR, ok := cidr.(ip.V4CIDR)
			if !ok {
				// FIXME IPv6
				return nil
			}

			netIP := cidr.Addr().AsNetIP()

			if !netIP.IsGlobalUnicast() {
				logCxt.WithField("addr", cidr).Debug("Address is not global unicast, ignore")
				return nil
			}
			key := routes.NewKey(v4CIDR)
			value := routes.NewValue(routes.FlagsLocalHost | m.flagsForCIDR(v4CIDR))
			newRoutes[key] = value

			netIPs = append(netIPs, netIP)

			return nil
		})
	}

	m.applyRoutesDelta(oldRoutes, newRoutes)
	m.localHostRoutes = newRoutes

	m.onHostIPsChange(netIPs)

}

type bpfIPAMPool struct {
	CIDR       ip.CIDR
	Masquerade bool
}

func (m *bpfRouteManager) onIPAMPoolUpdate(msg *proto.IPAMPoolUpdate) {
	// TODO IPAM pools and IPAM blocks can share the same CIDR
	pool := msg.GetPool()
	cidr, err := ip.ParseCIDROrIP(pool.Cidr)
	if err != nil {
		log.WithError(err).Panic("Failed to parse IPAM pool CIDR")
	}
	newPool := bpfIPAMPool{CIDR: cidr, Masquerade: pool.Masquerade}
	oldPool, ok := m.ipPools[msg.Id]
	if !ok || oldPool != newPool {
		m.ipPools[msg.Id] = newPool
		m.ipPoolsDirty = true
	}
}

func (m *bpfRouteManager) onIPAMPoolRemove(msg *proto.IPAMPoolRemove) {
	_, ok := m.ipPools[msg.Id]
	if ok {
		delete(m.ipPools, msg.Id)
		m.ipPoolsDirty = true
	}
}

func (m *bpfRouteManager) getContainingIPPool(cidr ip.V4CIDR) *bpfIPAMPool {
	for _, p := range m.ipPools {
		if poolCIDR, ok := p.CIDR.(ip.V4CIDR); ok && poolCIDR.ContainsV4(cidr.Addr().(ip.V4Addr)) {
			return &p
		}
	}
	return nil
}

func (m *bpfRouteManager) onHostIPsChange(newIPs []net.IP) {
	m.cbLck.RLock()
	defer m.cbLck.RUnlock()
	if m.hostIPsUpdateCB != nil {
		m.hostIPsUpdateCB(newIPs)
	}
	log.Debugf("localHostIPs update %+v", newIPs)
}

func (m *bpfRouteManager) recalculateWorkloads() {
	oldRoutes := m.localWorkloadRoutes
	newRoutes := map[routes.Key]routes.Value{}

	for wepID, wep := range m.localWorkloads {
		log.WithField("wepID", wepID).Debug("Adding IPs from local workload")
		for _, ipStr := range wep.Ipv4Nets { // FIXME IPv6
			cidr := ip.MustParseCIDROrIP(ipStr)
			v4CIDR, ok := cidr.(ip.V4CIDR)
			if !ok {
				// FIXME IPv6
				continue
			}
			key := routes.NewKey(v4CIDR)
			flags := routes.FlagsLocalWorkload
			flags |= m.flagsForCIDR(v4CIDR)
			value := routes.NewValueWithIfIndex(flags, m.localIfaceToIfIndex[wep.Name])
			newRoutes[key] = value
		}
	}

	m.applyRoutesDelta(oldRoutes, newRoutes)
	m.localWorkloadRoutes = newRoutes
}

func (m *bpfRouteManager) flagsForCIDR(v4CIDR ip.V4CIDR) (flags routes.Flags) {
	pool := m.getContainingIPPool(v4CIDR)
	if pool != nil {
		flags |= routes.FlagInIPAMPool
		if pool.Masquerade {
			flags |= routes.FlagNATOutgoing
		}
	}
	return
}

func (m *bpfRouteManager) recalculateRemoteHostIPs() {
	oldRoutes := m.remoteHostRoutes
	newRoutes := map[routes.Key]routes.Value{}

	for nodename, ipStr := range m.remoteHostIPs {
		log.WithField("nodename", nodename).Debug("Adding IP from remote host")
		cidr := ip.MustParseCIDROrIP(ipStr)
		v4CIDR, ok := cidr.(ip.V4CIDR)
		if !ok {
			// FIXME IPv6
			continue
		}
		key := routes.NewKey(v4CIDR)
		value := routes.NewValue(routes.FlagsRemoteHost | m.flagsForCIDR(v4CIDR))
		newRoutes[key] = value
	}

	m.applyRoutesDelta(oldRoutes, newRoutes)
	m.remoteHostRoutes = newRoutes
}

func (m *bpfRouteManager) applyRoutesDelta(oldRoutes map[routes.Key]routes.Value, newRoutes map[routes.Key]routes.Value) {
	// FIXME assumes that workload and host routes will never overlap.
	for k, v := range oldRoutes {
		if newV, ok := newRoutes[k]; ok && newV == v {
			continue
		}
		delete(m.desiredRoutes, k)
		m.dirtyRoutes.Add(k)
		m.onRouteDeleteCB(k)
	}
	for k, v := range newRoutes {
		if oldV, ok := oldRoutes[k]; ok && oldV == v {
			continue
		}
		m.desiredRoutes[k] = v
		m.dirtyRoutes.Add(k)
		m.onRouteUpdateCB(k, v)
	}
}

func (m *bpfRouteManager) onRouteUpdate(update *proto.RouteUpdate) {
	if update.Type != proto.RouteType_WORKLOADS_NODE {
		log.WithField("type", update.Type).Debug("Route type we're not interested in, ignoring")
		return
	}

	if update.Node == m.myNodename {
		// We learn about local endpoints from a different message.
		log.Debug("Workload is on this host, ignoring route")
		return
	}

	cidr := ip.MustParseCIDROrIP(update.Dst)
	v4CIDR, ok := cidr.(ip.V4CIDR)
	if !ok {
		// FIXME IPv6
		return
	}
	key := routes.NewKey(v4CIDR)

	nextHop := ip.MustParseCIDROrIP(update.Gw)
	v4NextHop, ok := nextHop.(ip.V4CIDR)
	if !ok {
		// FIXME IPv6
		return
	}

	// TODO: if we used flagsForCIDR() here, we'd have an order-dependency with IP pools.
	// That would require us to recalculate these routes when the IP pools change.  Since we're not using
	// the nat-outgoing bit for remote routes and we know that remote routes should be in an IP pool, just set
	// FlagInIPAMPool for all of these routes.  If we do get that wrong and we've got an orphaned IP block, it
	// won't do any harm since we know it's still on a Calico host, which is what we really care about for
	// routing purposes.
	flags := routes.FlagsRemoteWorkload | routes.FlagInIPAMPool
	value := routes.NewValueWithNextHop(flags, v4NextHop.Addr().(ip.V4Addr))

	m.desiredRoutes[key] = value
	m.dirtyRoutes.Add(key)
	m.onRouteUpdateCB(key, value)
}

func (m *bpfRouteManager) onRouteRemove(update *proto.RouteRemove) {
	if update.Type != proto.RouteType_WORKLOADS_NODE {
		log.WithField("type", update.Type).Debug("Route type we're not interested in, ignoring")
		return
	}

	cidr := ip.MustParseCIDROrIP(update.Dst)
	v4CIDR, ok := cidr.(ip.V4CIDR)
	if !ok {
		// FIXME IPv6
		return
	}
	key := routes.NewKey(v4CIDR)
	if _, ok := m.desiredRoutes[key]; ok {
		delete(m.desiredRoutes, key)
		m.dirtyRoutes.Add(key)
		m.onRouteDeleteCB(key)
	}
}

func (m *bpfRouteManager) onWorkloadEndpointUpdate(update *proto.WorkloadEndpointUpdate) {
	m.localWorkloads[*update.Id] = update.Endpoint
	m.localWorkloadsDirty = true
}

func (m *bpfRouteManager) onWorkloadEndpointRemove(update *proto.WorkloadEndpointRemove) {
	delete(m.localWorkloads, *update.Id)
	m.localWorkloadsDirty = true
}

func (m *bpfRouteManager) onHostMetadataUpdate(update *proto.HostMetadataUpdate) {
	if update.Hostname == m.myNodename {
		log.Debug("Ignoring host metadata update for this host")
		return
	}
	if update.Ipv4Addr == m.remoteHostIPs[update.Hostname] {
		return
	}
	m.remoteHostIPs[update.Hostname] = update.Ipv4Addr
	m.remoteHostIPsDirty = true
}

func (m *bpfRouteManager) onHostMetadataRemove(remove *proto.HostMetadataRemove) {
	if remove.Hostname == m.myNodename {
		log.Debug("Ignoring host metadata remove for this host")
		return
	}
	delete(m.remoteHostIPs, remove.Hostname)
	m.remoteHostIPsDirty = true
}

func (m *bpfRouteManager) setHostIPUpdatesCallBack(cb func([]net.IP)) {
	m.cbLck.Lock()
	defer m.cbLck.Unlock()

	m.hostIPsUpdateCB = cb
}

func (m *bpfRouteManager) setRoutesCallBacks(update func(routes.Key, routes.Value), del func(routes.Key)) {
	m.cbLck.Lock()
	defer m.cbLck.Unlock()

	m.routesUpdateCB = update
	m.routesDeleteCB = del
}

func (m *bpfRouteManager) onRouteUpdateCB(k routes.Key, v routes.Value) {
	m.cbLck.RLock()
	defer m.cbLck.RUnlock()
	if m.routesUpdateCB != nil {
		m.routesUpdateCB(k, v)
	}
}

func (m *bpfRouteManager) onRouteDeleteCB(k routes.Key) {
	m.cbLck.RLock()
	defer m.cbLck.RUnlock()
	if m.routesDeleteCB != nil {
		m.routesDeleteCB(k)
	}
}
