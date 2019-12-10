// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"time"

	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/proto"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type bpfRouteManager struct {
	myNodename string

	// Tracking for local host IPs.
	localHostIPs      map[string]set.Set
	localHostRoutes   map[routes.Key]routes.Value
	localHostIPsDirty bool

	// Tracking for remote host IPs.
	remoteHostIPs      map[string]string
	remoteHostRoutes   map[routes.Key]routes.Value
	remoteHostIPsDirty bool

	// Tracking for local workload IPs.
	localWorkloads        map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	localWorkloadRoutes   map[routes.Key]routes.Value
	localWorkloadIPsDirty bool

	// desiredRoutes contains the complete, desired state of the dataplane map.
	desiredRoutes map[routes.Key]routes.Value
	routeMap      bpf.Map

	dirtyRoutes     set.Set
	resyncScheduled bool
}

func newBPFRouteManager(myNodename string, mc *bpf.MapContext) *bpfRouteManager {
	return &bpfRouteManager{
		myNodename:      myNodename,
		desiredRoutes:   map[routes.Key]routes.Value{},
		localHostIPs:    map[string]set.Set{},
		remoteHostIPs:   map[string]string{},
		localWorkloads:  map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		routeMap:        routes.Map(mc),
		dirtyRoutes:     set.New(),
		resyncScheduled: true,
	}
}

func (m *bpfRouteManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// Updates to local IPs.  We use these to include host IPs in the map.
	case *ifaceAddrsUpdate:
		m.onIfaceAddrsUpdate(msg)

	case *proto.RouteUpdate:
		m.onRouteUpdate(msg)
	case *proto.RouteRemove:
		m.onRouteRemove(msg)

	case *proto.WorkloadEndpointUpdate:
		m.onWorkloadEndpointUpdate(msg)
	case *proto.WorkloadEndpointRemove:
		m.onWorkloadEndpointRemove(msg)

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

	if m.localWorkloadIPsDirty {
		m.recalculateWorkloadIPs()
		m.localWorkloadIPsDirty = false
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
			if !cidr.Addr().AsNetIP().IsGlobalUnicast() {
				logCxt.WithField("addr", cidr).Debug("Address is not global unicast, ignore")
				return nil
			}
			key := routes.NewKey(v4CIDR)
			value := routes.NewValue(routes.TypeLocalHost)
			newRoutes[key] = value
			return nil
		})
	}

	m.applyRoutesDelta(oldRoutes, newRoutes)
	m.localHostRoutes = newRoutes
}

func (m *bpfRouteManager) recalculateWorkloadIPs() {
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
			value := routes.NewValue(routes.TypeLocalWorkload)
			newRoutes[key] = value
		}
	}

	m.applyRoutesDelta(oldRoutes, newRoutes)
	m.localWorkloadRoutes = newRoutes
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
		value := routes.NewValue(routes.TypeRemoteHost)
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
	}
	for k, v := range newRoutes {
		if oldV, ok := oldRoutes[k]; ok && oldV == v {
			continue
		}
		m.desiredRoutes[k] = v
		m.dirtyRoutes.Add(k)
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
	value := routes.NewValueWithNextHop(routes.TypeRemoteWorkload, v4NextHop.Addr().(ip.V4Addr))

	m.desiredRoutes[key] = value
	m.dirtyRoutes.Add(key)
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
	}
}

func (m *bpfRouteManager) onWorkloadEndpointUpdate(update *proto.WorkloadEndpointUpdate) {
	m.localWorkloads[*update.Id] = update.Endpoint
	m.localWorkloadIPsDirty = true
}

func (m *bpfRouteManager) onWorkloadEndpointRemove(update *proto.WorkloadEndpointRemove) {
	delete(m.localWorkloads, *update.Id)
	m.localWorkloadIPsDirty = true
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
