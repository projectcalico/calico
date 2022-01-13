// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	bpfarp "github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type bpfRouteManager struct {
	myNodename      string
	resyncScheduled bool
	routeMap        bpf.Map
	hostIP          net.IP

	// These fields contain our cache of the input data, indexed for efficient updates
	// and lookups:
	//
	// - routes from the calculation graph
	// - local interface names, IPs, and, indexes
	// - local workloads and their IPs.
	//
	// From these fields we're able to calculate the BPF routes that should be in the dataplane.

	// cidrToRoute maps from CIDR to the calculation graph's routes.  These cover IP pools, local
	// and remote workloads and hosts.  For local routes, we're missing some information that we
	// need from the dataplane.
	cidrToRoute map[ip.V4CIDR]proto.RouteUpdate
	// cidrToLocalIfaces maps from (/32) CIDR to the set of interfaces that have that CIDR
	cidrToLocalIfaces map[ip.V4CIDR]set.Set[string]
	localIfaceToCIDRs map[string]set.Set[ip.V4CIDR]
	// cidrToWEPIDs maps from (/32) CIDR to the set of local proto.WorkloadEndpointIDs that have that CIDR.
	cidrToWEPIDs map[ip.V4CIDR]set.Set[proto.WorkloadEndpointID]
	// wepIDToWorklaod contains all the local workloads.
	wepIDToWorklaod map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	// ifaceNameToIdx maps local interface name to interface ID.
	ifaceNameToIdx map[string]int
	// ifaceNameToWEPIDs maps local interface name to the set of local proto.WorkloadEndpointIDs that have that name.
	// (Usually a single WEP).
	ifaceNameToWEPIDs map[string]set.Set[proto.WorkloadEndpointID]
	// externalNodeCIDRs is a set of CIDRs that should be treated as external nodes (and hence we should allow
	// IPIP and VXLAN to/from them).
	externalNodeCIDRs set.Set[ip.V4CIDR]
	// Set of CIDRs for which we need to update the BPF routes.
	dirtyCIDRs set.Set[ip.V4CIDR]

	// These fields track the desired state of the dataplane and the set of inconsistencies
	// between that and the real state of the dataplane.

	// desiredRoutes contains the complete, desired state of the dataplane map.
	desiredRoutes map[routes.Key]routes.Value
	dirtyRoutes   set.Set[routes.Key]

	// Callbacks used to tell kube-proxy about the relevant routes.
	cbLck           sync.RWMutex
	hostIPsUpdateCB func([]net.IP)
	routesUpdateCB  func(routes.Key, routes.Value)
	routesDeleteCB  func(routes.Key)

	opReporter logutils.OpRecorder

	wgEnabled bool

	arpMap bpf.Map
}

func newBPFRouteManager(config *Config, mc *bpf.MapContext,
	opReporter logutils.OpRecorder) *bpfRouteManager {

	// Record the external node CIDRs and pre-mark them as dirty.  These can only change with a config update,
	// which would restart Felix.
	extCIDRs := set.New[ip.V4CIDR]()
	dirtyCIDRs := set.New[ip.V4CIDR]()
	for _, cidrStr := range config.ExternalNodesCidrs {
		if strings.Contains(cidrStr, ":") {
			log.WithField("cidr", cidrStr).Debug("Ignoring IPv6 external CIDR")
			continue
		}
		cidr, err := ip.ParseCIDROrIP(cidrStr)
		if err != nil {
			log.WithError(err).WithField("cidr", cidr).Error(
				"Failed to parse external node CIDR (which should have been validated already).")
		}
		extCIDRs.Add(cidr.(ip.V4CIDR))
		dirtyCIDRs.Add(cidr.(ip.V4CIDR))
	}

	return &bpfRouteManager{
		myNodename:        config.Hostname,
		cidrToRoute:       map[ip.V4CIDR]proto.RouteUpdate{},
		cidrToLocalIfaces: map[ip.V4CIDR]set.Set[string]{},
		localIfaceToCIDRs: map[string]set.Set[ip.V4CIDR]{},
		cidrToWEPIDs:      map[ip.V4CIDR]set.Set[proto.WorkloadEndpointID]{},
		wepIDToWorklaod:   map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		ifaceNameToIdx:    map[string]int{},
		ifaceNameToWEPIDs: map[string]set.Set[proto.WorkloadEndpointID]{},
		externalNodeCIDRs: extCIDRs,
		dirtyCIDRs:        dirtyCIDRs,

		desiredRoutes: map[routes.Key]routes.Value{},
		routeMap:      mc.RouteMap,

		dirtyRoutes:     set.New[routes.Key](),
		resyncScheduled: true,

		opReporter: opReporter,

		wgEnabled: config.Wireguard.Enabled,
		arpMap:    mc.ArpMap, // XXX we should create a map for local pods only
	}
}

func (m *bpfRouteManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// Updates to local IPs.  We use these to include host IPs in the map.
	case *ifaceUpdate:
		m.onIfaceUpdate(msg)
	case *ifaceAddrsUpdate:
		m.onIfaceAddrsUpdate(msg)

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
	case *proto.HostMetadataUpdate:
		if msg.Hostname == m.myNodename {
			log.WithField("HostMetadataUpdate", msg).Info("Host IP changed")
			ip := net.ParseIP(msg.Ipv4Addr)
			if ip != nil {
				m.hostIP = ip
			}
		}
	}
}

func (m *bpfRouteManager) CompleteDeferredWork() error {
	startTime := time.Now()

	// Step 1: calculate any updates to the _desired_ state of the BPF map.
	m.recalculateRoutesForDirtyCIDRs()

	// Step 2: if required, load the state of the map from the dataplane so we can do efficient deltas.
	if m.resyncScheduled {
		m.opReporter.RecordOperation("resync-bpf-routes")
		m.resyncWithDataplane()
		m.resyncScheduled = false
	}

	// Step 3: apply dataplane updates.
	numDels, numAdds := m.applyUpdates()

	duration := time.Since(startTime)
	if numDels > 0 || numAdds > 0 {
		m.opReporter.RecordOperation("update-bpf-routes")
		log.WithFields(log.Fields{
			"timeTaken": duration,
			"numAdds":   numAdds,
			"numDels":   numDels,
		}).Debug("Completed updates to BPF routes.")
	}

	return nil
}

func (m *bpfRouteManager) recalculateRoutesForDirtyCIDRs() {
	m.dirtyCIDRs.Iter(func(cidr ip.V4CIDR) error {
		dataplaneKey := routes.NewKey(cidr)
		newValue := m.calculateRoute(cidr)

		oldValue, exists := m.desiredRoutes[dataplaneKey]
		if newValue != nil {
			if exists && oldValue == *newValue {
				// Value is already correct.  We're done.
				return set.RemoveItem
			}
			m.desiredRoutes[dataplaneKey] = *newValue
			m.onRouteUpdateCB(dataplaneKey, *newValue)
		} else {
			if !exists {
				// Value is already correct.  We're done.
				return set.RemoveItem
			}
			delete(m.desiredRoutes, dataplaneKey)
			m.onRouteDeleteCB(dataplaneKey)
		}
		m.dirtyRoutes.Add(dataplaneKey)
		return set.RemoveItem
	})
}

func (m *bpfRouteManager) resolveARP(ifname string, ifidx int, ip net.IP) {
	if m.hostIP == nil {
		log.WithField("iface", ifname).Warn("No host IP")
		return
	}

	iface, err := net.InterfaceByIndex(ifidx)
	if err != nil {
		log.WithError(err).WithField("iface", ifname).Warn("Failed to get iface.")
		return
	}

	a, err := arp.Dial(iface)
	if err != nil {
		log.WithError(err).WithField("iface", ifname).Warn("Failed to create arp client.")
		return
	}
	defer a.Close()

	hw, err := a.Resolve(ip)
	if err != nil {
		log.WithError(err).WithField("iface", ifname).Warnf("Failed to resolve arp for ip %s.", ip)
		return
	}

	log.WithField("iface", ifname).Infof("%s -> %s", ip, hw)

	_ = m.arpMap.Update(bpfarp.NewKey(ip, uint32(ifidx)).AsBytes(), bpfarp.NewValue(iface.HardwareAddr, hw).AsBytes())
}

func (m *bpfRouteManager) calculateRoute(cidr ip.V4CIDR) *routes.Value {
	// First check for a matching local host IP.  The calculation graph doesn't know about all of these
	// so we might not get a CG route.
	var flags routes.Flags

	_, ok := m.cidrToLocalIfaces[cidr]
	if ok {
		flags |= routes.FlagsLocalHost
	}

	// Similarly, handle external node CIDRs, which are derived from config, not the calc graph.
	// For now, we don't examine all CIDRs to see if they might be inside an external node CIDR since
	// other routes are either
	// - Derived from IP pools and workloads, in which case, overlap would be a misconfiguration and
	//   avoiding treating workloads as nodes is safer.
	// - Derived from hosts, in which case we'll set the host flag anyway from its CG route.
	if m.externalNodeCIDRs.Contains(cidr) {
		log.WithField("cidr", cidr).Debug("CIDR is for external nodes.")
		flags |= routes.FlagHost
	}

	cgRoute, cgRouteExists := m.cidrToRoute[cidr]
	if cgRouteExists {
		// Collect flags that are shared by all route types.
		if cgRoute.SameSubnet {
			flags |= routes.FlagSameSubnet
		}
		if cgRoute.IpPoolType != proto.IPPoolType_NONE {
			flags |= routes.FlagInIPAMPool
		}
		if cgRoute.NatOutgoing {
			flags |= routes.FlagNATOutgoing
		}
	}

	var route *routes.Value

	switch cgRoute.Type {
	case proto.RouteType_LOCAL_WORKLOAD:
		if !cgRoute.LocalWorkload {
			// Just the local IPAM block, not an actual workload.
			return nil
		}
		if wepIDs, ok := m.cidrToWEPIDs[cidr]; ok {
			bestWepScore := -1
			var bestWepID proto.WorkloadEndpointID
			if wepIDs.Len() > 1 {
				log.WithField("cidr", cidr).Warn(
					"Multiple local workloads with same IP but BPF dataplane only supports single route. " +
						"Will choose one route.")
			}
			wepIDs.Iter(func(wepID proto.WorkloadEndpointID) error {
				// Route is a local workload look up its name and interface details.
				wepScore := 0
				wep := m.wepIDToWorklaod[wepID]
				ifaceName := wep.Name
				ifaceIdx, ok := m.ifaceNameToIdx[ifaceName]
				if ok {
					wepScore++
				}
				if wepScore > bestWepScore || wepScore == bestWepScore && wepID.String() > bestWepID.String() {
					flags |= routes.FlagsLocalWorkload
					routeVal := routes.NewValueWithIfIndex(flags, ifaceIdx)
					route = &routeVal
					bestWepID = wepID
					bestWepScore = wepScore
					go m.resolveARP(ifaceName, ifaceIdx, cidr.Addr().AsNetIP())
				}
				return nil
			})
		}
	case proto.RouteType_REMOTE_WORKLOAD:
		flags |= routes.FlagsRemoteWorkload
		if m.wgEnabled {
			flags |= routes.FlagTunneled
		}
		switch cgRoute.IpPoolType {
		case proto.IPPoolType_VXLAN, proto.IPPoolType_IPIP:
			flags |= routes.FlagTunneled
		}
		if cgRoute.DstNodeIp == "" {
			log.WithField("node", cgRoute.DstNodeName).Debug(
				"Can't program route for remote workload, don't know its node's IP")
			return nil
		}
		nodeIP := net.ParseIP(cgRoute.DstNodeIp)
		routeVal := routes.NewValueWithNextHop(flags, ip.FromNetIP(nodeIP).(ip.V4Addr))
		route = &routeVal
	case proto.RouteType_REMOTE_HOST:
		flags |= routes.FlagsRemoteHost
		if cgRoute.DstNodeIp == "" {
			log.WithField("node", cgRoute.DstNodeName).Panic(
				"Remote host route is missing node's IP but its CIDR should equal its IP.")
			return nil
		}
		nodeIP := net.ParseIP(cgRoute.DstNodeIp)
		routeVal := routes.NewValueWithNextHop(flags, ip.FromNetIP(nodeIP).(ip.V4Addr))
		route = &routeVal
	case proto.RouteType_LOCAL_HOST:
		// It may be a localhost IP that is not assigned to a device like an
		// k8s ExternalIP. Route resolver knew that it was assigned to our
		// hostname.
		flags |= routes.FlagsLocalHost
		fallthrough
	default: // proto.RouteType_CIDR_INFO / LOCAL_HOST or no route at all
		if flags != 0 {
			// We have something to say about this route.
			routeVal := routes.NewValue(flags)
			route = &routeVal
		}
	}

	return route
}

func (m *bpfRouteManager) applyUpdates() (numDels uint, numAdds uint) {

	debug := log.GetLevel() >= log.DebugLevel

	m.dirtyRoutes.Iter(func(key routes.Key) error {
		value, present := m.desiredRoutes[key]
		if !present {
			// Delete the key.
			numDels++
			if debug {
				log.WithField("k", key).Debug("Deleting route from dataplane")
			}
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
		if debug {
			log.WithField("k", key).WithField("v", value).Debug("Adding/Updating route in dataplane")
		}
		err := m.routeMap.Update(key[:], value[:])
		if err != nil {
			log.WithFields(log.Fields{"key": key}).Error("Failed to update BPF map")
			m.resyncScheduled = true
			return nil
		}
		return set.RemoveItem
	})

	return
}

// resyncWithDataplane reads all routes from the dataplane and compares them against m.desiredRoutes.
//
// After this operation, m.dirtyRoutes only contains routes that are out-of-sync with the dataplane.
// Already-correct routes are removed from the dirty set.  Missing, incorrect, and, superfluous routes are added.
func (m *bpfRouteManager) resyncWithDataplane() {
	debug := log.GetLevel() >= log.DebugLevel
	log.Info("Doing full resync of BPF routes map")

	// Mark all desired routes as dirty.
	m.dirtyRoutes.Clear()
	for k := range m.desiredRoutes {
		m.dirtyRoutes.Add(k)
	}

	// Scan the dataplane, discarding any routes that are already correct.
	err := m.routeMap.Iter(func(k, v []byte) bpf.IteratorAction {
		var key routes.Key
		var value routes.Value
		copy(key[:], k)
		copy(value[:], v)

		if desired, ok := m.desiredRoutes[key]; ok && desired == value {
			// Route is already correct.
			if debug {
				log.WithField("k", key).WithField("v", value).Debug("Route already correct.")
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
		return bpf.IterNone
	})
	if err != nil {
		log.WithError(err).Panic("Failed to scan BPF map.")
	}
}

func (m *bpfRouteManager) onIfaceUpdate(msg *ifaceUpdate) {
	// We're interested in the mapping from interface name to interface index.
	if msg.State == ifacemonitor.StateUp {
		oldIdx, ok := m.ifaceNameToIdx[msg.Name]
		if !ok || oldIdx != msg.Index {
			m.ifaceNameToIdx[msg.Name] = msg.Index
			m.onIfaceIdxChanged(msg.Name)
		}
	} else {
		_, ok := m.ifaceNameToIdx[msg.Name]
		if ok {
			delete(m.ifaceNameToIdx, msg.Name)
			m.onIfaceIdxChanged(msg.Name)
		}
	}
}

func (m *bpfRouteManager) onIfaceIdxChanged(name string) {
	wepIDs := m.ifaceNameToWEPIDs[name]
	if wepIDs == nil {
		return
	}
	wepIDs.Iter(func(wepID proto.WorkloadEndpointID) error {
		wep := m.wepIDToWorklaod[wepID]
		cidrs := getV4WorkloadCIDRs(wep)
		m.markCIDRsDirty(cidrs...)
		return nil
	})
}

func (m *bpfRouteManager) onIfaceAddrsUpdate(update *ifaceAddrsUpdate) {
	changed := false

	var newCIDRs set.Set[ip.V4CIDR]
	if update.Addrs == nil {
		newCIDRs = set.Empty[ip.V4CIDR]()
	} else {
		newCIDRs = set.New[ip.V4CIDR]()
		update.Addrs.Iter(func(cidrStr string) error {
			cidr := ip.MustParseCIDROrIP(cidrStr)
			if v4CIDR, ok := cidr.(ip.V4CIDR); ok && cidr.Addr().AsNetIP().IsGlobalUnicast() {
				newCIDRs.Add(v4CIDR)
			}
			return nil
		})
	}

	cidrs := m.localIfaceToCIDRs[update.Name]
	if cidrs != nil {
		cidrs.Iter(func(cidr ip.V4CIDR) error {
			if newCIDRs.Contains(cidr) {
				// No change for this address.
				newCIDRs.Discard(cidr)
				return nil
			}
			// Address deleted.
			changed = true
			m.cidrToLocalIfaces[cidr].Discard(update.Name)
			if m.cidrToLocalIfaces[cidr].Len() == 0 {
				delete(m.cidrToLocalIfaces, cidr)
			}
			m.markCIDRsDirty(cidr)
			return set.RemoveItem
		})
	}

	newCIDRs.Iter(func(cidr ip.V4CIDR) error {
		changed = true
		ifaceNames := m.cidrToLocalIfaces[cidr]
		if ifaceNames == nil {
			ifaceNames = set.New[string]()
			m.cidrToLocalIfaces[cidr] = ifaceNames
		}
		ifaceNames.Add(update.Name)
		if cidrs == nil {
			cidrs = set.New[ip.V4CIDR]()
			m.localIfaceToCIDRs[update.Name] = cidrs
		}
		m.markCIDRsDirty(cidr)
		cidrs.Add(cidr)
		return set.RemoveItem
	})

	if changed {
		var newIPs []net.IP
		for cidr := range m.cidrToLocalIfaces {
			newIPs = append(newIPs, cidr.Addr().AsNetIP())
		}
		m.onHostIPsChange(newIPs)
	}
}

func (m *bpfRouteManager) onHostIPsChange(newIPs []net.IP) {
	m.cbLck.RLock()
	defer m.cbLck.RUnlock()
	if m.hostIPsUpdateCB != nil {
		m.hostIPsUpdateCB(newIPs)
	}
	log.Debugf("localHostIPs update %+v", newIPs)
}

func (m *bpfRouteManager) onRouteUpdate(update *proto.RouteUpdate) {
	cidr := ip.MustParseCIDROrIP(update.Dst)
	v4CIDR, ok := cidr.(ip.V4CIDR)
	if !ok {
		// FIXME IPv6
		return
	}

	// For now don't handle the tunnel addresses, which were previously not being included in the route updates.
	if update.Type == proto.RouteType_REMOTE_TUNNEL || update.Type == proto.RouteType_LOCAL_TUNNEL {
		m.onRouteRemove(&proto.RouteRemove{Dst: update.Dst})
		return
	}

	if m.cidrToRoute[v4CIDR] == *update {
		return
	}

	m.cidrToRoute[v4CIDR] = *update
	m.dirtyCIDRs.Add(v4CIDR)
}

func (m *bpfRouteManager) onRouteRemove(update *proto.RouteRemove) {
	cidr := ip.MustParseCIDROrIP(update.Dst)
	v4CIDR, ok := cidr.(ip.V4CIDR)
	if !ok {
		// FIXME IPv6
		return
	}

	if _, ok := m.cidrToRoute[v4CIDR]; ok {
		// Check the entry is in the cache before removing and flagging as dirty.
		delete(m.cidrToRoute, v4CIDR)
		m.dirtyCIDRs.Add(v4CIDR)
	}
}

func (m *bpfRouteManager) onWorkloadEndpointUpdate(update *proto.WorkloadEndpointUpdate) {
	// Clean up the indexes for any old WEPs that had this ID.
	m.removeWEP(update.Id)
	// Update the indexes to add this WEP.
	m.addWEP(update)
}

func (m *bpfRouteManager) addWEP(update *proto.WorkloadEndpointUpdate) {
	m.wepIDToWorklaod[*update.Id] = update.Endpoint
	newCIDRs := getV4WorkloadCIDRs(update.Endpoint)
	for _, cidr := range newCIDRs {
		wepIDs := m.cidrToWEPIDs[cidr]
		if wepIDs == nil {
			wepIDs = set.New[proto.WorkloadEndpointID]()
			m.cidrToWEPIDs[cidr] = wepIDs
		}
		wepIDs.Add(*update.Id)
	}
	m.markCIDRsDirty(newCIDRs...)
	wepIDs := m.ifaceNameToWEPIDs[update.Endpoint.Name]
	if wepIDs == nil {
		wepIDs = set.New[proto.WorkloadEndpointID]()
		m.ifaceNameToWEPIDs[update.Endpoint.Name] = wepIDs
	}
	wepIDs.Add(*update.Id)
}

func (m *bpfRouteManager) onWorkloadEndpointRemove(update *proto.WorkloadEndpointRemove) {
	m.removeWEP(update.Id)
}

func (m *bpfRouteManager) removeWEP(id *proto.WorkloadEndpointID) {
	oldWEP := m.wepIDToWorklaod[*id]
	if oldWEP == nil {
		return
	}
	delete(m.wepIDToWorklaod, *id)
	oldCIDRs := getV4WorkloadCIDRs(oldWEP)
	for _, cidr := range oldCIDRs {
		m.cidrToWEPIDs[cidr].Discard(*id)
		if m.cidrToWEPIDs[cidr].Len() == 0 {
			delete(m.cidrToWEPIDs, cidr)
		}
	}
	m.markCIDRsDirty(oldCIDRs...)
	m.ifaceNameToWEPIDs[oldWEP.Name].Discard(*id)
	if m.ifaceNameToWEPIDs[oldWEP.Name].Len() == 0 {
		delete(m.ifaceNameToWEPIDs, oldWEP.Name)
	}
}

func getV4WorkloadCIDRs(wep *proto.WorkloadEndpoint) (cidrs []ip.V4CIDR) {
	if wep == nil {
		return
	}
	for _, addr := range wep.Ipv4Nets {
		cidrs = append(cidrs, ip.MustParseCIDROrIP(addr).(ip.V4CIDR))
	}
	return
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

func (m *bpfRouteManager) markCIDRsDirty(cidrs ...ip.V4CIDR) {
	m.dirtyCIDRs.AddAll(cidrs)
}
