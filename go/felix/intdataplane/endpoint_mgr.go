// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/ifacemonitor"
	"github.com/projectcalico/felix/go/felix/ip"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/routetable"
	"github.com/projectcalico/felix/go/felix/rules"
	"github.com/projectcalico/felix/go/felix/set"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
)

// endpointManager manages the dataplane resources that belong to each endpoint as well as
// the "dispatch chains" that fan out packets to the right per-endpoint chain.
//
// It programs the relevant iptables chains (via the iptables.Table objects) along with
// per-endpoint routes (via the RouteTable).
//
// Since calculating the dispatch chains is fairly expensive, the main OnUpdate method
// simply records the pending state of each interface and defers the actual calculation
// to CompleteDeferredWork().  This is also the basis of our failure handling; updates
// that fail are left in the pending state so they can be retried later.
type endpointManager struct {
	ipVersion      uint8
	wlIfacesRegexp *regexp.Regexp

	// Our dependencies.
	filterTable  iptablesTable
	ruleRenderer rules.RuleRenderer
	routeTable   *routetable.RouteTable

	// Active state, updated in CompleteDeferredWork.
	activeEndpoints      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	activeIfaceNameToID  map[string]proto.WorkloadEndpointID
	activeUpIfaces       set.Set
	activeIdToChains     map[proto.WorkloadEndpointID][]*iptables.Chain
	activeDispatchChains []*iptables.Chain

	ifaceNamesToReconfigure set.Set
	ifaceIDsToUpdateStatus  set.Set

	// Pending updates, cleared in CompleteDeferredWork.
	pendingEndpointUpdates map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	pendingIfaceUpdates    map[string]ifacemonitor.State

	// Host endpoint processing.
	ifaceAddrs               map[string]set.Set
	rawHostEndpoints         map[proto.HostEndpointID]*proto.HostEndpoint
	dirtyHostEndpoints       bool
	activeHostIfaceToChains  map[string][]*iptables.Chain
	activeHostDispatchChains []*iptables.Chain

	// Callbacks
	OnWorkloadEndpointStatusUpdate EndpointStatusUpdateCallback
}

type EndpointStatusUpdateCallback func(ipVersion uint8, id proto.WorkloadEndpointID, status string)

func newEndpointManager(
	filterTable iptablesTable,
	ruleRenderer rules.RuleRenderer,
	routeTable *routetable.RouteTable,
	ipVersion uint8,
	wlInterfacePrefixes []string,
	onWorkloadEndpointStatusUpdate EndpointStatusUpdateCallback,
) *endpointManager {
	wlIfacesPattern := "^(" + strings.Join(wlInterfacePrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	return &endpointManager{
		ipVersion:      ipVersion,
		wlIfacesRegexp: wlIfacesRegexp,

		filterTable:  filterTable,
		ruleRenderer: ruleRenderer,
		routeTable:   routeTable,

		activeEndpoints:     map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		activeIfaceNameToID: map[string]proto.WorkloadEndpointID{},
		activeUpIfaces:      set.New(),
		activeIdToChains:    map[proto.WorkloadEndpointID][]*iptables.Chain{},

		ifaceNamesToReconfigure: set.New(),
		ifaceIDsToUpdateStatus:  set.New(),

		pendingEndpointUpdates:   map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		pendingIfaceUpdates:      map[string]ifacemonitor.State{},
		ifaceAddrs:               map[string]set.Set{},
		rawHostEndpoints:         map[proto.HostEndpointID]*proto.HostEndpoint{},
		dirtyHostEndpoints:       true,
		activeHostIfaceToChains:  map[string][]*iptables.Chain{},
		activeHostDispatchChains: nil,

		OnWorkloadEndpointStatusUpdate: onWorkloadEndpointStatusUpdate,
	}
}

func (m *endpointManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		m.pendingEndpointUpdates[*msg.Id] = msg.Endpoint
	case *proto.WorkloadEndpointRemove:
		m.pendingEndpointUpdates[*msg.Id] = nil
	case *proto.HostEndpointUpdate:
		log.WithField("msg", msg).Debug("Host endpoint update")
		m.rawHostEndpoints[*msg.Id] = msg.Endpoint
		m.dirtyHostEndpoints = true
	case *proto.HostEndpointRemove:
		log.WithField("msg", msg).Debug("Host endpoint removed")
		delete(m.rawHostEndpoints, *msg.Id)
		m.dirtyHostEndpoints = true
	case *ifaceUpdate:
		log.WithField("update", msg).Debug("Interface state changed.")
		if !m.wlIfacesRegexp.MatchString(msg.Name) {
			log.WithField("update", msg).Debug("Not workload interface, ignoring.")
			return
		}
		m.pendingIfaceUpdates[msg.Name] = msg.State
	case *ifaceAddrsUpdate:
		log.WithField("update", msg).Debug("Interface addrs changed.")
		if m.wlIfacesRegexp.MatchString(msg.Name) {
			log.WithField("update", msg).Debug("Workload interface, ignoring.")
			return
		}
		if msg.Addrs != nil {
			m.ifaceAddrs[msg.Name] = msg.Addrs
		} else {
			delete(m.ifaceAddrs, msg.Name)
		}
		m.dirtyHostEndpoints = true
	}
}

func (m *endpointManager) CompleteDeferredWork() error {
	// Copy the pending interface updates to the active set.  Mark any interfaces that
	// have come up to be reconfigured.
	for ifaceName, state := range m.pendingIfaceUpdates {
		if state == ifacemonitor.StateUp {
			m.activeUpIfaces.Add(ifaceName)
			m.ifaceNamesToReconfigure.Add(ifaceName)
		} else {
			m.activeUpIfaces.Discard(ifaceName)
		}
		logCxt := log.WithField("ifaceName", ifaceName)
		if epID, ok := m.activeIfaceNameToID[ifaceName]; ok {
			logCxt.Info("Interface state changed; marking for status update.")
			m.ifaceIDsToUpdateStatus.Add(epID)
		} else {
			// We don't know about this interface yet (or it's already been deleted).
			// If the endpoint gets created, we'll do the update then. If it's been
			// deleted, we've already cleaned it up.
			logCxt.Debug("Ignoring interface state change for unknown interface.")
		}
		delete(m.pendingIfaceUpdates, ifaceName)
	}

	if err := m.resolveWorkloadEndpoints(); err != nil {
		log.WithError(err).Warn("Failed to resolve workload endpoints")
		return err
	}

	if m.dirtyHostEndpoints {
		if err := m.resolveHostEndpoints(); err != nil {
			log.WithError(err).Warn("Failed to resolve host endpoints")
			return err
		}
		m.dirtyHostEndpoints = false
	}

	return nil
}

func (m *endpointManager) resolveWorkloadEndpoints() error {
	// Update any dirty endpoints.
	for id, workload := range m.pendingEndpointUpdates {
		logCxt := log.WithField("id", id)
		oldWorkload := m.activeEndpoints[id]
		if workload != nil {
			logCxt.Info("Updating per-endpoint chains.")
			chains := m.ruleRenderer.WorkloadEndpointToIptablesChains(&id, workload)
			m.filterTable.UpdateChains(chains)
			m.activeIdToChains[id] = chains

			logCxt.Info("Updating endpoint routes.")
			var ipStrings []string
			if m.ipVersion == 4 {
				ipStrings = workload.Ipv4Nets
			} else {
				ipStrings = workload.Ipv6Nets
			}

			if oldWorkload != nil && oldWorkload.Name != workload.Name {
				logCxt.Debug("Interface name changed, cleaning up old state")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
				m.ifaceNamesToReconfigure.Discard(oldWorkload.Name)
				delete(m.activeIfaceNameToID, oldWorkload.Name)
			}
			var mac net.HardwareAddr
			if workload.Mac != "" {
				var err error
				mac, err = net.ParseMAC(workload.Mac)
				if err != nil {
					logCxt.WithError(err).Error(
						"Failed to parse endpoint's MAC address")
				}
			}
			routeTargets := make([]routetable.Target, len(ipStrings))
			for i, s := range ipStrings {
				routeTargets[i] = routetable.Target{
					CIDR:    ip.MustParseCIDR(s),
					DestMAC: mac,
				}
			}
			m.routeTable.SetRoutes(workload.Name, routeTargets)
			m.ifaceNamesToReconfigure.Add(workload.Name)
			m.activeEndpoints[id] = workload
			m.activeIfaceNameToID[workload.Name] = id
			delete(m.pendingEndpointUpdates, id)
		} else {
			logCxt.Info("Workload removed, deleting its chains.")
			m.filterTable.RemoveChains(m.activeIdToChains[id])
			if oldWorkload := m.activeEndpoints[id]; oldWorkload != nil {
				// Remove any routes from the routing table.  The RouteTable will
				// remove any conntrack entries as a side-effect.
				logCxt.Info("Workload removed, deleting old state.")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
				m.ifaceNamesToReconfigure.Discard(oldWorkload.Name)
				delete(m.activeIfaceNameToID, oldWorkload.Name)
			}
			delete(m.activeEndpoints, id)
			delete(m.pendingEndpointUpdates, id)
		}

		// Update or deletion, make sure we update the interface status.
		m.ifaceIDsToUpdateStatus.Add(id)
	}

	// Rewrite the dispatch chains if they've changed.
	// TODO(smc) avoid re-rendering chains if nothing has changed.  (Slightly tricky because
	// the dispatch chains depend on the interface names and maybe later the IPs in the data.)
	newDispatchChains := m.ruleRenderer.WorkloadDispatchChains(m.activeEndpoints)
	if !reflect.DeepEqual(newDispatchChains, m.activeDispatchChains) {
		log.Info("Workloads changed, updating dispatch chains.")
		m.filterTable.RemoveChains(m.activeDispatchChains)
		m.filterTable.UpdateChains(newDispatchChains)
		m.activeDispatchChains = newDispatchChains
	}

	m.ifaceNamesToReconfigure.Iter(func(item interface{}) error {
		ifaceName := item.(string)
		err := m.configureInterface(ifaceName)
		if err != nil {
			log.WithError(err).Warn("Failed to configure interface, will retry")
			return nil
		}
		return set.RemoveItem
	})

	m.ifaceIDsToUpdateStatus.Iter(func(item interface{}) error {
		logCxt := log.WithField("workloadID", item)
		logCxt.Debug("Re-evaluating endpoint status")
		workloadID := item.(proto.WorkloadEndpointID)
		var known, operUp, adminUp, failed bool

		workload, known := m.activeEndpoints[workloadID]
		if known {
			adminUp = workload.State == "active"
			operUp = m.activeUpIfaces.Contains(workload.Name)
			failed = m.ifaceNamesToReconfigure.Contains(workload.Name)
		}

		var status string
		if known {
			if failed {
				status = "error"
			} else if operUp && adminUp {
				status = "up"
			} else {
				status = "down"
			}
		}
		logCxt = logCxt.WithFields(log.Fields{
			"known":   known,
			"failed":  failed,
			"operUp":  operUp,
			"adminUp": adminUp,
			"status":  status,
		})
		logCxt.Info("Re-evaluated endpoint status")
		m.OnWorkloadEndpointStatusUpdate(m.ipVersion, workloadID, status)

		return set.RemoveItem
	})

	return nil
}

func (m *endpointManager) resolveHostEndpoints() error {

	// Host endpoint resolution
	// ------------------------
	//
	// There is a set of non-workload interfaces on the local host, each possibly with
	// IP addresses, that might be controlled by HostEndpoint resources in the Calico
	// data model.  The data model syntactically allows multiple HostEndpoint
	// resources to match a given interface - for example, an interface 'eth1' might
	// have address 10.240.0.34 and 172.19.2.98, and the data model might include:
	//
	// - HostEndpoint A with Name 'eth1'
	//
	// - HostEndpoint B with ExpectedIpv4Addrs including '10.240.0.34'
	//
	// - HostEndpoint C with ExpectedIpv4Addrs including '172.19.2.98'.
	//
	// but at runtime, at any given time, we only allow one HostEndpoint to govern
	// that interface.  That HostEndpoint becomes the active one, and the others
	// remain inactive.  (But if, for example, the active HostEndpoint resource was
	// deleted, then one of the inactive ones could take over.)  Given multiple
	// matching HostEndpoint resources, the one that wins is the one with the
	// alphabetically earliest HostEndpointId
	//
	// So the process here is not about 'resolving' a particular HostEndpoint on its
	// own.  Rather it is looking at the set of local non-workload interfaces and
	// seeing which of them are matched by the current set of HostEndpoints as a
	// whole.
	resolvedHostEpIds := map[string]proto.HostEndpointID{}
	for ifaceName, ifaceAddrs := range m.ifaceAddrs {
		ifaceCxt := log.WithFields(log.Fields{
			"ifaceName":  ifaceName,
			"ifaceAddrs": ifaceAddrs,
		})
		bestHostEpId := proto.HostEndpointID{}
	HostEpLoop:
		for id, hostEp := range m.rawHostEndpoints {
			logCxt := ifaceCxt.WithField("id", id)
			logCxt.WithField("bestHostEpId", bestHostEpId).Debug("See if HostEp matches interface")
			if (bestHostEpId.EndpointId != "") && (bestHostEpId.EndpointId < id.EndpointId) {
				// We already have a HostEndpointId that is better than
				// this one, so no point looking any further.
				logCxt.Debug("No better than existing match")
				continue
			}
			if hostEp.Name == ifaceName {
				// The HostEndpoint has an explicit name that matches the
				// interface.
				logCxt.Debug("Match on explicit iface name")
				bestHostEpId = id
				continue
			} else if hostEp.Name != "" {
				// The HostEndpoint has an explicit name that isn't this
				// interface.  Continue, so as not to allow it to match on
				// an IP address instead.
				logCxt.Debug("Rejected on explicit iface name")
				continue
			}
			for _, wantedList := range [][]string{hostEp.ExpectedIpv4Addrs, hostEp.ExpectedIpv6Addrs} {
				for _, wanted := range wantedList {
					logCxt.WithField("wanted", wanted).Debug("Address wanted by HostEp")
					if ifaceAddrs.Contains(wanted) {
						// The HostEndpoint expects an IP address
						// that is on this interface.
						logCxt.Debug("Match on address")
						bestHostEpId = id
						continue HostEpLoop
					}
				}
			}
		}
		if bestHostEpId.EndpointId != "" {
			log.WithFields(log.Fields{
				"ifaceName":    ifaceName,
				"bestHostEpId": bestHostEpId,
			}).Debug("Got HostEp for interface")
			resolvedHostEpIds[ifaceName] = bestHostEpId
		}
	}

	// Set up programming for the host endpoints that are now to be used.
	newHostIfaceChains := map[string][]*iptables.Chain{}
	for ifaceName, id := range resolvedHostEpIds {
		log.WithField("id", id).Info("Updating host endpoint chains.")
		hostEp := m.rawHostEndpoints[id]
		chains := m.ruleRenderer.HostEndpointToIptablesChains(ifaceName, hostEp)
		if !reflect.DeepEqual(chains, m.activeHostIfaceToChains[ifaceName]) {
			m.filterTable.UpdateChains(chains)
		}
		newHostIfaceChains[ifaceName] = chains
		delete(m.activeHostIfaceToChains, ifaceName)
	}

	// Remove programming for host endpoints that are not now in use.
	for ifaceName, chains := range m.activeHostIfaceToChains {
		log.WithField("ifaceName", ifaceName).Info("Host interface no longer protected, deleting its chains.")
		m.filterTable.RemoveChains(chains)
	}

	// Remember the host endpoints that are now in use.
	m.activeHostIfaceToChains = newHostIfaceChains

	// Rewrite the dispatch chains if they've changed.
	// TODO(smc) avoid re-rendering chains if nothing has changed.  (Slightly tricky because
	// the dispatch chains depend on the interface names and maybe later the IPs in the data.)
	log.WithField("resolvedHostEpIds", resolvedHostEpIds).Debug("Rewrite dispatch chains?")
	newDispatchChains := m.ruleRenderer.HostDispatchChains(resolvedHostEpIds)
	if !reflect.DeepEqual(newDispatchChains, m.activeHostDispatchChains) {
		log.Info("HostEps changed, updating dispatch chains.")
		m.filterTable.RemoveChains(m.activeHostDispatchChains)
		m.filterTable.UpdateChains(newDispatchChains)
		m.activeHostDispatchChains = newDispatchChains
	}

	return nil
}

func (m *endpointManager) configureInterface(name string) error {
	if !m.activeUpIfaces.Contains(name) {
		log.WithField("ifaceName", name).Info(
			"Skipping configuration of interface because it is oper down.")
		return nil
	}
	log.WithField("ifaceName", name).Info(
		"Applying /proc/sys configuration to interface.")
	if m.ipVersion == 4 {
		err := writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", name), "1")
		if err != nil {
			return err
		}
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", name), "1")
		if err != nil {
			return err
		}
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", name), "1")
		if err != nil {
			return err
		}
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", name), "0")
		if err != nil {
			return err
		}
	} else {
		err := writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", name), "1")
		if err != nil {
			return err
		}
	}
	return nil
}

func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}
