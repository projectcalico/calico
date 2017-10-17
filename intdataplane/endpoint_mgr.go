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
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/routetable"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type routeTable interface {
	SetRoutes(ifaceName string, targets []routetable.Target)
}

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
	// Config.
	ipVersion      uint8
	wlIfacesRegexp *regexp.Regexp

	// Our dependencies.
	rawTable     iptablesTable
	mangleTable  iptablesTable
	filterTable  iptablesTable
	ruleRenderer rules.RuleRenderer
	routeTable   routeTable
	writeProcSys procSysWriter

	// Pending updates, cleared in CompleteDeferredWork as the data is copied to the activeXYZ
	// fields.
	pendingWlEpUpdates  map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	pendingIfaceUpdates map[string]ifacemonitor.State

	// Active state, updated in CompleteDeferredWork.
	activeWlEndpoints      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	activeWlIfaceNameToID  map[string]proto.WorkloadEndpointID
	activeUpIfaces         set.Set
	activeWlIDToChains     map[proto.WorkloadEndpointID][]*iptables.Chain
	activeWlDispatchChains map[string]*iptables.Chain

	// wlIfaceNamesToReconfigure contains names of workload interfaces that need to have
	// their configuration (sysctls etc.) refreshed.
	wlIfaceNamesToReconfigure set.Set

	// epIDsToUpdateStatus contains IDs of endpoints that we need to report status for.
	// Mix of host and workload endpoint IDs.
	epIDsToUpdateStatus set.Set

	// hostIfaceToAddrs maps host interface name to the set of IPs on that interface (reported
	// fro the dataplane).
	hostIfaceToAddrs map[string]set.Set
	// rawHostEndpoints contains the raw (i.e. not resolved to interface) host endpoints.
	rawHostEndpoints map[proto.HostEndpointID]*proto.HostEndpoint
	// hostEndpointsDirty is set to true when host endpoints are updated.
	hostEndpointsDirty bool
	// activeHostIfaceToChains maps host interface name to the chains that we've programmed.
	activeHostIfaceToRawChains    map[string][]*iptables.Chain
	activeHostIfaceToFiltChains   map[string][]*iptables.Chain
	activeHostIfaceToMangleChains map[string][]*iptables.Chain
	// Dispatch chains that we've programmed for host endpoints.
	activeHostRawDispatchChains    map[string]*iptables.Chain
	activeHostFilterDispatchChains map[string]*iptables.Chain
	activeHostMangleDispatchChains map[string]*iptables.Chain
	// activeHostEpIDToIfaceNames records which interfaces we resolved each host endpoint to.
	activeHostEpIDToIfaceNames map[proto.HostEndpointID][]string
	// activeIfaceNameToHostEpID records which endpoint we resolved each host interface to.
	activeIfaceNameToHostEpID map[string]proto.HostEndpointID

	needToCheckDispatchChains bool

	// Callbacks
	OnEndpointStatusUpdate EndpointStatusUpdateCallback
}

type EndpointStatusUpdateCallback func(ipVersion uint8, id interface{}, status string)

type procSysWriter func(path, value string) error

func newEndpointManager(
	rawTable iptablesTable,
	mangleTable iptablesTable,
	filterTable iptablesTable,
	ruleRenderer rules.RuleRenderer,
	routeTable routeTable,
	ipVersion uint8,
	wlInterfacePrefixes []string,
	onWorkloadEndpointStatusUpdate EndpointStatusUpdateCallback,
) *endpointManager {
	return newEndpointManagerWithShims(
		rawTable,
		mangleTable,
		filterTable,
		ruleRenderer,
		routeTable,
		ipVersion,
		wlInterfacePrefixes,
		onWorkloadEndpointStatusUpdate,
		writeProcSys,
	)
}

func newEndpointManagerWithShims(
	rawTable iptablesTable,
	mangleTable iptablesTable,
	filterTable iptablesTable,
	ruleRenderer rules.RuleRenderer,
	routeTable routeTable,
	ipVersion uint8,
	wlInterfacePrefixes []string,
	onWorkloadEndpointStatusUpdate EndpointStatusUpdateCallback,
	procSysWriter procSysWriter,
) *endpointManager {
	wlIfacesPattern := "^(" + strings.Join(wlInterfacePrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	return &endpointManager{
		ipVersion:      ipVersion,
		wlIfacesRegexp: wlIfacesRegexp,

		rawTable:     rawTable,
		mangleTable:  mangleTable,
		filterTable:  filterTable,
		ruleRenderer: ruleRenderer,
		routeTable:   routeTable,
		writeProcSys: procSysWriter,

		// Pending updates, we store these up as OnUpdate is called, then process them
		// in CompleteDeferredWork and transfer the important data to the activeXYX fields.
		pendingWlEpUpdates:  map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		pendingIfaceUpdates: map[string]ifacemonitor.State{},

		activeUpIfaces: set.New(),

		activeWlEndpoints:     map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		activeWlIfaceNameToID: map[string]proto.WorkloadEndpointID{},
		activeWlIDToChains:    map[proto.WorkloadEndpointID][]*iptables.Chain{},

		wlIfaceNamesToReconfigure: set.New(),

		epIDsToUpdateStatus: set.New(),

		hostIfaceToAddrs:   map[string]set.Set{},
		rawHostEndpoints:   map[proto.HostEndpointID]*proto.HostEndpoint{},
		hostEndpointsDirty: true,

		activeHostIfaceToRawChains:    map[string][]*iptables.Chain{},
		activeHostIfaceToFiltChains:   map[string][]*iptables.Chain{},
		activeHostIfaceToMangleChains: map[string][]*iptables.Chain{},

		// Caches of the current dispatch chains indexed by chain name.  We use these to
		// calculate deltas when we need to update the chains.
		activeWlDispatchChains:         map[string]*iptables.Chain{},
		activeHostFilterDispatchChains: map[string]*iptables.Chain{},
		activeHostMangleDispatchChains: map[string]*iptables.Chain{},
		activeHostRawDispatchChains:    map[string]*iptables.Chain{},
		needToCheckDispatchChains:      true, // Need to do start-of-day update.

		OnEndpointStatusUpdate: onWorkloadEndpointStatusUpdate,
	}
}

func (m *endpointManager) OnUpdate(protoBufMsg interface{}) {
	log.WithField("msg", protoBufMsg).Debug("Received message")
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		m.pendingWlEpUpdates[*msg.Id] = msg.Endpoint
	case *proto.WorkloadEndpointRemove:
		m.pendingWlEpUpdates[*msg.Id] = nil
	case *proto.HostEndpointUpdate:
		log.WithField("msg", msg).Debug("Host endpoint update")
		m.rawHostEndpoints[*msg.Id] = msg.Endpoint
		m.hostEndpointsDirty = true
		m.epIDsToUpdateStatus.Add(*msg.Id)
	case *proto.HostEndpointRemove:
		log.WithField("msg", msg).Debug("Host endpoint removed")
		delete(m.rawHostEndpoints, *msg.Id)
		m.hostEndpointsDirty = true
		m.epIDsToUpdateStatus.Add(*msg.Id)
	case *ifaceUpdate:
		log.WithField("update", msg).Debug("Interface state changed.")
		m.pendingIfaceUpdates[msg.Name] = msg.State
	case *ifaceAddrsUpdate:
		log.WithField("update", msg).Debug("Interface addrs changed.")
		if m.wlIfacesRegexp.MatchString(msg.Name) {
			log.WithField("update", msg).Debug("Workload interface, ignoring.")
			return
		}
		if msg.Addrs != nil {
			m.hostIfaceToAddrs[msg.Name] = msg.Addrs
		} else {
			delete(m.hostIfaceToAddrs, msg.Name)
		}
		m.hostEndpointsDirty = true
	}
}

func (m *endpointManager) CompleteDeferredWork() error {
	// Copy the pending interface state to the active set and mark any interfaces that have
	// changed state for reconfiguration by resolveWorkload/HostEndpoints()
	for ifaceName, state := range m.pendingIfaceUpdates {
		if state == ifacemonitor.StateUp {
			m.activeUpIfaces.Add(ifaceName)
			if m.wlIfacesRegexp.MatchString(ifaceName) {
				log.WithField("ifaceName", ifaceName).Info(
					"Workload interface came up, marking for reconfiguration.")
				m.wlIfaceNamesToReconfigure.Add(ifaceName)
			}
		} else {
			m.activeUpIfaces.Discard(ifaceName)
		}
		// If this interface is linked to any already-existing endpoints, mark the endpoint
		// status for recalculation.  If the matching endpoint changes when we do
		// resolveHostEndpoints() then that will mark old and new matching endpoints for
		// update.
		m.markEndpointStatusDirtyByIface(ifaceName)
		// Clean up as we go...
		delete(m.pendingIfaceUpdates, ifaceName)
	}

	m.resolveWorkloadEndpoints()

	if m.hostEndpointsDirty {
		log.Debug("Host endpoints updated, resolving them.")
		m.resolveHostEndpoints()
		m.hostEndpointsDirty = false
	}

	// Now send any endpoint status updates.
	m.updateEndpointStatuses()

	return nil
}

func (m *endpointManager) markEndpointStatusDirtyByIface(ifaceName string) {
	logCxt := log.WithField("ifaceName", ifaceName)
	if epID, ok := m.activeWlIfaceNameToID[ifaceName]; ok {
		logCxt.Info("Workload interface state changed; marking for status update.")
		m.epIDsToUpdateStatus.Add(epID)
	} else if epID, ok := m.activeIfaceNameToHostEpID[ifaceName]; ok {
		logCxt.Info("Host interface state changed; marking for status update.")
		m.epIDsToUpdateStatus.Add(epID)
	} else {
		// We don't know about this interface yet (or it's already been deleted).
		// If the endpoint gets created, we'll do the update then. If it's been
		// deleted, we've already cleaned it up.
		logCxt.Debug("Ignoring interface state change for unknown interface.")
	}
}

func (m *endpointManager) updateEndpointStatuses() {
	log.WithField("dirtyEndpoints", m.epIDsToUpdateStatus).Debug("Reporting endpoint status.")
	m.epIDsToUpdateStatus.Iter(func(item interface{}) error {
		switch id := item.(type) {
		case proto.WorkloadEndpointID:
			status := m.calculateWorkloadEndpointStatus(id)
			m.OnEndpointStatusUpdate(m.ipVersion, id, status)
		case proto.HostEndpointID:
			status := m.calculateHostEndpointStatus(id)
			m.OnEndpointStatusUpdate(m.ipVersion, id, status)
		}

		return set.RemoveItem
	})
}

func (m *endpointManager) calculateWorkloadEndpointStatus(id proto.WorkloadEndpointID) string {
	logCxt := log.WithField("workloadEndpointID", id)
	logCxt.Debug("Re-evaluating workload endpoint status")
	var operUp, adminUp, failed bool
	workload, known := m.activeWlEndpoints[id]
	if known {
		adminUp = workload.State == "active"
		operUp = m.activeUpIfaces.Contains(workload.Name)
		failed = m.wlIfaceNamesToReconfigure.Contains(workload.Name)
	}

	// Note: if endpoint is not known (i.e. has been deleted), status will be "", which signals
	// a deletion.
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
	logCxt.Info("Re-evaluated workload endpoint status")
	return status
}

func (m *endpointManager) calculateHostEndpointStatus(id proto.HostEndpointID) (status string) {
	logCxt := log.WithField("hostEndpointID", id)
	logCxt.Debug("Re-evaluating host endpoint status")
	var resolved, operUp bool
	_, known := m.rawHostEndpoints[id]

	// Note: if endpoint is not known (i.e. has been deleted), status will be "", which signals
	// a deletion.
	if known {
		ifaceNames := m.activeHostEpIDToIfaceNames[id]
		if len(ifaceNames) > 0 {
			resolved = true
			operUp = true
			for _, ifaceName := range ifaceNames {
				ifaceUp := m.activeUpIfaces.Contains(ifaceName)
				logCxt.WithFields(log.Fields{
					"ifaceName": ifaceName,
					"ifaceUp":   ifaceUp,
				}).Debug("Status of matching interface.")
				operUp = operUp && ifaceUp
			}
		}

		if resolved && operUp {
			status = "up"
		} else if resolved {
			status = "down"
		} else {
			// Known but failed to resolve, map that to error.
			status = "error"
		}
	}

	logCxt = logCxt.WithFields(log.Fields{
		"known":    known,
		"resolved": resolved,
		"operUp":   operUp,
		"status":   status,
	})
	logCxt.Info("Re-evaluated host endpoint status")
	return status
}

func (m *endpointManager) resolveWorkloadEndpoints() {
	if len(m.pendingWlEpUpdates) > 0 {
		// We're about to make endpoint updates, make sure we recheck the dispatch chains.
		m.needToCheckDispatchChains = true
	}

	// Update any dirty endpoints.
	for id, workload := range m.pendingWlEpUpdates {
		logCxt := log.WithField("id", id)
		oldWorkload := m.activeWlEndpoints[id]
		if workload != nil {
			logCxt.Info("Updating per-endpoint chains.")
			if oldWorkload != nil && oldWorkload.Name != workload.Name {
				logCxt.Debug("Interface name changed, cleaning up old state")
				m.filterTable.RemoveChains(m.activeWlIDToChains[id])
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
				m.wlIfaceNamesToReconfigure.Discard(oldWorkload.Name)
				delete(m.activeWlIfaceNameToID, oldWorkload.Name)
			}
			var ingressPolicyNames, egressPolicyNames []string
			if len(workload.Tiers) > 0 {
				ingressPolicyNames = workload.Tiers[0].IngressPolicies
				egressPolicyNames = workload.Tiers[0].EgressPolicies
			}
			adminUp := workload.State == "active"
			chains := m.ruleRenderer.WorkloadEndpointToIptablesChains(
				workload.Name,
				adminUp,
				ingressPolicyNames,
				egressPolicyNames,
				workload.ProfileIds,
			)
			m.filterTable.UpdateChains(chains)
			m.activeWlIDToChains[id] = chains

			// Collect the IP prefixes that we want to route locally to this endpoint:
			logCxt.Info("Updating endpoint routes.")
			var (
				ipStrings  []string
				natInfos   []*proto.NatInfo
				addrSuffix string
			)
			if m.ipVersion == 4 {
				ipStrings = workload.Ipv4Nets
				natInfos = workload.Ipv4Nat
				addrSuffix = "/32"
			} else {
				ipStrings = workload.Ipv6Nets
				natInfos = workload.Ipv6Nat
				addrSuffix = "/128"
			}
			if len(natInfos) != 0 {
				old := ipStrings
				ipStrings = make([]string, len(old)+len(natInfos))
				copy(ipStrings, old)
				for ii, natInfo := range natInfos {
					ipStrings[len(old)+ii] = natInfo.ExtIp + addrSuffix
				}
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
			var routeTargets []routetable.Target
			if adminUp {
				logCxt.Debug("Endpoint up, adding routes")
				for _, s := range ipStrings {
					routeTargets = append(routeTargets, routetable.Target{
						CIDR:    ip.MustParseCIDR(s),
						DestMAC: mac,
					})
				}
			} else {
				logCxt.Debug("Endpoint down, removing routes")
			}
			m.routeTable.SetRoutes(workload.Name, routeTargets)
			m.wlIfaceNamesToReconfigure.Add(workload.Name)
			m.activeWlEndpoints[id] = workload
			m.activeWlIfaceNameToID[workload.Name] = id
			delete(m.pendingWlEpUpdates, id)
		} else {
			logCxt.Info("Workload removed, deleting its chains.")
			m.filterTable.RemoveChains(m.activeWlIDToChains[id])
			if oldWorkload != nil {
				// Remove any routes from the routing table.  The RouteTable will
				// remove any conntrack entries as a side-effect.
				logCxt.Info("Workload removed, deleting old state.")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
				m.wlIfaceNamesToReconfigure.Discard(oldWorkload.Name)
				delete(m.activeWlIfaceNameToID, oldWorkload.Name)
			}
			delete(m.activeWlEndpoints, id)
			delete(m.pendingWlEpUpdates, id)
		}

		// Update or deletion, make sure we update the interface status.
		m.epIDsToUpdateStatus.Add(id)
	}

	if m.needToCheckDispatchChains {
		// Rewrite the dispatch chains if they've changed.
		newDispatchChains := m.ruleRenderer.WorkloadDispatchChains(m.activeWlEndpoints)
		m.updateDispatchChains(m.activeWlDispatchChains, newDispatchChains, m.filterTable)
		m.needToCheckDispatchChains = false
	}

	m.wlIfaceNamesToReconfigure.Iter(func(item interface{}) error {
		ifaceName := item.(string)
		err := m.configureInterface(ifaceName)
		if err != nil {
			log.WithError(err).Warn("Failed to configure interface, will retry")
			return nil
		}
		return set.RemoveItem
	})
}

func (m *endpointManager) resolveHostEndpoints() {

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
	newIfaceNameToHostEpID := map[string]proto.HostEndpointID{}
	newPreDNATIfaceNameToHostEpID := map[string]proto.HostEndpointID{}
	newUntrackedIfaceNameToHostEpID := map[string]proto.HostEndpointID{}
	newHostEpIDToIfaceNames := map[proto.HostEndpointID][]string{}
	for ifaceName, ifaceAddrs := range m.hostIfaceToAddrs {
		ifaceCxt := log.WithFields(log.Fields{
			"ifaceName":  ifaceName,
			"ifaceAddrs": ifaceAddrs,
		})
		bestHostEpId := proto.HostEndpointID{}
		var bestHostEp proto.HostEndpoint
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
				bestHostEp = *hostEp
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
						bestHostEp = *hostEp
						continue HostEpLoop
					}
				}
			}
		}
		if bestHostEpId.EndpointId != "" {
			logCxt := log.WithFields(log.Fields{
				"ifaceName":    ifaceName,
				"bestHostEpId": bestHostEpId,
			})
			logCxt.Debug("Got HostEp for interface")
			newIfaceNameToHostEpID[ifaceName] = bestHostEpId
			if len(bestHostEp.UntrackedTiers) > 0 {
				// Optimisation: only add the endpoint chains to the raw (untracked)
				// table if there's some untracked policy to apply.  This reduces
				// per-packet latency since every packet has to traverse the raw
				// table.
				logCxt.Debug("Endpoint has untracked policies.")
				newUntrackedIfaceNameToHostEpID[ifaceName] = bestHostEpId
			}
			if len(bestHostEp.PreDnatTiers) > 0 {
				// Similar optimisation (or neatness) for pre-DNAT policy.
				logCxt.Debug("Endpoint has pre-DNAT policies.")
				newPreDNATIfaceNameToHostEpID[ifaceName] = bestHostEpId
			}
			// Note, in contrast to the check above, we unconditionally record the
			// match in newHostEpIDToIfaceNames so that we always render the endpoint
			// into the filter table.  This ensures that we get the correct "default
			// drop" behaviour and that failsafe rules are applied correctly.
			newHostEpIDToIfaceNames[bestHostEpId] = append(
				newHostEpIDToIfaceNames[bestHostEpId], ifaceName)
		}

		oldID, wasKnown := m.activeIfaceNameToHostEpID[ifaceName]
		newID, isKnown := newIfaceNameToHostEpID[ifaceName]
		if oldID != newID {
			logCxt := ifaceCxt.WithFields(log.Fields{
				"oldID": m.activeIfaceNameToHostEpID[ifaceName],
				"newID": newIfaceNameToHostEpID[ifaceName],
			})
			logCxt.Info("Endpoint matching interface changed")
			if wasKnown {
				logCxt.Debug("Endpoint was known, updating old endpoint status")
				m.epIDsToUpdateStatus.Add(oldID)
			}
			if isKnown {
				logCxt.Debug("Endpoint is known, updating new endpoint status")
				m.epIDsToUpdateStatus.Add(newID)
			}
		}
	}

	// Set up programming for the host endpoints that are now to be used.
	newHostIfaceFiltChains := map[string][]*iptables.Chain{}
	for ifaceName, id := range newIfaceNameToHostEpID {
		log.WithField("id", id).Info("Updating host endpoint chains.")
		hostEp := m.rawHostEndpoints[id]

		// Update the filter chain, for normal traffic.
		var ingressPolicyNames, egressPolicyNames []string
		var ingressForwardPolicyNames, egressForwardPolicyNames []string
		if len(hostEp.Tiers) > 0 {
			ingressPolicyNames = hostEp.Tiers[0].IngressPolicies
			egressPolicyNames = hostEp.Tiers[0].EgressPolicies
		}
		if len(hostEp.ForwardTiers) > 0 {
			ingressForwardPolicyNames = hostEp.ForwardTiers[0].IngressPolicies
			egressForwardPolicyNames = hostEp.ForwardTiers[0].EgressPolicies
		}

		filtChains := m.ruleRenderer.HostEndpointToFilterChains(
			ifaceName,
			ingressPolicyNames,
			egressPolicyNames,
			ingressForwardPolicyNames,
			egressForwardPolicyNames,
			hostEp.ProfileIds,
		)

		if !reflect.DeepEqual(filtChains, m.activeHostIfaceToFiltChains[ifaceName]) {
			m.filterTable.UpdateChains(filtChains)
		}
		newHostIfaceFiltChains[ifaceName] = filtChains
		delete(m.activeHostIfaceToFiltChains, ifaceName)
	}

	newHostIfaceMangleChains := map[string][]*iptables.Chain{}
	for ifaceName, id := range newPreDNATIfaceNameToHostEpID {
		log.WithField("id", id).Info("Updating host endpoint mangle chains.")
		hostEp := m.rawHostEndpoints[id]

		// Update the mangle table, for preDNAT policy.
		var ingressPolicyNames []string
		if len(hostEp.PreDnatTiers) > 0 {
			ingressPolicyNames = hostEp.PreDnatTiers[0].IngressPolicies
		}
		mangleChains := m.ruleRenderer.HostEndpointToMangleChains(
			ifaceName,
			ingressPolicyNames,
		)
		if !reflect.DeepEqual(mangleChains, m.activeHostIfaceToMangleChains[ifaceName]) {
			m.mangleTable.UpdateChains(mangleChains)
		}
		newHostIfaceMangleChains[ifaceName] = mangleChains
		delete(m.activeHostIfaceToMangleChains, ifaceName)
	}

	newHostIfaceRawChains := map[string][]*iptables.Chain{}
	for ifaceName, id := range newUntrackedIfaceNameToHostEpID {
		log.WithField("id", id).Info("Updating host endpoint raw chains.")
		hostEp := m.rawHostEndpoints[id]

		// Update the raw chain, for untracked traffic.
		var ingressPolicyNames, egressPolicyNames []string
		if len(hostEp.UntrackedTiers) > 0 {
			ingressPolicyNames = hostEp.UntrackedTiers[0].IngressPolicies
			egressPolicyNames = hostEp.UntrackedTiers[0].EgressPolicies
		}
		rawChains := m.ruleRenderer.HostEndpointToRawChains(
			ifaceName,
			ingressPolicyNames,
			egressPolicyNames,
		)
		if !reflect.DeepEqual(rawChains, m.activeHostIfaceToRawChains[ifaceName]) {
			m.rawTable.UpdateChains(rawChains)
		}
		newHostIfaceRawChains[ifaceName] = rawChains
		delete(m.activeHostIfaceToRawChains, ifaceName)
	}

	// Remove programming for host endpoints that are not now in use.
	for ifaceName, chains := range m.activeHostIfaceToFiltChains {
		log.WithField("ifaceName", ifaceName).Info(
			"Host interface no longer protected, deleting its normal chains.")
		m.filterTable.RemoveChains(chains)
	}
	for ifaceName, chains := range m.activeHostIfaceToMangleChains {
		log.WithField("ifaceName", ifaceName).Info(
			"Host interface no longer protected, deleting its preDNAT chains.")
		m.mangleTable.RemoveChains(chains)
	}
	for ifaceName, chains := range m.activeHostIfaceToRawChains {
		log.WithField("ifaceName", ifaceName).Info(
			"Host interface no longer protected, deleting its untracked chains.")
		m.rawTable.RemoveChains(chains)
	}

	// Remember the host endpoints that are now in use.
	m.activeIfaceNameToHostEpID = newIfaceNameToHostEpID
	m.activeHostEpIDToIfaceNames = newHostEpIDToIfaceNames
	m.activeHostIfaceToFiltChains = newHostIfaceFiltChains
	m.activeHostIfaceToMangleChains = newHostIfaceMangleChains
	m.activeHostIfaceToRawChains = newHostIfaceRawChains

	// Rewrite the filter dispatch chains if they've changed.
	log.WithField("resolvedHostEpIds", newIfaceNameToHostEpID).Debug("Rewrite filter dispatch chains?")
	newFilterDispatchChains := m.ruleRenderer.HostDispatchChains(newIfaceNameToHostEpID, true)
	m.updateDispatchChains(m.activeHostFilterDispatchChains, newFilterDispatchChains, m.filterTable)

	// Rewrite the mangle dispatch chains if they've changed.
	log.WithField("resolvedHostEpIds", newPreDNATIfaceNameToHostEpID).Debug("Rewrite mangle dispatch chains?")
	newMangleDispatchChains := m.ruleRenderer.FromHostDispatchChains(newPreDNATIfaceNameToHostEpID)
	m.updateDispatchChains(m.activeHostMangleDispatchChains, newMangleDispatchChains, m.mangleTable)

	// Rewrite the raw dispatch chains if they've changed.
	log.WithField("resolvedHostEpIds", newUntrackedIfaceNameToHostEpID).Debug("Rewrite raw dispatch chains?")
	newRawDispatchChains := m.ruleRenderer.HostDispatchChains(newUntrackedIfaceNameToHostEpID, false)
	m.updateDispatchChains(m.activeHostRawDispatchChains, newRawDispatchChains, m.rawTable)

	log.Debug("Done resolving host endpoints.")
}

// updateDispatchChains updates one of the sets of dispatch chains.  It sends the changes to the
// given iptables.Table and records the updates in the activeChains map.
//
// Calculating the minimum update prevents log spam and reduces the work needed in the Table.
func (m *endpointManager) updateDispatchChains(
	activeChains map[string]*iptables.Chain,
	newChains []*iptables.Chain,
	table iptablesTable,
) {
	seenChains := set.New()
	for _, newChain := range newChains {
		seenChains.Add(newChain.Name)
		oldChain := activeChains[newChain.Name]
		if !reflect.DeepEqual(newChain, oldChain) {
			table.UpdateChain(newChain)
			activeChains[newChain.Name] = newChain
		}
	}
	for name := range activeChains {
		if !seenChains.Contains(name) {
			table.RemoveChainByName(name)
			delete(activeChains, name)
		}
	}
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
		// Enable strict reverse-path filtering.  This prevents a workload from spoofing its
		// IP address.  Non-privileged containers have additional anti-spoofing protection
		// but VM workloads, for example, can easily spoof their IP.
		err := m.writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", name), "1")
		if err != nil {
			return err
		}
		// Enable routing to localhost.  This is required to allow for NAT to the local
		// host.
		err = m.writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", name), "1")
		if err != nil {
			return err
		}
		// Enable proxy ARP, this makes the host respond to all ARP requests with its own
		// MAC.  This has a couple of advantages:
		//
		// - In OpenStack, we're forced to configure the guest's networking using DHCP.
		//   Since DHCP requires a subnet and gateway, representing the Calico network
		//   in the natural way would lose a lot of IP addresses.  For IPv4, we'd have to
		//   advertise a distinct /30 to each guest, which would use up 4 IPs per guest.
		//   Using proxy ARP, we can advertise the whole pool to each guest as its subnet
		//   but have the host respond to all ARP requests and route all the traffic whether
		//   it is on or off subnet.
		//
		// - For containers, we install explicit routes into the containers network
		//   namespace and we use a link-local address for the gateway.  Turing on proxy ARP
		//   means that we don't need to assign the link local address explicitly to each
		//   host side of the veth, which is one fewer thing to maintain and one fewer
		//   thing we may clash over.
		err = m.writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", name), "1")
		if err != nil {
			return err
		}
		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		err = m.writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", name), "0")
		if err != nil {
			return err
		}
		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		err = m.writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", name), "1")
		if err != nil {
			return err
		}
	} else {
		// Enable proxy NDP, similarly to proxy ARP, described above.
		err := m.writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", name), "1")
		if err != nil {
			return err
		}
		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		err = m.writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", name), "1")
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
