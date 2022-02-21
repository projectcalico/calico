// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// routeTable is the interface provided by the standard routetable module used to progam the RIB.
type routeTable interface {
	routeTableSyncer
	SetRoutes(ifaceName string, targets []routetable.Target)
	SetL2Routes(ifaceName string, targets []routetable.L2Target)
}

type hepListener interface {
	OnHEPUpdate(hostIfaceToEpMap map[string]proto.HostEndpoint)
}

type endpointManagerCallbacks struct {
	addInterface           *common.AddInterfaceFuncs
	removeInterface        *common.RemoveInterfaceFuncs
	updateInterface        *common.UpdateInterfaceFuncs
	updateHostEndpoint     *common.UpdateHostEndpointFuncs
	removeHostEndpoint     *common.RemoveHostEndpointFuncs
	updateWorkloadEndpoint *common.UpdateWorkloadEndpointFuncs
	removeWorkloadEndpoint *common.RemoveWorkloadEndpointFuncs
}

func newEndpointManagerCallbacks(callbacks *common.Callbacks, ipVersion uint8) endpointManagerCallbacks {
	if ipVersion == 4 {
		return endpointManagerCallbacks{
			addInterface:           callbacks.AddInterfaceV4,
			removeInterface:        callbacks.RemoveInterfaceV4,
			updateInterface:        callbacks.UpdateInterfaceV4,
			updateHostEndpoint:     callbacks.UpdateHostEndpointV4,
			removeHostEndpoint:     callbacks.RemoveHostEndpointV4,
			updateWorkloadEndpoint: callbacks.UpdateWorkloadEndpointV4,
			removeWorkloadEndpoint: callbacks.RemoveWorkloadEndpointV4,
		}
	} else {
		return endpointManagerCallbacks{
			addInterface:           &common.AddInterfaceFuncs{},
			removeInterface:        &common.RemoveInterfaceFuncs{},
			updateInterface:        &common.UpdateInterfaceFuncs{},
			updateHostEndpoint:     &common.UpdateHostEndpointFuncs{},
			removeHostEndpoint:     &common.RemoveHostEndpointFuncs{},
			updateWorkloadEndpoint: &common.UpdateWorkloadEndpointFuncs{},
			removeWorkloadEndpoint: &common.RemoveWorkloadEndpointFuncs{},
		}
	}
}

func (c *endpointManagerCallbacks) InvokeInterfaceCallbacks(old, new map[string]proto.HostEndpointID) {
	for ifaceName, oldEpID := range old {
		if newEpID, ok := new[ifaceName]; ok {
			if oldEpID != newEpID {
				c.updateInterface.Invoke(ifaceName, newEpID)
			}
		} else {
			c.removeInterface.Invoke(ifaceName)
		}
	}
	for ifaceName, newEpID := range new {
		if _, ok := old[ifaceName]; !ok {
			c.addInterface.Invoke(ifaceName, newEpID)
		}
	}
}

func (c *endpointManagerCallbacks) InvokeUpdateHostEndpoint(hostEpID proto.HostEndpointID) {
	c.updateHostEndpoint.Invoke(hostEpID)
}

func (c *endpointManagerCallbacks) InvokeRemoveHostEndpoint(hostEpID proto.HostEndpointID) {
	c.removeHostEndpoint.Invoke(hostEpID)
}

func (c *endpointManagerCallbacks) InvokeUpdateWorkload(old, new *proto.WorkloadEndpoint) {
	c.updateWorkloadEndpoint.Invoke(old, new)
}

func (c *endpointManagerCallbacks) InvokeRemoveWorkload(old *proto.WorkloadEndpoint) {
	c.removeWorkloadEndpoint.Invoke(old)
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
	ipVersion              uint8
	wlIfacesRegexp         *regexp.Regexp
	kubeIPVSSupportEnabled bool

	// Our dependencies.
	rawTable     iptablesTable
	mangleTable  iptablesTable
	filterTable  iptablesTable
	ruleRenderer rules.RuleRenderer
	routeTable   routeTable
	writeProcSys procSysWriter
	osStat       func(path string) (os.FileInfo, error)
	epMarkMapper rules.EndpointMarkMapper

	// Pending updates, cleared in CompleteDeferredWork as the data is copied to the activeXYZ
	// fields.
	pendingWlEpUpdates  map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	pendingIfaceUpdates map[string]ifacemonitor.State

	// Active state, updated in CompleteDeferredWork.
	activeWlEndpoints          map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	activeWlIfaceNameToID      map[string]proto.WorkloadEndpointID
	activeUpIfaces             set.Set
	activeWlIDToChains         map[proto.WorkloadEndpointID][]*iptables.Chain
	activeWlDispatchChains     map[string]*iptables.Chain
	activeEPMarkDispatchChains map[string]*iptables.Chain

	// Workload endpoints that would be locally active but are 'shadowed' by other endpoints
	// with the same interface name.
	shadowedWlEndpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint

	// wlIfaceNamesToReconfigure contains names of workload interfaces that need to have
	// their configuration (sysctls etc.) refreshed.
	wlIfaceNamesToReconfigure set.Set

	// epIDsToUpdateStatus contains IDs of endpoints that we need to report status for.
	// Mix of host and workload endpoint IDs.
	epIDsToUpdateStatus set.Set

	// sourceSpoofingConfig maps interface names to lists of source IPs that we accept from these interfaces
	// these interfaces (in addition to the pod IPs)
	sourceSpoofingConfig map[string][]string
	// default configuration for new interfaces
	// used to reset kernel settings when source spoofing is disabled
	defaultRpFilter string

	// hostIfaceToAddrs maps host interface name to the set of IPs on that interface (reported
	// fro the dataplane).
	hostIfaceToAddrs map[string]set.Set
	// rawHostEndpoints contains the raw (i.e. not resolved to interface) host endpoints.
	rawHostEndpoints map[proto.HostEndpointID]*proto.HostEndpoint
	// hostEndpointsDirty is set to true when host endpoints are updated.
	hostEndpointsDirty bool
	// activeHostIfaceToChains maps host interface name to the chains that we've programmed.
	activeHostIfaceToRawChains           map[string][]*iptables.Chain
	activeHostIfaceToFiltChains          map[string][]*iptables.Chain
	activeHostIfaceToMangleIngressChains map[string][]*iptables.Chain
	activeHostIfaceToMangleEgressChains  map[string][]*iptables.Chain
	// Dispatch chains that we've programmed for host endpoints.
	activeHostRawDispatchChains    map[string]*iptables.Chain
	activeHostFilterDispatchChains map[string]*iptables.Chain
	activeHostMangleDispatchChains map[string]*iptables.Chain
	// activeHostEpIDToIfaceNames records which interfaces we resolved each host endpoint to.
	activeHostEpIDToIfaceNames map[proto.HostEndpointID][]string
	// activeIfaceNameToHostEpID records which endpoint we resolved each host interface to.
	activeIfaceNameToHostEpID map[string]proto.HostEndpointID
	newIfaceNameToHostEpID    map[string]proto.HostEndpointID

	needToCheckDispatchChains     bool
	needToCheckEndpointMarkChains bool

	// Callbacks
	OnEndpointStatusUpdate EndpointStatusUpdateCallback
	callbacks              endpointManagerCallbacks
	bpfEnabled             bool
	bpfEndpointManager     hepListener
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
	epMarkMapper rules.EndpointMarkMapper,
	kubeIPVSSupportEnabled bool,
	wlInterfacePrefixes []string,
	onWorkloadEndpointStatusUpdate EndpointStatusUpdateCallback,
	defaultRpFilter string,
	bpfEnabled bool,
	bpfEndpointManager hepListener,
	callbacks *common.Callbacks,
) *endpointManager {
	return newEndpointManagerWithShims(
		rawTable,
		mangleTable,
		filterTable,
		ruleRenderer,
		routeTable,
		ipVersion,
		epMarkMapper,
		kubeIPVSSupportEnabled,
		wlInterfacePrefixes,
		onWorkloadEndpointStatusUpdate,
		writeProcSys,
		os.Stat,
		defaultRpFilter,
		bpfEnabled,
		bpfEndpointManager,
		callbacks,
	)
}

func newEndpointManagerWithShims(
	rawTable iptablesTable,
	mangleTable iptablesTable,
	filterTable iptablesTable,
	ruleRenderer rules.RuleRenderer,
	routeTable routeTable,
	ipVersion uint8,
	epMarkMapper rules.EndpointMarkMapper,
	kubeIPVSSupportEnabled bool,
	wlInterfacePrefixes []string,
	onWorkloadEndpointStatusUpdate EndpointStatusUpdateCallback,
	procSysWriter procSysWriter,
	osStat func(name string) (os.FileInfo, error),
	defaultRpFilter string,
	bpfEnabled bool,
	bpfEndpointManager hepListener,
	callbacks *common.Callbacks,
) *endpointManager {
	wlIfacesPattern := "^(" + strings.Join(wlInterfacePrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	return &endpointManager{
		ipVersion:              ipVersion,
		wlIfacesRegexp:         wlIfacesRegexp,
		kubeIPVSSupportEnabled: kubeIPVSSupportEnabled,
		bpfEnabled:             bpfEnabled,
		bpfEndpointManager:     bpfEndpointManager,

		rawTable:     rawTable,
		mangleTable:  mangleTable,
		filterTable:  filterTable,
		ruleRenderer: ruleRenderer,
		routeTable:   routeTable,
		writeProcSys: procSysWriter,
		osStat:       osStat,
		epMarkMapper: epMarkMapper,

		// Pending updates, we store these up as OnUpdate is called, then process them
		// in CompleteDeferredWork and transfer the important data to the activeXYX fields.
		pendingWlEpUpdates:  map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		pendingIfaceUpdates: map[string]ifacemonitor.State{},

		activeUpIfaces: set.New(),

		activeWlEndpoints:     map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		activeWlIfaceNameToID: map[string]proto.WorkloadEndpointID{},
		activeWlIDToChains:    map[proto.WorkloadEndpointID][]*iptables.Chain{},

		shadowedWlEndpoints: map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},

		wlIfaceNamesToReconfigure: set.New(),

		epIDsToUpdateStatus: set.New(),

		sourceSpoofingConfig: map[string][]string{},
		defaultRpFilter:      defaultRpFilter,

		hostIfaceToAddrs:   map[string]set.Set{},
		rawHostEndpoints:   map[proto.HostEndpointID]*proto.HostEndpoint{},
		hostEndpointsDirty: true,

		activeHostIfaceToRawChains:           map[string][]*iptables.Chain{},
		activeHostIfaceToFiltChains:          map[string][]*iptables.Chain{},
		activeHostIfaceToMangleIngressChains: map[string][]*iptables.Chain{},
		activeHostIfaceToMangleEgressChains:  map[string][]*iptables.Chain{},

		// Caches of the current dispatch chains indexed by chain name.  We use these to
		// calculate deltas when we need to update the chains.
		activeWlDispatchChains:         map[string]*iptables.Chain{},
		activeHostFilterDispatchChains: map[string]*iptables.Chain{},
		activeHostMangleDispatchChains: map[string]*iptables.Chain{},
		activeHostRawDispatchChains:    map[string]*iptables.Chain{},
		activeEPMarkDispatchChains:     map[string]*iptables.Chain{},
		needToCheckDispatchChains:      true, // Need to do start-of-day update.
		needToCheckEndpointMarkChains:  true, // Need to do start-of-day update.

		OnEndpointStatusUpdate: onWorkloadEndpointStatusUpdate,
		callbacks:              newEndpointManagerCallbacks(callbacks, ipVersion),
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
		m.callbacks.InvokeUpdateHostEndpoint(*msg.Id)
		m.rawHostEndpoints[*msg.Id] = msg.Endpoint
		m.hostEndpointsDirty = true
		m.epIDsToUpdateStatus.Add(*msg.Id)
	case *proto.HostEndpointRemove:
		log.WithField("msg", msg).Debug("Host endpoint removed")
		m.callbacks.InvokeRemoveHostEndpoint(*msg.Id)
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

func (m *endpointManager) ResolveUpdateBatch() error {
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

	if m.hostEndpointsDirty {
		log.Debug("Host endpoints updated, resolving them.")
		m.newIfaceNameToHostEpID = m.resolveHostEndpoints()
	}

	return nil
}

func (m *endpointManager) CompleteDeferredWork() error {

	m.resolveWorkloadEndpoints()

	if m.hostEndpointsDirty {
		log.Debug("Host endpoints updated, resolving them.")
		m.updateHostEndpoints()
		m.hostEndpointsDirty = false
	}

	if m.kubeIPVSSupportEnabled && m.needToCheckEndpointMarkChains {
		m.resolveEndpointMarks()
		m.needToCheckEndpointMarkChains = false
	}

	// Now send any endpoint status updates.
	m.updateEndpointStatuses()

	return nil
}

func (m *endpointManager) GetRouteTableSyncers() []routeTableSyncer {
	return []routeTableSyncer{m.routeTable}
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
				if ifaceName == allInterfaces {
					// For * host endpoints we don't let particular interfaces
					// impact their reported status, because it's unclear what
					// the semantics would be, and we'd potentially have to look
					// at every interface on the host.
					continue
				}
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

	removeActiveWorkload := func(logCxt *log.Entry, oldWorkload *proto.WorkloadEndpoint, id proto.WorkloadEndpointID) {
		m.callbacks.InvokeRemoveWorkload(oldWorkload)
		m.filterTable.RemoveChains(m.activeWlIDToChains[id])
		delete(m.activeWlIDToChains, id)
		if oldWorkload != nil {
			m.epMarkMapper.ReleaseEndpointMark(oldWorkload.Name)
			// Remove any routes from the routing table.  The RouteTable will remove any
			// conntrack entries as a side-effect.
			logCxt.Info("Workload removed, deleting old state.")
			m.routeTable.SetRoutes(oldWorkload.Name, nil)
			m.wlIfaceNamesToReconfigure.Discard(oldWorkload.Name)
			delete(m.activeWlIfaceNameToID, oldWorkload.Name)
			if m.hasSourceSpoofingConfiguration(oldWorkload.Name) {
				delete(m.sourceSpoofingConfig, oldWorkload.Name)
				m.updateRPFSkipChain()
			}
		}
		delete(m.activeWlEndpoints, id)
	}

	// Repeat the following loop until the pending update map is empty.  Note that it's possible
	// for an endpoint deletion to add a further update into the map (for a previously shadowed
	// endpoint), so we cannot assume that a single iteration will always be enough.
	for len(m.pendingWlEpUpdates) > 0 {
		// Handle pending workload endpoint updates.
		for id, workload := range m.pendingWlEpUpdates {
			logCxt := log.WithField("id", id)
			oldWorkload := m.activeWlEndpoints[id]
			if workload != nil {
				// Check if there is already an active workload endpoint with the same
				// interface name.
				if existingId, ok := m.activeWlIfaceNameToID[workload.Name]; ok && existingId != id {
					// There is.  We need to decide which endpoint takes preference.
					// (We presume this is some kind of make before break logic, and the
					// situation will shortly be resolved by one of the endpoints being
					// removed.  But in the meantime we must have predictable
					// behaviour.)
					logCxt.WithFields(log.Fields{
						"interfaceName": workload.Name,
						"existingId":    existingId,
					}).Info("New endpoint has same iface name as existing")
					if wlIdsAscending(&existingId, &id) {
						logCxt.Info("Existing endpoint takes preference")
						m.shadowedWlEndpoints[id] = workload
						delete(m.pendingWlEpUpdates, id)
						continue
					}
					logCxt.Info("New endpoint takes preference; remove existing")
					m.shadowedWlEndpoints[existingId] = m.activeWlEndpoints[existingId]
					removeActiveWorkload(logCxt, m.activeWlEndpoints[existingId], existingId)
				}
				logCxt.Info("Updating per-endpoint chains.")
				if oldWorkload != nil && oldWorkload.Name != workload.Name {
					logCxt.Debug("Interface name changed, cleaning up old state")
					m.epMarkMapper.ReleaseEndpointMark(oldWorkload.Name)
					if !m.bpfEnabled {
						m.filterTable.RemoveChains(m.activeWlIDToChains[id])
						if m.hasSourceSpoofingConfiguration(oldWorkload.Name) {
							delete(m.sourceSpoofingConfig, workload.Name)
							m.updateRPFSkipChain()
						}
					}
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
				if !m.bpfEnabled {
					chains := m.ruleRenderer.WorkloadEndpointToIptablesChains(
						workload.Name,
						m.epMarkMapper,
						adminUp,
						ingressPolicyNames,
						egressPolicyNames,
						workload.ProfileIds,
					)
					m.filterTable.UpdateChains(chains)
					m.activeWlIDToChains[id] = chains

					if len(workload.AllowSpoofedSourcePrefixes) > 0 && !m.hasSourceSpoofingConfiguration(workload.Name) {
						logCxt.Info("Disabling RPF check for workload")
						m.sourceSpoofingConfig[workload.Name] = workload.AllowSpoofedSourcePrefixes
						m.updateRPFSkipChain()
					} else if m.hasSourceSpoofingConfiguration(workload.Name) && len(workload.AllowSpoofedSourcePrefixes) == 0 {
						logCxt.Info("Enabling RPF check for workload (previously disabled)")
						delete(m.sourceSpoofingConfig, workload.Name)
						m.updateRPFSkipChain()
					}
				}

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
							CIDR:    ip.MustParseCIDROrIP(s),
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

				m.callbacks.InvokeUpdateWorkload(oldWorkload, workload)
			} else {
				logCxt.Info("Workload removed, deleting its chains.")
				removeActiveWorkload(logCxt, oldWorkload, id)
				delete(m.pendingWlEpUpdates, id)
				delete(m.shadowedWlEndpoints, id)

				if oldWorkload != nil {
					// Check for another endpoint with the same interface name,
					// that should now become active.
					bestShadowedId := proto.WorkloadEndpointID{}
					for sId, sWorkload := range m.shadowedWlEndpoints {
						logCxt.Infof("Old workload %v", oldWorkload)
						logCxt.Infof("Shadowed workload %v", sWorkload)
						if sWorkload.Name == oldWorkload.Name {
							if bestShadowedId.EndpointId == "" || wlIdsAscending(&sId, &bestShadowedId) {
								bestShadowedId = sId
							}
						}
					}
					if bestShadowedId.EndpointId != "" {
						m.pendingWlEpUpdates[bestShadowedId] = m.shadowedWlEndpoints[bestShadowedId]
						delete(m.shadowedWlEndpoints, bestShadowedId)
					}
				}
			}

			// Update or deletion, make sure we update the interface status.
			m.epIDsToUpdateStatus.Add(id)
		}
	}

	if !m.bpfEnabled && m.needToCheckDispatchChains {
		// Rewrite the dispatch chains if they've changed.
		newDispatchChains := m.ruleRenderer.WorkloadDispatchChains(m.activeWlEndpoints)
		m.updateDispatchChains(m.activeWlDispatchChains, newDispatchChains, m.filterTable)
		m.needToCheckDispatchChains = false

		// Set flag to update endpoint mark chains.
		m.needToCheckEndpointMarkChains = true
	}

	m.wlIfaceNamesToReconfigure.Iter(func(item interface{}) error {
		ifaceName := item.(string)
		err := m.configureInterface(ifaceName)
		if err != nil {
			if exists, err := m.interfaceExistsInProcSys(ifaceName); err == nil && !exists {
				// Suppress log spam if interface has been removed.
				log.WithError(err).Debug("Failed to configure interface and it seems to be gone")
			} else {
				log.WithError(err).Warn("Failed to configure interface, will retry")
			}
			return nil
		}
		return set.RemoveItem
	})
}

func wlIdsAscending(id1, id2 *proto.WorkloadEndpointID) bool {
	if id1.OrchestratorId == id2.OrchestratorId {
		// Need to compare WorkloadId.
		if id1.WorkloadId == id2.WorkloadId {
			// Need to compare EndpointId.
			return id1.EndpointId < id2.EndpointId
		}
		return id1.WorkloadId < id2.WorkloadId
	}
	return id1.OrchestratorId < id2.OrchestratorId
}

func (m *endpointManager) hasSourceSpoofingConfiguration(interfaceName string) bool {
	_, ok := m.sourceSpoofingConfig[interfaceName]
	return ok
}

func (m *endpointManager) updateRPFSkipChain() {
	log.Debug("Updating RPF skip chain")
	chain := &iptables.Chain{
		Name:  rules.ChainRpfSkip,
		Rules: make([]iptables.Rule, 0),
	}
	for interfaceName, addresses := range m.sourceSpoofingConfig {
		for _, addr := range addresses {
			chain.Rules = append(chain.Rules, iptables.Rule{
				Match:  iptables.Match().InInterface(interfaceName).SourceNet(addr),
				Action: iptables.AcceptAction{},
			})
		}
	}
	m.rawTable.UpdateChain(chain)
}

func (m *endpointManager) resolveEndpointMarks() {
	if m.bpfEnabled {
		return
	}

	// Render endpoint mark chains for active workload and host endpoint.
	newEndpointMarkDispatchChains := m.ruleRenderer.EndpointMarkDispatchChains(m.epMarkMapper, m.activeWlEndpoints, m.activeIfaceNameToHostEpID)
	m.updateDispatchChains(m.activeEPMarkDispatchChains, newEndpointMarkDispatchChains, m.filterTable)
}

func (m *endpointManager) resolveHostEndpoints() map[string]proto.HostEndpointID {

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
	for ifaceName, ifaceAddrs := range m.hostIfaceToAddrs {
		ifaceCxt := log.WithFields(log.Fields{
			"ifaceName":  ifaceName,
			"ifaceAddrs": ifaceAddrs,
		})
		bestHostEpId := proto.HostEndpointID{}
	HostEpLoop:
		for id, hostEp := range m.rawHostEndpoints {
			logCxt := ifaceCxt.WithField("id", id)
			if forAllInterfaces(hostEp) {
				logCxt.Debug("Skip all-interfaces host endpoint")
				continue
			}
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
			logCxt := log.WithFields(log.Fields{
				"ifaceName":    ifaceName,
				"bestHostEpId": bestHostEpId,
			})
			logCxt.Debug("Got HostEp for interface")
			newIfaceNameToHostEpID[ifaceName] = bestHostEpId
		}
	}

	// Similar loop to find the best all-interfaces host endpoint.
	bestHostEpId := proto.HostEndpointID{}
	for id, hostEp := range m.rawHostEndpoints {
		logCxt := log.WithField("id", id)
		if !forAllInterfaces(hostEp) {
			logCxt.Debug("Skip interface-specific host endpoint")
			continue
		}
		if (bestHostEpId.EndpointId != "") && (bestHostEpId.EndpointId < id.EndpointId) {
			// We already have a HostEndpointId that is better than
			// this one, so no point looking any further.
			logCxt.Debug("No better than existing match")
			continue
		}
		logCxt.Debug("New best all-interfaces host endpoint")
		bestHostEpId = id
	}

	if bestHostEpId.EndpointId != "" {
		log.WithField("bestHostEpId", bestHostEpId).Debug("Got all interfaces HostEp")
		newIfaceNameToHostEpID[allInterfaces] = bestHostEpId
	}

	if m.bpfEndpointManager != nil {
		// Construct map of interface names to host endpoints, and pass to the BPF endpoint
		// manager.
		hostIfaceToEpMap := map[string]proto.HostEndpoint{}
		for ifaceName, id := range newIfaceNameToHostEpID {
			// Note, dereference the proto.HostEndpoint here so that the data lifetime
			// is decoupled from the validity of the pointer here.
			hostIfaceToEpMap[ifaceName] = *m.rawHostEndpoints[id]
		}
		m.bpfEndpointManager.OnHEPUpdate(hostIfaceToEpMap)
	}

	return newIfaceNameToHostEpID
}

func (m *endpointManager) updateHostEndpoints() {

	// Calculate filtered name/id maps for untracked and pre-DNAT policy, and a reverse map from
	// each active host endpoint to the interfaces it is in use for.
	newIfaceNameToHostEpID := m.newIfaceNameToHostEpID
	newPreDNATIfaceNameToHostEpID := map[string]proto.HostEndpointID{}
	newUntrackedIfaceNameToHostEpID := map[string]proto.HostEndpointID{}
	newHostEpIDToIfaceNames := map[proto.HostEndpointID][]string{}
	for ifaceName, id := range newIfaceNameToHostEpID {
		logCxt := log.WithField("id", id).WithField("ifaceName", ifaceName)
		ep := m.rawHostEndpoints[id]
		if len(ep.UntrackedTiers) > 0 {
			if ifaceName == allInterfaces {
				// GlobalNetworkPolicy with `doNotTrack: True` has been configured
				// to apply to a host-* endpoint, which is not currently supported.
				// Log and warning and ignore it.
				logCxt.Warning("DoNotTrack policy is not supported for a HEP with `interfaceName: *`; ignoring it")
			} else {
				// Optimisation: only add the endpoint chains to the raw (untracked)
				// table if there's some untracked policy to apply.  This reduces
				// per-packet latency since every packet has to traverse the raw
				// table.
				logCxt.Debug("Endpoint has untracked policies.")
				newUntrackedIfaceNameToHostEpID[ifaceName] = id
			}
		}
		if len(ep.PreDnatTiers) > 0 {
			// Similar optimisation (or neatness) for pre-DNAT policy.
			logCxt.Debug("Endpoint has pre-DNAT policies.")
			newPreDNATIfaceNameToHostEpID[ifaceName] = id
		}
		// Record that this host endpoint is in use, for status reporting.
		newHostEpIDToIfaceNames[id] = append(
			newHostEpIDToIfaceNames[id], ifaceName)

		// Also determine endpoints for which we need to review status.
		oldID, wasKnown := m.activeIfaceNameToHostEpID[ifaceName]
		newID, isKnown := newIfaceNameToHostEpID[ifaceName]
		if oldID != newID {
			logCxt := logCxt.WithFields(log.Fields{
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

	if !m.bpfEnabled {
		// Build iptables chains for normal and apply-on-forward host endpoint policy.
		newHostIfaceFiltChains := map[string][]*iptables.Chain{}
		newHostIfaceMangleEgressChains := map[string][]*iptables.Chain{}
		for ifaceName, id := range newIfaceNameToHostEpID {
			log.WithField("id", id).Info("Updating host endpoint normal policy chains.")
			hostEp := m.rawHostEndpoints[id]

			// Update chains in the filter and mangle tables, for normal traffic.
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
				m.epMarkMapper,
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

			mangleChains := m.ruleRenderer.HostEndpointToMangleEgressChains(
				ifaceName,
				egressPolicyNames,
				hostEp.ProfileIds,
			)
			if !reflect.DeepEqual(mangleChains, m.activeHostIfaceToMangleEgressChains[ifaceName]) {
				m.mangleTable.UpdateChains(mangleChains)
			}
			newHostIfaceMangleEgressChains[ifaceName] = mangleChains
			delete(m.activeHostIfaceToMangleEgressChains, ifaceName)
		}

		// Build iptables chains for pre-DNAT host endpoint policy.
		newHostIfaceMangleIngressChains := map[string][]*iptables.Chain{}
		for ifaceName, id := range newPreDNATIfaceNameToHostEpID {
			log.WithField("id", id).Info("Updating host endpoint mangle ingress chains.")
			hostEp := m.rawHostEndpoints[id]

			// Update the mangle table for preDNAT policy.
			var ingressPolicyNames []string
			if len(hostEp.PreDnatTiers) > 0 {
				ingressPolicyNames = hostEp.PreDnatTiers[0].IngressPolicies
			}
			mangleChains := m.ruleRenderer.HostEndpointToMangleIngressChains(
				ifaceName,
				ingressPolicyNames,
			)
			if !reflect.DeepEqual(mangleChains, m.activeHostIfaceToMangleIngressChains[ifaceName]) {
				m.mangleTable.UpdateChains(mangleChains)
			}
			newHostIfaceMangleIngressChains[ifaceName] = mangleChains
			delete(m.activeHostIfaceToMangleIngressChains, ifaceName)
		}

		// Remove normal, apply-on-forward and pre-DNAT policy iptables chains that are no
		// longer wanted.
		for ifaceName, chains := range m.activeHostIfaceToFiltChains {
			log.WithField("ifaceName", ifaceName).Info(
				"Host interface no longer protected, deleting its normal chains.")
			m.filterTable.RemoveChains(chains)
		}
		for ifaceName, chains := range m.activeHostIfaceToMangleEgressChains {
			log.WithField("ifaceName", ifaceName).Info(
				"Host interface no longer protected, deleting its mangle egress chains.")
			m.mangleTable.RemoveChains(chains)
		}
		for ifaceName, chains := range m.activeHostIfaceToMangleIngressChains {
			log.WithField("ifaceName", ifaceName).Info(
				"Host interface no longer protected, deleting its preDNAT chains.")
			m.mangleTable.RemoveChains(chains)
		}

		m.callbacks.InvokeInterfaceCallbacks(m.activeIfaceNameToHostEpID, newIfaceNameToHostEpID)

		m.activeHostIfaceToFiltChains = newHostIfaceFiltChains
		m.activeHostIfaceToMangleEgressChains = newHostIfaceMangleEgressChains
		m.activeHostIfaceToMangleIngressChains = newHostIfaceMangleIngressChains
	}

	if m.ipVersion == 4 || !m.bpfEnabled {
		// Build iptables chains for untracked host endpoint policy.
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
			var rawChains []*iptables.Chain
			if m.bpfEnabled {
				rawChains = append(rawChains, m.ruleRenderer.HostEndpointToRawEgressChain(
					ifaceName,
					egressPolicyNames,
				))
			} else {
				rawChains = m.ruleRenderer.HostEndpointToRawChains(
					ifaceName,
					ingressPolicyNames,
					egressPolicyNames,
				)
			}
			if !reflect.DeepEqual(rawChains, m.activeHostIfaceToRawChains[ifaceName]) {
				m.rawTable.UpdateChains(rawChains)
			}
			newHostIfaceRawChains[ifaceName] = rawChains
			delete(m.activeHostIfaceToRawChains, ifaceName)
		}

		// Remove untracked policy iptables chains that are no longer wanted.
		for ifaceName, chains := range m.activeHostIfaceToRawChains {
			log.WithField("ifaceName", ifaceName).Info(
				"Host interface no longer protected, deleting its untracked chains.")
			m.rawTable.RemoveChains(chains)
		}

		m.activeHostIfaceToRawChains = newHostIfaceRawChains
	}

	// Remember the host endpoints that are now in use.
	m.activeIfaceNameToHostEpID = newIfaceNameToHostEpID
	m.activeHostEpIDToIfaceNames = newHostEpIDToIfaceNames

	if m.ipVersion == 4 || !m.bpfEnabled {
		// Rewrite the raw dispatch chains if they've changed.  Note, we use iptables for untracked
		// egress policy even in BPF mode.
		log.WithField("resolvedHostEpIds", newUntrackedIfaceNameToHostEpID).Debug("Rewrite raw dispatch chains?")
		var newRawDispatchChains []*iptables.Chain
		if m.bpfEnabled {
			newRawDispatchChains = m.ruleRenderer.ToHostDispatchChains(newUntrackedIfaceNameToHostEpID, "")
		} else {
			newRawDispatchChains = m.ruleRenderer.HostDispatchChains(newUntrackedIfaceNameToHostEpID, "", false)
		}
		m.updateDispatchChains(m.activeHostRawDispatchChains, newRawDispatchChains, m.rawTable)
	}

	if m.bpfEnabled {
		// Code after this point is for other dispatch chains and IPVS endpoint marking,
		// which aren't needed in BPF mode.
		return
	}

	// Rewrite the filter dispatch chains if they've changed.
	log.WithField("resolvedHostEpIds", newIfaceNameToHostEpID).Debug("Rewrite filter dispatch chains?")
	defaultIfaceName := ""
	if _, ok := newIfaceNameToHostEpID[allInterfaces]; ok {
		// All-interfaces host endpoint is active.  Arrange for it to be the default,
		// instead of trying to dispatch to it directly based on the non-existent interface
		// name *.
		defaultIfaceName = allInterfaces
		delete(newIfaceNameToHostEpID, allInterfaces)
	}
	newFilterDispatchChains := m.ruleRenderer.HostDispatchChains(newIfaceNameToHostEpID, defaultIfaceName, true)
	newMangleEgressDispatchChains := m.ruleRenderer.ToHostDispatchChains(newIfaceNameToHostEpID, defaultIfaceName)
	m.updateDispatchChains(m.activeHostFilterDispatchChains, newFilterDispatchChains, m.filterTable)
	// Set flag to update endpoint mark chains.
	m.needToCheckEndpointMarkChains = true

	// Rewrite the mangle dispatch chains if they've changed.
	log.WithField("resolvedHostEpIds", newPreDNATIfaceNameToHostEpID).Debug("Rewrite mangle dispatch chains?")
	defaultIfaceName = ""
	if _, ok := newPreDNATIfaceNameToHostEpID[allInterfaces]; ok {
		// All-interfaces host endpoint is active.  Arrange for it to be the
		// default. This is handled the same as the filter dispatch chains above.
		defaultIfaceName = allInterfaces
		delete(newPreDNATIfaceNameToHostEpID, allInterfaces)
	}
	newMangleIngressDispatchChains := m.ruleRenderer.FromHostDispatchChains(newPreDNATIfaceNameToHostEpID, defaultIfaceName)
	newMangleDispatchChains := append(newMangleIngressDispatchChains, newMangleEgressDispatchChains...)
	m.updateDispatchChains(m.activeHostMangleDispatchChains, newMangleDispatchChains, m.mangleTable)

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

func (m *endpointManager) interfaceExistsInProcSys(name string) (bool, error) {
	var directory string
	if m.ipVersion == 4 {
		directory = fmt.Sprintf("/proc/sys/net/ipv4/conf/%s", name)
	} else {
		directory = fmt.Sprintf("/proc/sys/net/ipv6/conf/%s", name)
	}
	_, err := m.osStat(directory)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func configureInterface(name string, ipVersion int, rpFilter string, writeProcSys procSysWriter) error {
	log.WithField("ifaceName", name).Info(
		"Applying /proc/sys configuration to interface.")
	if ipVersion == 4 {
		// Enable routing to localhost.  This is required to allow for NAT to the local
		// host.
		err := writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", name), "1")
		if err != nil {
			return err
		}
		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", name), "0")
		if err != nil {
			log.Warnf("failed to set net.ipv4.neigh.%s.proxy_delay=0: %s", name, err)
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
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", name), "1")
		if err != nil {
			return err
		}
		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", name), "1")
		if err != nil {
			return err
		}
		// Disable kernel rpf check for interfaces that have rpf filtering explicitely disabled
		// This is set only in IPv4 mode as there's no equivalent sysctl in IPv6
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", name), rpFilter)
		if err != nil {
			return err
		}
	} else {
		// Enable proxy NDP, similarly to proxy ARP, described above.
		err := writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", name), "1")
		if err != nil {
			return err
		}
		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", name), "1")
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *endpointManager) configureInterface(name string) error {
	if !m.activeUpIfaces.Contains(name) {
		log.WithField("ifaceName", name).Info(
			"Skipping configuration of interface because it is oper down.")
		return nil
	}

	// Special case: for security, even if our IPv6 support is disabled, try to disable RAs on the interface.
	acceptRAPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", name)
	err := m.writeProcSys(acceptRAPath, "0")
	if err != nil {
		if exists, err2 := m.interfaceExistsInProcSys(name); err2 == nil && !exists {
			log.WithField("file", acceptRAPath).Debug(
				"Failed to set accept_ra flag. Interface is missing in /proc/sys.")
		} else {
			if err2 != nil {
				log.WithError(err2).Error("Error checking if interface exists")
			}
			log.WithError(err).WithField("ifaceName", name).Warnf("Could not set accept_ra")
		}
	}

	rpFilter := m.defaultRpFilter
	if m.hasSourceSpoofingConfiguration(name) {
		rpFilter = "0"
	}

	return configureInterface(name, int(m.ipVersion), rpFilter, m.writeProcSys)
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

// The interface name that we use to mean "all interfaces".  This is intentionally longer than
// IFNAMSIZ (16) characters, so that it can't possibly match a real interface name.
var allInterfaces = "any-interface-at-all"

// True if the given host endpoint is for all interfaces, as opposed to for a specific interface.
func forAllInterfaces(hep *proto.HostEndpoint) bool {
	return hep.Name == "*"
}

// for implementing the endpointsSource interface
func (m *endpointManager) GetRawHostEndpoints() map[proto.HostEndpointID]*proto.HostEndpoint {
	return m.rawHostEndpoints
}
