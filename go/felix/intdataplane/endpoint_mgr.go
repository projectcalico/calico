// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	ipVersion      int
	wlIfacesRegexp *regexp.Regexp

	// Our dependencies.
	filterTable  *iptables.Table
	ruleRenderer rules.RuleRenderer
	routeTable   *routetable.RouteTable

	// Active state, updated in CompleteDeferredWork.
	activeEndpoints      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	activeUpIfaces       set.Set
	activeIdToChains     map[proto.WorkloadEndpointID][]*iptables.Chain
	activeDispatchChains []*iptables.Chain

	activeIfacesNeedingConfig set.Set

	// Pending updates, cleared in CompleteDeferredWork.
	pendingEndpointUpdates map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	pendingIfaceUpdates    map[string]ifacemonitor.State

	// Host endpoint processing.
	ifaceAddrs               map[string][]string
	rawHostEndpoints         map[proto.HostEndpointID]*proto.HostEndpoint
	dirtyHostEndpoints       bool
	activeHostIdToChains     map[*proto.HostEndpointID][]*iptables.Chain
	activeHostDispatchChains []*iptables.Chain
}

func newEndpointManager(
	filterTable *iptables.Table,
	ruleRenderer rules.RuleRenderer,
	routeTable *routetable.RouteTable,
	ipVersion int,
	ourInterfacePrefixes []string,
) *endpointManager {
	wlIfacesPattern := "^(" + strings.Join(ourInterfacePrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	return &endpointManager{
		ipVersion:      ipVersion,
		wlIfacesRegexp: wlIfacesRegexp,

		filterTable:  filterTable,
		ruleRenderer: ruleRenderer,
		routeTable:   routeTable,

		activeEndpoints:  nil,
		activeUpIfaces:   set.New(),
		activeIdToChains: nil,

		activeIfacesNeedingConfig: set.New(),

		pendingEndpointUpdates:   make(map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint),
		pendingIfaceUpdates:      make(map[string]ifacemonitor.State),
		ifaceAddrs:               make(map[string][]string),
		rawHostEndpoints:         make(map[proto.HostEndpointID]*proto.HostEndpoint),
		dirtyHostEndpoints:       true,
		activeHostIdToChains:     make(map[*proto.HostEndpointID][]*iptables.Chain),
		activeHostDispatchChains: nil,
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
		m.ifaceAddrs[msg.Name] = msg.Addrs
		m.dirtyHostEndpoints = true
	}
}

func (m *endpointManager) CompleteDeferredWork() error {
	for ifaceName, state := range m.pendingIfaceUpdates {
		if state == ifacemonitor.StateUp {
			m.activeUpIfaces.Add(ifaceName)
			m.activeIfacesNeedingConfig.Add(ifaceName)
		} else {
			m.activeUpIfaces.Discard(ifaceName)
		}
	}

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
				logCxt.Debug("Interface name changed, cleaning up old routes")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
				m.activeIfacesNeedingConfig.Discard(oldWorkload.Name)
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
			m.activeIfacesNeedingConfig.Add(workload.Name)
			m.activeEndpoints[id] = workload
			delete(m.pendingEndpointUpdates, id)
		} else {
			logCxt.Info("Workload removed, deleting its chains.")
			m.filterTable.RemoveChains(m.activeIdToChains[id])
			if oldWorkload := m.activeEndpoints[id]; oldWorkload != nil {
				logCxt.Info("Workload removed, deleting its routes.")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
				m.activeIfacesNeedingConfig.Discard(oldWorkload.Name)
			}
			delete(m.activeEndpoints, id)
			delete(m.pendingEndpointUpdates, id)
		}
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

	m.activeIfacesNeedingConfig.Iter(func(item interface{}) error {
		ifaceName := item.(string)
		err := m.configureInterface(ifaceName)
		if err != nil {
			log.WithError(err).Warn("Failed to configure interface, will retry")
			return nil
		}
		return set.RemoveItem
	})

	if m.dirtyHostEndpoints {
		err := m.resolveHostEndpoints()
		if err != nil {
			log.WithError(err).Warn("Failed to resolve host endpoints")
			return err
		}
		m.dirtyHostEndpoints = false
	}

	return nil
}

func (m *endpointManager) resolveHostEndpoints() error {

	// Host endpoint resolution
	// ------------------------
	//
	// There is a set of non-workload interfaces on the local host, each
	// possibly with IP addresses, that might be controlled by HostEndpoint
	// resources in the Calico data model.  The data model syntactically
	// allows multiple HostEndpoint resources to match a given interface -
	// for example, an interface 'eth1' might have address 10.240.0.34 and
	// 172.19.2.98, and the data model might include:
	//
	// - HostEndpoint A with Name 'eth1'
	//
	// - HostEndpoint B with ExpectedIpv4Addrs including '10.240.0.34'
	//
	// - HostEndpoint C with ExpectedIpv4Addrs including '172.19.2.98'.
	//
	// but at one runtime, at any given time, we only allow one HostEndpoint
	// to govern that interface.  That HostEndpoint becomes the active one,
	// and the others remain inactive.  (But if, for example, the active
	// HostEndpoint resource was deleted, then one of the inactive ones
	// could take over.)  Given multiple matching HostEndpoint resources,
	// the one that wins is the one with the alphabetically earliest
	// HostEndpointId
	//
	// So the process here is not about 'resolving' a particular
	// HostEndpoint on its own.  Rather it is looking at the set of local
	// non-workload interfaces and seeing which of them are matched by
	// the current set of HostEndpoints as a whole.
	var resolvedHostEpIds map[string]*proto.HostEndpointID = nil
	for ifaceName, ifaceAddrs := range m.ifaceAddrs {
		var bestHostEpId *proto.HostEndpointID = nil
	HostEpLoop:
		for id, hostEp := range m.rawHostEndpoints {
			logCxt := log.WithField("id", id)
			if (bestHostEpId != nil) && (bestHostEpId.EndpointId < id.EndpointId) {
				// We already have a HostEndpointId that is
				// better than this one, so no point looking any
				// further.
				logCxt.Debug("No better than existing match")
				continue
			}
			if hostEp.Name == ifaceName {
				// The HostEndpoint has an explicit name that
				// matches the interface.
				logCxt.Debug("Match on explicit iface name")
				bestHostEpId = &id
				continue
			} else if hostEp.Name != "" {
				// The HostEndpoint has an explicit name that
				// isn't this interface.  Continue, so as not to
				// allow it to match on an IP address instead.
				logCxt.Debug("Rejected on explicit iface name")
				continue
			}
			for wanted := range append(hostEp.ExpectedIpv4Addrs, hostEp.ExpectedIpv6Addrs...) {
				for actual := range ifaceAddrs {
					if wanted == actual {
						// The HostEndpoint expects an
						// IP address that is on this
						// interface.
						logCxt.Debug("Match on address")
						bestHostEpId = &id
						continue HostEpLoop
					}
				}
			}
		}
		if bestHostEpId != nil {
			resolvedHostEpIds[ifaceName] = bestHostEpId
		}
	}

	// Set up programming for the host endpoints that are now to be used.
	var newHostEpChains map[*proto.HostEndpointID][]*iptables.Chain = nil
	for _, id := range resolvedHostEpIds {
		log.WithField("id", id).Info("Updating per-endpoint chains.")
		hostEp := m.rawHostEndpoints[*id]
		chains := m.ruleRenderer.HostEndpointToIptablesChains(id, hostEp)
		m.filterTable.UpdateChains(chains)
		newHostEpChains[id] = chains
		delete(m.activeHostIdToChains, id)
	}

	// Remove programming for host endpoints that are not now in use.
	for id, chains := range m.activeHostIdToChains {
		log.WithField("id", id).Info("HostEp removed, deleting its chains.")
		m.filterTable.RemoveChains(chains)
	}

	// Remember the host endpoints that are now in use.
	m.activeHostIdToChains = newHostEpChains

	// Rewrite the dispatch chains if they've changed.
	// TODO(smc) avoid re-rendering chains if nothing has changed.  (Slightly tricky because
	// the dispatch chains depend on the interface names and maybe later the IPs in the data.)
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
	if m.ipVersion == 4 {
		// TODO(smc) Retry, don't panic!
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
