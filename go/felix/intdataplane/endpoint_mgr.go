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
	"os"
	"reflect"
	"regexp"
	"strings"
)

type endpointManager struct {
	ipVersion       int
	ourIfacesRegexp *regexp.Regexp

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
}

func newEndpointManager(
	filterTable *iptables.Table,
	ruleRenderer rules.RuleRenderer,
	routeTable *routetable.RouteTable,
	ipVersion int,
	ourInterfacePrefixes []string,
) *endpointManager {
	ourIfacesPattern := "^(" + strings.Join(ourInterfacePrefixes, "|") + ").*"
	ourIfacesRegexp := regexp.MustCompile(ourIfacesPattern)

	return &endpointManager{
		ipVersion:       ipVersion,
		ourIfacesRegexp: ourIfacesRegexp,

		filterTable:  filterTable,
		ruleRenderer: ruleRenderer,
		routeTable:   routeTable,

		activeEndpoints:  map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		activeUpIfaces:   set.New(),
		activeIdToChains: map[proto.WorkloadEndpointID][]*iptables.Chain{},

		activeIfacesNeedingConfig: set.New(),

		pendingEndpointUpdates: map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		pendingIfaceUpdates:    map[string]ifacemonitor.State{},
	}
}

func (m *endpointManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		m.pendingEndpointUpdates[*msg.Id] = msg.Endpoint
	case *proto.WorkloadEndpointRemove:
		m.pendingEndpointUpdates[*msg.Id] = nil
	case *proto.HostEndpointUpdate:
		// TODO(smc) Host endpoint updates
		log.WithField("msg", msg).Warn("Message not implemented")
	case *proto.HostEndpointRemove:
		// TODO(smc) Host endpoint updates
		log.WithField("msg", msg).Warn("Message not implemented")
	case *ifaceUpdate:
		log.WithField("update", msg).Debug("Interface state changed.")
		if !m.ourIfacesRegexp.MatchString(msg.Name) {
			log.WithField("update", msg).Debug("Not our interface, ignoring.")
			return
		}
		m.pendingIfaceUpdates[msg.Name] = msg.State
	}
}

func (m *endpointManager) CompleteDeferredWork() error {
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
			ipNets := make([]ip.CIDR, len(ipStrings))
			for i, s := range ipStrings {
				ipNets[i] = ip.MustParseCIDR(s)
			}
			if oldWorkload != nil && oldWorkload.Name != workload.Name {
				logCxt.Debug("Interface name changed, cleaning up old routes")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
				m.activeIfacesNeedingConfig.Discard(oldWorkload.Name)
			}
			m.routeTable.SetRoutes(workload.Name, ipNets)
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

	m.activeIfacesNeedingConfig.Iter(func(item interface{}) error {
		ifaceName := item.(string)
		err := m.configureInterface(ifaceName)
		if err != nil {
			log.WithError(err).Warn("Failed to configure interface, will retry")
			return nil
		}
		return set.RemoveItem
	})

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
