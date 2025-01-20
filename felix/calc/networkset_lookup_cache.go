// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeNetworkSetCacheLength = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_collector_lookupcache_networksets",
		Help: "Total number of entries currently residing in the network set lookup cache.",
	})
)

func init() {
	prometheus.MustRegister(gaugeNetworkSetCacheLength)
}

type networkSetData struct {
	cidrs        set.Set[ip.CIDR]
	endpointData *EndpointData
}

// Networkset data is stored in the EndpointData object for easier type processing for flow logs.
type NetworkSetLookupsCache struct {
	nsMutex     sync.RWMutex
	networkSets map[model.Key]*networkSetData
	ipTree      *IpTrie
}

func NewNetworkSetLookupsCache() *NetworkSetLookupsCache {
	nc := &NetworkSetLookupsCache{
		nsMutex: sync.RWMutex{},

		// NetworkSet data.
		networkSets: make(map[model.Key]*networkSetData),

		// Reverse lookups by CIDR and egress domain.
		ipTree: NewIpTrie(),
	}

	return nc
}

func (nc *NetworkSetLookupsCache) RegisterWith(allUpdateDispatcher *dispatcher.Dispatcher) {
	allUpdateDispatcher.Register(model.NetworkSetKey{}, nc.OnUpdate)
}

// OnUpdate is the callback method registered with the AllUpdatesDispatcher for
// the model.NetworkSet type. This method updates the mapping between networkSets
// and the corresponding CIDRs that they contain.
func (nc *NetworkSetLookupsCache) OnUpdate(nsUpdate api.Update) (_ bool) {
	switch k := nsUpdate.Key.(type) {
	case model.NetworkSetKey:
		if nsUpdate.Value == nil {
			nc.removeNetworkSet(k)
		} else {
			networkset := nsUpdate.Value.(*model.NetworkSet)
			nc.addOrUpdateNetworkset(&networkSetData{
				endpointData: &EndpointData{
					Key:        k,
					Networkset: nsUpdate.Value,
				},
				cidrs: set.FromArray(ip.CIDRsFromCalicoNets(networkset.Nets)),
			})
		}
	default:
		log.Infof("ignoring unexpected update: %v %#v",
			reflect.TypeOf(nsUpdate.Key), nsUpdate)
		return
	}
	log.Infof("Updating networkset cache with networkset data %v", nsUpdate.Key)
	return
}

// addOrUpdateNetworkset tracks networkset to CIDR mapping as well as the reverse
// mapping from CIDR to networkset.
func (nc *NetworkSetLookupsCache) addOrUpdateNetworkset(data *networkSetData) {
	// If the networkset exists, it was updated, then we might have to add or
	// remove CIDRs and allowed egress domains.
	nc.nsMutex.Lock()
	defer nc.nsMutex.Unlock()

	currentData, exists := nc.networkSets[data.endpointData.Key]
	if currentData == nil {
		currentData = &networkSetData{
			cidrs: set.New[ip.CIDR](),
		}
	}
	nc.networkSets[data.endpointData.Key] = data

	set.IterDifferences[ip.CIDR](data.cidrs, currentData.cidrs,
		// In new, not current.  Add new entry to mappings.
		func(newCIDR ip.CIDR) error {
			nc.ipTree.InsertKey(newCIDR, data.endpointData.Key)
			return nil
		},
		// In current, not new.  Remove old entry from mappings.
		func(oldCIDR ip.CIDR) error {
			nc.ipTree.DeleteKey(oldCIDR, data.endpointData.Key)
			return nil
		},
	)
	if !exists {
		nc.reportNetworksetCacheMetrics()
	}
}

// removeNetworkSet removes the networkset from the NetworksetLookupscache.networkSets map
// and also removes all corresponding CIDR to networkset mappings as well.
// This method should acquire (and release) the NetworkSetLookupsCache.nsMutex before (and after)
// manipulating the maps.
func (nc *NetworkSetLookupsCache) removeNetworkSet(key model.Key) {
	nc.nsMutex.Lock()
	defer nc.nsMutex.Unlock()
	currentData, ok := nc.networkSets[key]
	if !ok {
		// We don't know about this networkset. Nothing to do.
		return
	}
	currentData.cidrs.Iter(func(oldCIDR ip.CIDR) error {
		nc.ipTree.DeleteKey(oldCIDR, key)
		return nil
	})
	delete(nc.networkSets, key)
	nc.reportNetworksetCacheMetrics()
}

// GetNetworkSetFromIP finds Longest Prefix Match CIDR from given IP ADDR and return last observed
// Networkset for that CIDR
func (nc *NetworkSetLookupsCache) GetNetworkSetFromIP(addr [16]byte) (ed *EndpointData, ok bool) {
	nc.nsMutex.RLock()
	defer nc.nsMutex.RUnlock()
	// Find the first cidr that contains the ip address to use for the lookup.
	ipAddr := ip.FromNetIP(net.IP(addr[:]))
	if key, _ := nc.ipTree.GetLongestPrefixCidr(ipAddr); key != nil {
		if ns := nc.networkSets[key]; ns != nil {
			// Found a NetworkSet, so set the return variables.
			ed = ns.endpointData
			ok = true
		}
	}
	return
}

func (nc *NetworkSetLookupsCache) DumpNetworksets() string {
	nc.nsMutex.RLock()
	defer nc.nsMutex.RUnlock()
	lines := nc.ipTree.DumpCIDRKeys()
	lines = append(lines, "-------")
	for key, ns := range nc.networkSets {
		cidrStr := []string{}
		ns.cidrs.Iter(func(cidr ip.CIDR) error {
			cidrStr = append(cidrStr, cidr.String())
			return nil
		})
		domainStr := []string{}
		lines = append(lines,
			key.(model.NetworkSetKey).Name,
			"   cidrs: "+strings.Join(cidrStr, ","),
			" domains: "+strings.Join(domainStr, ","),
		)
	}
	return strings.Join(lines, "\n")
}

// reportNetworksetCacheMetrics reports networkset cache performance metrics to prometheus
func (nc *NetworkSetLookupsCache) reportNetworksetCacheMetrics() {
	gaugeNetworkSetCacheLength.Set(float64(len(nc.networkSets)))
}
