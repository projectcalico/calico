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
	kapiv1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// LookupsCache provides an API to do the following:
// - lookup endpoint information given an IP
// - lookup policy/profile information given the NFLOG prefix
//
// To do this, the LookupsCache uses two caches to hook into the
// calculation graph at various stages
// - EndpointLookupsCache
// - PolicyLookupsCache
type LookupsCache struct {
	polCache *PolicyLookupsCache
	epCache  *EndpointLookupsCache
	nsCache  *NetworkSetLookupsCache
	svcCache *ServiceLookupsCache
}

func NewLookupsCache() *LookupsCache {
	lc := &LookupsCache{
		polCache: NewPolicyLookupsCache(),
		epCache:  NewEndpointLookupsCache(),
		nsCache:  NewNetworkSetLookupsCache(),
		svcCache: NewServiceLookupsCache(),
	}
	return lc
}

// GetEndpoint returns the ordered list of tiers for a particular endpoint.
func (lc *LookupsCache) GetEndpoint(addr [16]byte) (EndpointData, bool) {
	return lc.epCache.GetEndpoint(addr)
}

// GetEndpointKeys returns all endpoint keys that the cache is tracking.
// Convenience method only used for testing purposes.
func (lc *LookupsCache) GetEndpointKeys() []model.Key {
	return lc.epCache.GetEndpointKeys()
}

// GetAllEndpointData returns all endpoint data that the cache is tracking.
// Convenience method only used for testing purposes.
func (lc *LookupsCache) GetAllEndpointData() []EndpointData {
	return lc.epCache.GetAllEndpointData()
}

// GetNode returns the node configured with the supplied address. This matches against one of the following:
// - The node IP address
// - The node IPIP tunnel address
// - The node VXLAN tunnel address
// - The node wireguard tunnel address
func (lc *LookupsCache) GetNode(addr [16]byte) (string, bool) {
	return lc.epCache.GetNode(addr)
}

// GetNetworkSet returns the networkset information for an address.
// It returns the first networkset it finds that contains the given address.
func (lc *LookupsCache) GetNetworkSet(addr [16]byte) (EndpointData, bool) {
	return lc.nsCache.GetNetworkSetFromIP(addr)
}

// GetNetworkSetWithNamespace returns the NetworkSet information for an address with namespace
// precedence. If preferredNamespace is provided, NetworkSets in that namespace are prioritized.
func (lc *LookupsCache) GetNetworkSetWithNamespace(addr [16]byte, preferredNamespace string) (EndpointData, bool) {
	return lc.nsCache.GetNetworkSetFromIPWithNamespace(addr, preferredNamespace)
}

// IsEndpointDeleted returns whether the given endpoint is marked for deletion.
func (lc *LookupsCache) IsEndpointDeleted(ep EndpointData) bool {
	return lc.epCache.IsEndpointDeleted(ep)
}

// MarkEndpointDeleted marks an endpoint as deleted for testing purposes.
// This should not be called from any mainline code.
func (lc *LookupsCache) MarkEndpointDeleted(ep EndpointData) {
	lc.epCache.MarkEndpointForDeletion(ep)
}

// GetRuleIDFromNFLOGPrefix returns the RuleID associated with the supplied NFLOG prefix.
func (lc *LookupsCache) GetRuleIDFromNFLOGPrefix(prefix [64]byte) *RuleID {
	return lc.polCache.GetRuleIDFromNFLOGPrefix(prefix)
}

// GetRuleIDFromID64 returns the RuleID associated with the supplied 64bit ID.
func (lc *LookupsCache) GetRuleIDFromID64(id uint64) *RuleID {
	return lc.polCache.GetRuleIDFromID64(id)
}

// GetID64FromNFLOGPrefix returns the 64 bit ID associated with the supplied NFLOG prefix.
func (lc *LookupsCache) GetID64FromNFLOGPrefix(prefix [64]byte) uint64 {
	return lc.polCache.GetID64FromNFLOGPrefix(prefix)
}

// EnableID64 make the PolicyLookupsCache to also generate 64bit IDs for each
// NFLOGPrefix. Once turned on, cannot be turned off.
func (lc *LookupsCache) EnableID64() {
	lc.polCache.SetUseIDs()
}

// GetServiceFromPreNATDest looks up a service by cluster/external IP.
func (lc *LookupsCache) GetServiceFromPreDNATDest(ipPreDNAT [16]byte, portPreDNAT int, proto int) (proxy.ServicePortName, bool) {
	return lc.svcCache.GetServiceFromPreDNATDest(ipPreDNAT, portPreDNAT, proto)
}

// GetNodePortService looks up a service by port and protocol (assuming a node IP).
func (lc *LookupsCache) GetNodePortService(port int, proto int) (proxy.ServicePortName, bool) {
	return lc.svcCache.GetNodePortService(port, proto)
}

func (lc *LookupsCache) GetServiceSpecFromResourceKey(key model.ResourceKey) (kapiv1.ServiceSpec, bool) {
	return lc.svcCache.GetServiceSpecFromResourceKey(key)
}

// SetMockData fills in some of the data structures for use in the test code. This should not
// be called from any mainline code.
func (lc *LookupsCache) SetMockData(
	em map[[16]byte]EndpointData,
	nm map[[64]byte]*RuleID,
	ns map[model.NetworkSetKey]*model.NetworkSet,
	svcs map[model.ResourceKey]*kapiv1.Service,
) {
	for ip, ed := range em {
		if ed == nil {
			delete(lc.epCache.ipToEndpoints, ip)
		} else {
			lc.epCache.ipToEndpoints[ip] = []endpointData{ed.(endpointData)}
		}
	}
	for id, rid := range nm {
		if rid == nil {
			delete(lc.polCache.nflogPrefixHash, id)
		} else {
			lc.polCache.nflogPrefixHash[id] = pcRuleID{ruleID: rid}
		}
	}
	for k, v := range ns {
		lc.nsCache.OnUpdate(api.Update{KVPair: model.KVPair{Key: k, Value: v}})
	}
	for k, v := range svcs {
		lc.svcCache.OnResourceUpdate(api.Update{KVPair: model.KVPair{Key: k, Value: v}})
	}
}
