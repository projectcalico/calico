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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/stringutils"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	endpointDataTTLAfterMarkedAsRemovedSeconds = 2 * config.DefaultConntrackPollingInterval
)

var gaugeEndpointCacheLength = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "felix_collector_lookupcache_endpoints",
	Help: "Total number of entries currently residing in the endpoints lookup cache.",
})

func init() {
	prometheus.MustRegister(gaugeEndpointCacheLength)
}

// ===== A note on data structures for storing policy matches =====
//
// We store the various nflog matches that we need to report as a metric update in a flattened slice.
//
// For each tier, we need to store at most a match for each staged policy *and* and a verdict match (for end-of-tier
// drop, or policy match for policy after all staged policies).
//     SP1 SP2 ... SPn EOTD
//
// Suppose we have a tier that contains the following:
//     P1 P2 SP1 SP2 P3 SP3 P4 SP4 SP5
//
// We need 5 buckets to contain all possible results of the tier.
// If we match any of the real policies P1-P4, then we cannot match any of the staged policies after that point. We
// can use n (the nth staged policy) as the index into this tiers set results, and for each real policy match
// we assign it the index of the next staged policy.
//
// So, in the above example, the offset for this tier, into the full set of policy matches would be:
//     P1 P2 SP1 SP2 P3 SP3 P4 SP4 SP5 <EOTD or EOTP>
//      0  0   0   1  2   2  3   3   4              5    <- The "policy match index"
//
// e.g. in position 2, we can have a result from either P3 or SP3. If the result is P3 then we do not need to consider
//      the data in position 3, 4 or 5 - that is because P3 is an enforced policy and so none of the subsequent
//      policies in the tier can be hit.
//
// In the event of an end-of-tier-pass (i.e. the tier contains only staged policies), any staged policy that has not had
// an explicit hit, will be recorded as an end-of-tier drop for that policy. This is effectively the outcome *should*
// the staged policy be enforced.
//
// With multiple tiers, the policy match index increments across the ordered set of tiers.

type EndpointData struct {
	Key model.Key

	// Whether the endpoint is local or not.
	IsLocal bool

	// Ingress and egress match data.
	Ingress *MatchData
	Egress  *MatchData

	// EndpointData will have either an Endpoint OR a Networkset.
	// The networkset will only be set in the EndpointData if an
	// endpoint for the IP is not found.
	Endpoint   interface{}
	Networkset interface{}

	// used for deleting an EndpointData, to delegate the actual
	// deletion endpointDataTTLAfterMarkedAsRemovedSeconds later
	markedToBeDeleted bool
}

type MatchData struct {
	// The map of policy ID to match index.
	PolicyMatches map[PolicyID]int

	// The map of tier to end-of-tier match index.
	TierData map[string]*TierData

	// The profile match index.
	ProfileMatchIndex int
}

type TierData struct {
	// ImplicitDropRuleID is used to track the last policy in each tier that
	// selected this endpoint. This special RuleID is created so that implicitly
	// dropped packets in each tier can be counted against these policies as
	// being responsible for denying the packet.
	//
	// May be set to nil if the tier only contains staged policies.
	ImplicitDropRuleID *RuleID

	// The index into the policy match slice that the implicit drop rule is added. This is always the last
	// index for this tier and equal to FirstPolicyMatchIndex+len(StagedPolicyImplicitDropRuleIDs).
	EndOfTierMatchIndex int
}

// EndpointLookupsCache provides an API to lookup endpoint information given
// an IP address.
//
// To do this, the EndpointLookupsCache hooks into the calculation graph
// by handling callbacks for updated local endpoint tier information.
//
// It also functions as a node that is part of the calculation graph
// to handle remote endpoint information. To do this, it registers
// with the remote endpoint dispatcher and updates the endpoint
// cache appropriately.
type EndpointLookupsCache struct {
	epMutex       sync.RWMutex
	endpointData  map[model.Key]*EndpointData
	ipToEndpoints map[[16]byte][]*EndpointData

	endpointDeletionTimers map[model.Key]*time.Timer

	// Node relationship data.
	// TODO(rlb): We should just treat this as an endpoint
	nodes         map[string]v3.NodeSpec
	nodeIPToNames map[[16]byte][]string
}

func NewEndpointLookupsCache() *EndpointLookupsCache {
	ec := &EndpointLookupsCache{
		epMutex:       sync.RWMutex{},
		ipToEndpoints: map[[16]byte][]*EndpointData{},
		endpointData:  map[model.Key]*EndpointData{},

		endpointDeletionTimers: map[model.Key]*time.Timer{},
		nodeIPToNames:          make(map[[16]byte][]string),
		nodes:                  make(map[string]v3.NodeSpec),
	}

	return ec
}

func (ec *EndpointLookupsCache) RegisterWith(
	allUpdateDisp *dispatcher.Dispatcher,
	remoteEndpointDispatcher *dispatcher.Dispatcher,
) {
	remoteEndpointDispatcher.Register(model.WorkloadEndpointKey{}, ec.OnUpdate)
	remoteEndpointDispatcher.Register(model.HostEndpointKey{}, ec.OnUpdate)
	allUpdateDisp.Register(model.ResourceKey{}, ec.OnResourceUpdate)
}

// OnEndpointTierUpdate is called by the PolicyResolver when it figures out tiers that apply
// to an endpoint. This method tracks local endpoint (model.WorkloadEndpoint and model.HostEndpoint)
// and corresponding IP address relationship. The difference between this handler and the OnUpdate
// handler (below) is this method records tier information for local endpoints while this information
// is ignored for remote endpoints.
func (ec *EndpointLookupsCache) OnEndpointTierUpdate(key model.Key, ep interface{}, filteredTiers []TierInfo) {
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		if ep == nil {
			ec.removeEndpointWithDelay(k)
		} else {
			endpoint := ep.(*model.WorkloadEndpoint)
			ed := ec.CreateEndpointData(key, ep, filteredTiers)
			ec.addOrUpdateEndpoint(k, ed, extractIPsFromWorkloadEndpoint(endpoint))
		}
	case model.HostEndpointKey:
		if ep == nil {
			ec.removeEndpointWithDelay(k)
		} else {
			endpoint := ep.(*model.HostEndpoint)
			ed := ec.CreateEndpointData(key, ep, filteredTiers)
			ec.addOrUpdateEndpoint(k, ed, extractIPsFromHostEndpoint(endpoint))
		}
	}
	log.Infof("Updating endpoint cache with local endpoint data %v", key)
}

// CreateEndpointData creates the endpoint data based on tier
func (ec *EndpointLookupsCache) CreateEndpointData(key model.Key, ep interface{}, filteredTiers []TierInfo) *EndpointData {
	ed := &EndpointData{
		Key:      key,
		Endpoint: ep,
		IsLocal:  true,
		Ingress: &MatchData{
			PolicyMatches:     make(map[PolicyID]int),
			TierData:          make(map[string]*TierData),
			ProfileMatchIndex: -1,
		},
		Egress: &MatchData{
			PolicyMatches:     make(map[PolicyID]int),
			TierData:          make(map[string]*TierData),
			ProfileMatchIndex: -1,
		},
	}
	var policyMatchIdxIngress, policyMatchIdxEgress int
	for _, ti := range filteredTiers {
		if len(ti.OrderedPolicies) == 0 {
			continue
		}
		tdIngress := &TierData{}
		tdEgress := &TierData{}
		var hasIngress, hasEgress bool
		for _, pol := range ti.OrderedPolicies {
			namespace, tier, name, err := deconstructPolicyName(pol.Key.Name)
			if err != nil {
				log.WithError(err).Error("Unable to parse policy name")
				continue
			}
			if pol.GovernsIngress() {
				// Add a ingress implicit drop lookup..
				rid := NewRuleID(tier, name, namespace, RuleIDIndexImplicitDrop,
					rules.RuleDirIngress, rules.RuleActionDeny)
				ed.Ingress.PolicyMatches[rid.PolicyID] = policyMatchIdxIngress

				if model.PolicyIsStaged(pol.Key.Name) {
					// Increment the match index. We don't do this for non-staged policies because they replace the
					// subsequent staged policy in the results.
					policyMatchIdxIngress++
				} else {
					// This is a non-staged policy, update our end-of-tier match.
					tdIngress.ImplicitDropRuleID = rid
				}
				hasIngress = true
			}
			if pol.GovernsEgress() {
				// Add a egress implicit drop lookup..
				rid := NewRuleID(tier, name, namespace, RuleIDIndexImplicitDrop,
					rules.RuleDirEgress, rules.RuleActionDeny)
				ed.Egress.PolicyMatches[rid.PolicyID] = policyMatchIdxEgress

				if model.PolicyIsStaged(pol.Key.Name) {
					// Increment the match index. We don't do this for non-staged policies because they replace the
					// subsequent staged policy in the results.
					policyMatchIdxEgress++
				} else {
					// This is a non-staged policy, update our end-of-tier match.
					tdEgress.ImplicitDropRuleID = rid
				}
				hasEgress = true
			}
		}

		// If there were any policies then set the end-of-tier match index and add the tier lookup.
		if hasIngress {
			tdIngress.EndOfTierMatchIndex = policyMatchIdxIngress
			policyMatchIdxIngress++
			ed.Ingress.TierData[ti.Name] = tdIngress
		}
		if hasEgress {
			tdEgress.EndOfTierMatchIndex = policyMatchIdxEgress
			policyMatchIdxEgress++
			ed.Egress.TierData[ti.Name] = tdEgress
		}
	}

	// Update the profile match index.
	ed.Ingress.ProfileMatchIndex = policyMatchIdxIngress
	ed.Egress.ProfileMatchIndex = policyMatchIdxEgress

	return ed
}

// OnUpdate is the callback method registered with the RemoteEndpointDispatcher for
// model.WorkloadEndpoint and model.HostEndpoint types. This method updates the
// mapping between an remote endpoint and all the IPs that the endpoint contains.
// The difference between OnUpdate and OnEndpointTierUpdate is that this method
// does not track tier information for a remote endpoint endpoint whereas
// OnEndpointTierUpdate tracks a local endpoint and records its corresponding tier
// information as well.
func (ec *EndpointLookupsCache) OnUpdate(epUpdate api.Update) (_ bool) {
	switch k := epUpdate.Key.(type) {
	case model.WorkloadEndpointKey:
		if epUpdate.Value == nil {
			ec.removeEndpointWithDelay(k)
		} else {
			endpoint := epUpdate.Value.(*model.WorkloadEndpoint)
			ed := &EndpointData{
				Key:      k,
				Endpoint: epUpdate.Value,
			}
			ec.addOrUpdateEndpoint(k, ed, extractIPsFromWorkloadEndpoint(endpoint))
		}
	case model.HostEndpointKey:
		if epUpdate.Value == nil {
			ec.removeEndpointWithDelay(k)
		} else {
			endpoint := epUpdate.Value.(*model.HostEndpoint)
			ed := &EndpointData{
				Key:      k,
				Endpoint: epUpdate.Value,
			}
			ec.addOrUpdateEndpoint(k, ed, extractIPsFromHostEndpoint(endpoint))
		}
	default:
		log.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(epUpdate.Key), epUpdate)
		return
	}
	log.Debugf("Updating endpoint cache with remote endpoint data %v", epUpdate.Key)

	return
}

// OnResourceUpdate is the callback method registered with the allUpdates dispatcher. We filter out everything except
// node updates.
func (ec *EndpointLookupsCache) OnResourceUpdate(update api.Update) (_ bool) {
	switch k := update.Key.(type) {
	case model.ResourceKey:
		switch k.Kind {
		case v3.KindNode:
			if update.Value == nil {
				ec.removeNode(k.Name)
			} else {
				ec.addOrUpdateNode(k.Name, update.Value.(*v3.Node))
			}
		default:
			log.Debugf("Ignoring update for resource: %s", k)
		}
	default:
		log.Errorf("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}
	return
}

// addOrUpdateEndpoint tracks endpoint to IP mapping as well as IP to endpoint reverse mapping
// for a workload or host endpoint.
func (ec *EndpointLookupsCache) addOrUpdateEndpoint(key model.Key, incomingEndpointData *EndpointData, ipsOfIncomingEndpoint [][16]byte) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	// If the endpoint exists, and it was updated, then we might have to add or
	// remove IPs.
	// First up, get all current ip addresses.
	var ipsToRemove set.Set[[16]byte] = set.New[[16]byte]()

	currentEndpoint, endpointAlreadyExists := ec.endpointData[key]
	// Create a copy so that we can figure out which IPs to keep and
	// which ones to remove.
	if endpointAlreadyExists {
		// collect all IPs from existing endpoint key
		switch currentEndpoint.Key.(type) {
		case model.WorkloadEndpointKey:
			ipsToRemove.AddAll(extractIPsFromWorkloadEndpoint(currentEndpoint.Endpoint.(*model.WorkloadEndpoint)))
		case model.HostEndpointKey:
			ipsToRemove.AddAll(extractIPsFromHostEndpoint(currentEndpoint.Endpoint.(*model.HostEndpoint)))
		}
	}

	// Collect all IPs that correspond to this endpoint and mark
	// any IP that shouldn't be discarded.
	ipsToUpdate := set.New[[16]byte]()
	for _, ip := range ipsOfIncomingEndpoint {
		// If this is an already existing IP, then remove it,
		if ipsToRemove.Contains(ip) {
			ipsToRemove.Discard(ip)
		}

		// capture all incoming IPs as both new and existing ip mappins
		// need to be updated with incoming endpoint data
		ipsToUpdate.Add(ip)
	}

	// update endpoint data lookup by key

	// if there was a previous endpoint with the same key to be deleted,
	// stop the deletion timer and let the entries be updated with incomingEndpointData
	deletionTimer, isEndpointSetToBePrevDeleted := ec.endpointDeletionTimers[key]
	if endpointAlreadyExists && isEndpointSetToBePrevDeleted {
		deletionTimer.Stop()
		delete(ec.endpointDeletionTimers, key)
	}

	ec.endpointData[incomingEndpointData.Key] = incomingEndpointData

	// update endpoint data lookup by ips
	ipsToUpdate.Iter(func(newIP [16]byte) error {
		ec.updateIPToEndpointMapping(newIP, incomingEndpointData)
		return nil
	})

	ipsToRemove.Iter(
		func(ip [16]byte) error {
			ec.removeEndpointDataIpMapping(key, ip)
			return set.RemoveItem
		})

	ec.reportEndpointCacheMetrics()
}

// updateIPToEndpointMapping creates or appends the EndpointData to a corresponding
// ip address in the ipToEndpoints map.
// This method isn't safe to be used concurrently and the caller should acquire the
// EndpointLookupsCache.epMutex before calling this method.
func (ec *EndpointLookupsCache) updateIPToEndpointMapping(ip [16]byte, incomingEndpointData *EndpointData) {
	// Check if this IP already has a corresponding endpoint.
	// If it has one, then append the endpoint to it. This is
	// expected to happen if an IP address is reused in a very
	// short interval. Otherwise, create a new IP to endpoint
	// mapping entry.
	existingEpDataForIp, ok := ec.ipToEndpoints[ip]

	if !ok {
		ec.ipToEndpoints[ip] = []*EndpointData{incomingEndpointData}
		return
	}

	// if there are existing EndpointData for the IP, loop through the slice
	// > if an endpointData is marked to be deleted - delete it
	// > update an endpointData
	isExistingEp := false
	i := 0
	for i < len(existingEpDataForIp) {
		if existingEpDataForIp[i].markedToBeDeleted {
			existingEpDataForIp = removeEndpointDataFromSlice(existingEpDataForIp, i)
			continue
		}

		// Check if this is an existing endpoint. If it is,
		// then just store the updated endpoint.
		if incomingEndpointData.Key == existingEpDataForIp[i].Key {
			isExistingEp = true
			existingEpDataForIp[i] = incomingEndpointData
		}

		i++
	}

	if !isExistingEp {
		existingEpDataForIp = append(existingEpDataForIp, incomingEndpointData)
	}
	ec.ipToEndpoints[ip] = existingEpDataForIp
}

func removeEndpointDataFromSlice(s []*EndpointData, i int) []*EndpointData {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]

	return s[:len(s)-1]
}

// removeEndpointWithDelay marks all EndpointData referenced by the
// (key model.Key) and delegates the removeEndpoint to another
// goroutine that will be called after endpointDataTTLAfterMarkedAsRemoved
// has passed.  ipToEndpointDeletionTimers is used to track the all the timers
// created for tentatively deleted endpoints as they are accessed by add/update
// operations.
func (ec *EndpointLookupsCache) removeEndpointWithDelay(key model.Key) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	endpointData, endpointExists := ec.endpointData[key]
	if !endpointExists {
		// for performance improvement - as time.AfterFunc creates a go routine
		return
	}

	_, isDeletionTimerForEndpointExists := ec.endpointDeletionTimers[key]
	if isDeletionTimerForEndpointExists {
		return
	}

	// mark the endpoint to be deleted and attach a timer to delegate the actual deletion
	endpointData.markedToBeDeleted = true

	endpointDeletionTimer := time.AfterFunc(endpointDataTTLAfterMarkedAsRemovedSeconds, func() { ec.removeEndpoint(key) })
	ec.endpointDeletionTimers[key] = endpointDeletionTimer
}

// removeEndpoint removes all EndpointData markedToBeDeleted from the slice
// captures all IPs and removes all correspondoing IP to EndpointData mapping as well.
func (ec *EndpointLookupsCache) removeEndpoint(key model.Key) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	// update ip mapping to remove all endpoints
	currentEndpointData, ok := ec.endpointData[key]
	if !ok {
		return
	}

	ipsMarkedAsDeleted := set.New[[16]byte]()

	// if the endpoint has not been marked for deletion ignore it as it may have been
	// updated before the deletion timer has been triggered
	if !currentEndpointData.markedToBeDeleted {
		return
	}

	// collect the IPs of this endpoint as we will need to remove it as well from the ipmapping
	switch currentEndpointData.Key.(type) {
	case model.WorkloadEndpointKey:
		ipsMarkedAsDeleted.AddAll(extractIPsFromWorkloadEndpoint(currentEndpointData.Endpoint.(*model.WorkloadEndpoint)))
	case model.HostEndpointKey:
		ipsMarkedAsDeleted.AddAll(extractIPsFromHostEndpoint(currentEndpointData.Endpoint.(*model.HostEndpoint)))
	}

	ipsMarkedAsDeleted.Iter(func(ip [16]byte) error {
		ec.removeEndpointDataIpMapping(key, ip)
		return nil
	})

	delete(ec.endpointData, key)
	delete(ec.endpointDeletionTimers, key)
	ec.reportEndpointCacheMetrics()
}

// removeEndpointDataIpMapping checks if  there is an existing
//   - IP to WEP/HEP relation that is being tracked and removes it if there is one.
//   - Endpoint to IP relation that is being tracked and removes it if there is one.
//
// This method isn't safe to be used concurrently and the caller should acquire the
// EndpointLookupsCache.epMutex before calling this method.
func (ec *EndpointLookupsCache) removeEndpointDataIpMapping(key model.Key, ip [16]byte) {
	// Remove existing IP to endpoint mapping.
	existingEps, ok := ec.ipToEndpoints[ip]
	if !ok || len(existingEps) == 1 {
		// There are no entries or only a single endpoint corresponding
		// to this IP address so it is safe to remove this mapping.
		delete(ec.ipToEndpoints, ip)
	} else {
		// If there is more than one endpoint, then keep the reverse ip
		// to endpoint mapping but only remove the endpoint corresponding
		// to this remove call.
		newEps := make([]*EndpointData, 0, len(existingEps)-1)
		for _, ep := range existingEps {
			if ep.Key == key {
				continue
			}
			newEps = append(newEps, ep)
		}
		ec.ipToEndpoints[ip] = newEps
	}
}

// IsEndpoint returns true if the supplied address is a endpoint, otherwise returns false.
// Use the EndpointData.IsLocal() method to check if an EndpointData object (returned by the
// EndpointLookupsCache.GetEndpoint() method) is a local endpoint or not.
func (ec *EndpointLookupsCache) IsEndpoint(addr [16]byte) bool {
	_, ok := ec.GetEndpoint(addr)
	return ok
}

// GetEndpoint returns the ordered list of tiers for a particular endpoint.
func (ec *EndpointLookupsCache) GetEndpoint(addr [16]byte) (*EndpointData, bool) {
	ec.epMutex.RLock()
	defer ec.epMutex.RUnlock()

	eps, ok := ec.ipToEndpoints[addr]
	if len(eps) >= 1 {
		// We return the last observed endpoint.
		return eps[len(eps)-1], ok
	}
	return nil, ok
}

// GetEndpointKeys retrieves all keys from the EndpointLookupCache
func (ec *EndpointLookupsCache) GetEndpointKeys() []model.Key {
	ec.epMutex.RLock()
	defer ec.epMutex.RUnlock()

	eps := []model.Key{}
	for key := range ec.endpointData {
		eps = append(eps, key)
	}
	return eps
}

// GetEndpointKeys retrieves all EndpointData from the EndpointLookupCache
// excluding those which are not marked as deleted
func (ec *EndpointLookupsCache) GetAllEndpointData() []*EndpointData {
	ec.epMutex.RLock()
	defer ec.epMutex.RUnlock()

	allEds := []*EndpointData{}
	for _, ed := range ec.endpointData {
		if ed.markedToBeDeleted {
			continue
		}
		allEds = append(allEds, ed)
	}
	return allEds
}

// reportEndpointCacheMetrics reports endpoint cache performance metrics to prometheus
func (ec *EndpointLookupsCache) reportEndpointCacheMetrics() {
	gaugeEndpointCacheLength.Set(float64(len(ec.endpointData)))
}

func (ec *EndpointLookupsCache) GetNode(ip [16]byte) (string, bool) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	if nodes, ok := ec.nodeIPToNames[ip]; ok && len(nodes) == 1 {
		log.Debugf("IP %v corresponds to node %s", ip, nodes[0])
		return nodes[0], true
	}
	log.Debugf("IP %v does not correspond to a known node IP", ip)
	return "", false
}

// endpointName is a convenience function to return a printable name for an endpoint.
func endpointName(key model.Key) (name string) {
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		name = workloadEndpointName(k)
	case model.HostEndpointKey:
		name = hostEndpointName(k)
	}
	return
}

// workloadEndpointName returns a single string rep of the workload endpoint.
func workloadEndpointName(wep model.WorkloadEndpointKey) string {
	return "WEP(" + wep.Hostname + "/" + wep.OrchestratorID + "/" + wep.WorkloadID + "/" + wep.EndpointID + ")"
}

// hostEndpointName returns a single string rep of the host endpoint.
func hostEndpointName(hep model.HostEndpointKey) string {
	return "HEP(" + hep.Hostname + "/" + hep.EndpointID + ")"
}

// extractIPsFromHostEndpoint converts the expected IPs of the host endpoint into [16]byte
func extractIPsFromHostEndpoint(endpoint *model.HostEndpoint) [][16]byte {
	v4Addrs := endpoint.ExpectedIPv4Addrs
	v6Addrs := endpoint.ExpectedIPv6Addrs
	combined := make([][16]byte, 0, len(v4Addrs)+len(v6Addrs))
	for _, addr := range v4Addrs {
		var addrB [16]byte
		copy(addrB[:], addr.IP.To16()[:16])
		combined = append(combined, addrB)
	}
	for _, addr := range v6Addrs {
		var addrB [16]byte
		copy(addrB[:], addr.IP.To16()[:16])
		combined = append(combined, addrB)
	}
	return combined
}

// extractIPsFromWorkloadEndpoint converts the IPv[46]Nets fields of the WorkloadEndpoint into
// [16]bytes. It ignores any prefix length.
func extractIPsFromWorkloadEndpoint(endpoint *model.WorkloadEndpoint) [][16]byte {
	v4Nets := endpoint.IPv4Nets
	v6Nets := endpoint.IPv6Nets
	combined := make([][16]byte, 0, len(v4Nets)+len(v6Nets))
	for _, addr := range v4Nets {
		var addrB [16]byte
		copy(addrB[:], addr.IP.To16()[:16])
		combined = append(combined, addrB)
	}
	for _, addr := range v6Nets {
		var addrB [16]byte
		copy(addrB[:], addr.IP.To16()[:16])
		combined = append(combined, addrB)
	}
	return combined
}

// DumpEndpoints generates a string of all endpoints in the cache
// with formatting of:
// "model.Key.Name: ip0, ip1, ... ipn", where ip0..n are IPs of
// the endpoint
func (ec *EndpointLookupsCache) DumpEndpoints() string {
	ec.epMutex.RLock()
	defer ec.epMutex.RUnlock()

	lines := []string{}
	for ip, eds := range ec.ipToEndpoints {
		edNames := []string{}
		for _, ed := range eds {
			edNames = append(edNames, endpointName(ed.Key))
		}
		lines = append(lines, net.IP(ip[:16]).String()+": "+strings.Join(edNames, ","))
	}

	lines = append(lines, "-------")

	for key, endpointData := range ec.endpointData {
		ipStr := []string{}
		ips := set.New[[16]byte]()

		if !endpointData.markedToBeDeleted {
			switch endpointData.Key.(type) {
			case model.WorkloadEndpointKey:
				ips.AddAll(extractIPsFromWorkloadEndpoint(endpointData.Endpoint.(*model.WorkloadEndpoint)))
			case model.HostEndpointKey:
				ips.AddAll(extractIPsFromHostEndpoint(endpointData.Endpoint.(*model.HostEndpoint)))
			}
		}

		ips.Iter(func(ip [16]byte) error {
			ipStr = append(ipStr, net.IP(ip[:16]).String())
			return nil
		})
		lines = append(lines, endpointName(key), ": ", strings.Join(ipStr, ","))
	}

	return strings.Join(lines, "\n")
}

// addOrUpdateNode tracks IP to node mappings.
func (ec *EndpointLookupsCache) addOrUpdateNode(name string, node *v3.Node) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	if existing, ok := ec.nodes[name]; ok {
		if reflect.DeepEqual(existing, node.Spec) {
			// Service data has not changed. Do nothing.
			return
		}

		// Service data has changed, keep the logic simple by removing the old service and re-adding the new one.
		ec.handleNode(name, existing, ec.removeNodeMap)
	}

	ec.handleNode(name, node.Spec, ec.addNodeMap)
	ec.nodes[name] = node.Spec
}

// removeNode tracks removal of a node from the IP mappings.
func (ec *EndpointLookupsCache) removeNode(name string) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	if existing, ok := ec.nodes[name]; ok {
		ec.handleNode(name, existing, ec.removeNodeMap)
		delete(ec.nodes, name)
	}
}

// handleNode handles the mappings for a node. The supplied operator is used to either add or remove the mappings.
func (ec *EndpointLookupsCache) handleNode(name string, node v3.NodeSpec, nodeOp func(name string, ip [16]byte)) {
	if node.BGP != nil && node.BGP.IPv4Address != "" {
		if nodeIP, ok := IPStringToArray(node.BGP.IPv4Address); ok {
			nodeOp(name, nodeIP)
		}
	}

	if node.BGP != nil && node.BGP.IPv4IPIPTunnelAddr != "" {
		if nodeIP, ok := IPStringToArray(node.BGP.IPv4IPIPTunnelAddr); ok {
			nodeOp(name, nodeIP)
		}
	}

	if node.IPv4VXLANTunnelAddr != "" {
		if nodeIP, ok := IPStringToArray(node.IPv4VXLANTunnelAddr); ok {
			nodeOp(name, nodeIP)
		}
	}

	if node.Wireguard != nil && node.Wireguard.InterfaceIPv4Address != "" {
		if nodeIP, ok := IPStringToArray(node.Wireguard.InterfaceIPv4Address); ok {
			nodeOp(name, nodeIP)
		}
	}
}

// removeNodeMap removes a single node <-> IP mapping.
func (ec *EndpointLookupsCache) removeNodeMap(name string, ip [16]byte) {
	names := stringutils.RemoveValue(ec.nodeIPToNames[ip], name)
	if len(names) == 0 {
		// No more services for the cluster IP, so just remove the cluster IP to service mapping
		delete(ec.nodeIPToNames, ip)
	} else {
		ec.nodeIPToNames[ip] = names
	}
}

// addNodeMap adds a single node <-> IP mapping.
func (ec *EndpointLookupsCache) addNodeMap(name string, ip [16]byte) {
	if !stringutils.InSlice(ec.nodeIPToNames[ip], name) {
		ec.nodeIPToNames[ip] = append(ec.nodeIPToNames[ip], name)
	}
}
