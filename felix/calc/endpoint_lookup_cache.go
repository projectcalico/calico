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
	"iter"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	apispec "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/stringutils"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	endpointDataDeletionDelay time.Duration = 2 * config.DefaultConntrackPollingInterval
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

// EndpointData is the exported interface for our cache entries, used by
// the collector to interrogate the cached entry.
type EndpointData interface {
	Key() model.Key
	GenerateName() string
	IsLocal() bool
	IsHostEndpoint() bool
	Labels() uniquelabels.Map
	IngressMatchData() *MatchData
	EgressMatchData() *MatchData
}

// endpointData is our internal interface shared by our local/remote cache
// entries.
type endpointData interface {
	EndpointData
	allIPs() [][16]byte
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
	// TierDefaultActionRuleID is used to track the last policy in each tier that
	// selected this endpoint. This special RuleID is created so that implicitly
	// dropped packets in each tier can be counted against these policies as
	// being responsible for denying the packet.
	//
	// May be set to nil if the tier only contains staged policies.
	TierDefaultActionRuleID *RuleID

	// The index into the policy match slice that the implicit drop rule is added. This is always the last
	// index for this tier and equal to FirstPolicyMatchIndex+len(StagedPolicyTierDefaultActionRuleID).
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
	epMutex sync.RWMutex

	// localEndpointData contains information about local endpoints only, it
	// includes additional policy match information vs remoteEndpointData.
	localEndpointData map[model.EndpointKey]*LocalEndpointData
	// remoteEndpointData contains information about remote endpoints only.
	// We use a separate map for remote endpoints to minimize the size in
	// memory.
	remoteEndpointData map[model.EndpointKey]*RemoteEndpointData

	ipToEndpoints map[[16]byte][]endpointData

	endpointDeletionTimers map[model.Key]*time.Timer

	// Map to track which endpoints are marked for deletion
	markedForDeletion map[model.EndpointKey]bool

	// Node relationship data.
	// TODO(rlb): We should just treat this as an endpoint
	nodes         map[string]internalapi.NodeSpec
	nodeIPToNames map[[16]byte][]string
	deletionDelay time.Duration
}

type EndpointLookupsCacheOption func(*EndpointLookupsCache)

func WithDeletionDelay(d time.Duration) EndpointLookupsCacheOption {
	return func(ec *EndpointLookupsCache) {
		ec.deletionDelay = d
	}
}

func NewEndpointLookupsCache(opts ...EndpointLookupsCacheOption) *EndpointLookupsCache {
	ec := &EndpointLookupsCache{
		epMutex:       sync.RWMutex{},
		ipToEndpoints: map[[16]byte][]endpointData{},

		localEndpointData:  map[model.EndpointKey]*LocalEndpointData{},
		remoteEndpointData: map[model.EndpointKey]*RemoteEndpointData{},

		endpointDeletionTimers: map[model.Key]*time.Timer{},
		markedForDeletion:      map[model.EndpointKey]bool{},
		nodeIPToNames:          make(map[[16]byte][]string),
		nodes:                  make(map[string]internalapi.NodeSpec),
		deletionDelay:          endpointDataDeletionDelay,
	}

	for _, opt := range opts {
		opt(ec)
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
func (ec *EndpointLookupsCache) OnEndpointTierUpdate(key model.EndpointKey, ep model.Endpoint, _ []EndpointComputedData, _ *EndpointBGPPeer, filteredTiers []TierInfo) {
	if ep == nil {
		log.Debugf("Queueing deletion of local endpoint data %v", key)
		ec.removeEndpointWithDelay(key)
	} else {
		ed := ec.CreateLocalEndpointData(key, ep, filteredTiers)
		log.Debugf("Updating endpoint cache with local endpoint data: %v", key)
		ec.addOrUpdateEndpoint(key, ed)
	}
}

// CreateLocalEndpointData creates the endpoint data based on tier
func (ec *EndpointLookupsCache) CreateLocalEndpointData(key model.EndpointKey, ep model.Endpoint, filteredTiers []TierInfo) *LocalEndpointData {
	ed := &LocalEndpointData{
		CommonEndpointData: CalculateCommonEndpointData(key, ep),
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

		tierDefaultAction := rules.RuleActionDeny
		if ti.DefaultAction == apispec.Pass {
			tierDefaultAction = rules.RuleActionPass
		}

		var hasIngress, hasEgress bool
		for _, pol := range ti.OrderedPolicies {
			if pol.GovernsIngress() {
				// Add an ingress tier default action lookup.
				rid := NewRuleID(pol.Key.Kind, ti.Name, pol.Key.Name, pol.Key.Namespace, RuleIndexTierDefaultAction, rules.RuleDirIngress, tierDefaultAction)
				ed.Ingress.PolicyMatches[rid.PolicyID] = policyMatchIdxIngress

				if model.KindIsStaged(pol.Key.Kind) {
					// Increment the match index. We don't do this for non-staged policies because they replace the
					// subsequent staged policy in the results.
					policyMatchIdxIngress++
				} else {
					// This is a non-staged policy, update our end-of-tier match.
					tdIngress.TierDefaultActionRuleID = rid
				}
				hasIngress = true
			}
			if pol.GovernsEgress() {
				// Add an egress tier default action lookup.
				rid := NewRuleID(pol.Key.Kind, ti.Name, pol.Key.Name, pol.Key.Namespace, RuleIndexTierDefaultAction, rules.RuleDirEgress, tierDefaultAction)
				ed.Egress.PolicyMatches[rid.PolicyID] = policyMatchIdxEgress

				if model.KindIsStaged(pol.Key.Kind) {
					// Increment the match index. We don't do this for non-staged policies because they replace the
					// subsequent staged policy in the results.
					policyMatchIdxEgress++
				} else {
					// This is a non-staged policy, update our end-of-tier match.
					tdEgress.TierDefaultActionRuleID = rid
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

func CalculateCommonEndpointData(key model.EndpointKey, ep model.Endpoint) CommonEndpointData {
	generateName, ips := extractEndpointInfo(ep)
	return CommonEndpointData{
		key:          key,
		labels:       ep.GetLabels(),
		generateName: generateName,
		ips:          ips,
	}
}

func extractEndpointInfo(ep model.Endpoint) (string, [][16]byte) {
	var generateName string
	var ips [][16]byte
	switch ep := ep.(type) {
	case *model.WorkloadEndpoint:
		generateName = ep.GenerateName
		ips = extractIPsFromWorkloadEndpoint(ep)
	case *model.HostEndpoint:
		generateName = ""
		ips = extractIPsFromHostEndpoint(ep)
	}
	return generateName, ips
}

// OnUpdate is the callback method registered with the RemoteEndpointDispatcher for
// model.WorkloadEndpoint and model.HostEndpoint types. This method updates the
// mapping between a remote endpoint and all the IPs that the endpoint contains.
// The difference between OnUpdate and OnEndpointTierUpdate is that this method
// handles remote endpoints, which do not have policy match information, while
// OnEndpointTierUpdate handles local endpoints and stores off their policy
// match information.
func (ec *EndpointLookupsCache) OnUpdate(epUpdate api.Update) (_ bool) {
	switch k := epUpdate.Key.(type) {
	case model.EndpointKey:
		if epUpdate.Value == nil {
			ec.removeEndpointWithDelay(k)
		} else {
			endpoint := epUpdate.Value.(model.Endpoint)
			ed := &RemoteEndpointData{
				CommonEndpointData: CalculateCommonEndpointData(k, endpoint),
			}
			ec.addOrUpdateEndpoint(k, ed)
		}
	default:
		log.Debugf("Ignoring unexpected update: %v %#v",
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
		case internalapi.KindNode:
			if update.Value == nil {
				ec.removeNode(k.Name)
			} else {
				ec.addOrUpdateNode(k.Name, update.Value.(*internalapi.Node))
			}
		default:
			log.Tracef("Ignoring update for resource: %s", k)
		}
	default:
		log.Errorf("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}
	return
}

// addOrUpdateEndpoint tracks endpoint to IP mapping as well as IP to endpoint reverse mapping
// for a workload or host endpoint.
func (ec *EndpointLookupsCache) addOrUpdateEndpoint(key model.EndpointKey, incomingEndpointData endpointData) {
	ipsOfIncomingEndpoint := incomingEndpointData.allIPs()

	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	// If the endpoint exists, and it was updated, then we might have to add or
	// remove IPs.
	// First up, get all current ip addresses.
	var ipsToRemove set.Set[[16]byte] = set.New[[16]byte]()

	currentEndpoint, endpointAlreadyExists := ec.lookupEndpoint(key)
	// Create a copy so that we can figure out which IPs to keep and
	// which ones to remove.
	if endpointAlreadyExists {
		// collect all IPs from existing endpoint key
		ipsToRemove.AddAll(currentEndpoint.allIPs())
	}

	// Collect all IPs that correspond to this endpoint and mark
	// any IP that shouldn't be discarded.
	ipsToUpdate := set.New[[16]byte]()
	for _, ip := range ipsOfIncomingEndpoint {
		// If this is an already existing IP, then remove it
		if ipsToRemove.Contains(ip) {
			ipsToRemove.Discard(ip)
		}

		// capture all incoming IPs as both new and existing ip mappings
		// need to be updated with incoming endpoint data
		ipsToUpdate.Add(ip)
	}

	// update endpoint data lookup by key

	// If there was a previous endpoint with the same key to be deleted,
	// stop the deletion timer and let the entries be updated with incomingEndpointData
	deletionTimer, isEndpointSetToBePrevDeleted := ec.endpointDeletionTimers[key]
	if endpointAlreadyExists && isEndpointSetToBePrevDeleted {
		deletionTimer.Stop()
		delete(ec.endpointDeletionTimers, key)
		// Remove deletion marking since we're updating the endpoint
		delete(ec.markedForDeletion, key)
	}

	ec.storeEndpoint(key, incomingEndpointData)

	// update endpoint data lookup by ips
	for newIP := range ipsToUpdate.All() {
		ec.updateIPToEndpointMapping(newIP, incomingEndpointData)
	}

	for ip := range ipsToRemove.All() {
		ec.removeEndpointDataIpMapping(key, ip)
		ipsToRemove.Discard(ip)
	}

	ec.reportEndpointCacheMetrics()
}

func (ec *EndpointLookupsCache) lookupEndpoint(key model.EndpointKey) (ed endpointData, ok bool) {
	ed, ok = ec.localEndpointData[key]
	if ok {
		return
	}
	ed, ok = ec.remoteEndpointData[key]
	if ok {
		return
	}
	return nil, false
}

func (ec *EndpointLookupsCache) storeEndpoint(key model.EndpointKey, ed endpointData) {
	switch ed := ed.(type) {
	case *LocalEndpointData:
		ec.localEndpointData[key] = ed
	case *RemoteEndpointData:
		ec.remoteEndpointData[key] = ed
	}
}

func (ec *EndpointLookupsCache) allEndpoints() iter.Seq2[model.EndpointKey, endpointData] {
	return func(yield func(model.EndpointKey, endpointData) bool) {
		for k, v := range ec.localEndpointData {
			if !yield(k, v) {
				return
			}
		}
		for k, v := range ec.remoteEndpointData {
			if !yield(k, v) {
				return
			}
		}
	}
}

// updateIPToEndpointMapping creates or appends the EndpointData to a corresponding
// ip address in the ipToEndpoints map.
// This method isn't safe to be used concurrently and the caller should acquire the
// EndpointLookupsCache.epMutex before calling this method.
func (ec *EndpointLookupsCache) updateIPToEndpointMapping(ip [16]byte, incomingEndpointData endpointData) {
	// Check if this IP already has a corresponding endpoint.
	// If it has one, then append the endpoint to it. This is
	// expected to happen if an IP address is reused in a very
	// short interval. Otherwise, create a new IP to endpoint
	// mapping entry.
	existingEpDataForIp, ok := ec.ipToEndpoints[ip]

	if !ok {
		ec.ipToEndpoints[ip] = []endpointData{incomingEndpointData}
		return
	}

	// if there are existing EndpointData for the IP, loop through the slice
	// > if an endpointData is marked to be deleted - delete it
	// > update an endpointData
	isExistingEp := false
	i := 0
	for i < len(existingEpDataForIp) {
		if epKey, ok := existingEpDataForIp[i].Key().(model.EndpointKey); ok && ec.markedForDeletion[epKey] {
			existingEpDataForIp = removeEndpointDataFromSlice(existingEpDataForIp, i)
			continue
		}

		// Check if this is an existing endpoint. If it is,
		// then just store the updated endpoint.
		if incomingEndpointData.Key() == existingEpDataForIp[i].Key() {
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

func removeEndpointDataFromSlice(s []endpointData, i int) []endpointData {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]

	return s[:len(s)-1]
}

// removeEndpointWithDelay marks all EndpointData referenced by the
// (key model.Key) and delegates the removeEndpoint to another
// goroutine that will be called after endpointDataTTLAfterMarkedAsRemoved
// has passed. ipToEndpointDeletionTimers is used to track all the timers
// created for tentatively deleted endpoints as they are accessed by add/update
// operations.
func (ec *EndpointLookupsCache) removeEndpointWithDelay(key model.EndpointKey) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	_, endpointExists := ec.lookupEndpoint(key)
	if !endpointExists {
		// for performance improvement - as time.AfterFunc creates a go routine
		return
	}

	_, isDeletionTimerForEndpointExists := ec.endpointDeletionTimers[key]
	if isDeletionTimerForEndpointExists {
		return
	}

	// mark the endpoint to be deleted and attach a timer to delegate the actual deletion
	ec.markedForDeletion[key] = true

	endpointDeletionTimer := time.AfterFunc(ec.deletionDelay, func() { ec.removeEndpoint(key) })
	ec.endpointDeletionTimers[key] = endpointDeletionTimer
}

// removeEndpoint removes all EndpointData that were previously marked for deletion
// captures all IPs and removes all correspondoing IP to EndpointData mapping as well.
func (ec *EndpointLookupsCache) removeEndpoint(key model.EndpointKey) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	// update ip mapping to remove all endpoints
	currentEndpointData, ok := ec.lookupEndpoint(key)
	if !ok {
		return
	}

	// If the endpoint has not been marked for deletion ignore it as it may have been
	// updated before the deletion timer has been triggered.
	if !ec.markedForDeletion[key] {
		return
	}

	// Collect the IPs of this endpoint as we will need to remove it from the IP mapping.
	ipsMarkedAsDeleted := set.From(currentEndpointData.allIPs()...)
	for ip := range ipsMarkedAsDeleted.All() {
		ec.removeEndpointDataIpMapping(key, ip)
	}

	delete(ec.localEndpointData, key)
	delete(ec.remoteEndpointData, key)
	delete(ec.endpointDeletionTimers, key)
	delete(ec.markedForDeletion, key)
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
		newEps := make([]endpointData, 0, len(existingEps)-1)
		for _, ep := range existingEps {
			if ep.Key() == key {
				continue
			}
			newEps = append(newEps, ep)
		}
		ec.ipToEndpoints[ip] = newEps
	}
}

// GetEndpoint returns an endpoint matching the given IP, if there is one.
// If more than one endpoint has the IP, the last observed endpoint is returned.
func (ec *EndpointLookupsCache) GetEndpoint(addr [16]byte) (EndpointData, bool) {
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

	eps := make([]model.Key, 0, len(ec.localEndpointData)+len(ec.remoteEndpointData))
	for k := range ec.allEndpoints() {
		eps = append(eps, k)
	}
	return eps
}

// GetAllEndpointData retrieves all EndpointData from the EndpointLookupCache
// excluding those which are not marked as deleted. Convenience method only
// used for testing purposes.
func (ec *EndpointLookupsCache) GetAllEndpointData() []EndpointData {
	ec.epMutex.RLock()
	defer ec.epMutex.RUnlock()

	allEds := []EndpointData{}
	for key, ed := range ec.allEndpoints() {
		if ec.markedForDeletion[key] {
			continue
		}
		allEds = append(allEds, ed)
	}
	return allEds
}

// IsEndpointDeleted returns whether the given endpoint is marked for deletion.
func (ec *EndpointLookupsCache) IsEndpointDeleted(ep EndpointData) bool {
	ec.epMutex.RLock()
	defer ec.epMutex.RUnlock()

	if key, ok := ep.Key().(model.EndpointKey); ok {
		return ec.markedForDeletion[key]
	}
	return false
}

// MarkEndpointForDeletion marks the given endpoint for deletion.
func (ec *EndpointLookupsCache) MarkEndpointForDeletion(ep EndpointData) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	if key, ok := ep.Key().(model.EndpointKey); ok {
		ec.markedForDeletion[key] = true
	}
}

// reportEndpointCacheMetrics reports endpoint cache performance metrics to prometheus
func (ec *EndpointLookupsCache) reportEndpointCacheMetrics() {
	gaugeEndpointCacheLength.Set(float64(len(ec.remoteEndpointData) + len(ec.localEndpointData)))
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
		copy(addrB[:], addr.To16()[:16])
		combined = append(combined, addrB)
	}
	for _, addr := range v6Addrs {
		var addrB [16]byte
		copy(addrB[:], addr.To16()[:16])
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
			edNames = append(edNames, endpointName(ed.Key()))
		}
		lines = append(lines, net.IP(ip[:16]).String()+": "+strings.Join(edNames, ","))
	}

	lines = append(lines, "-------")

	for key, endpointData := range ec.allEndpoints() {
		ipStr := []string{}
		ips := set.New[[16]byte]()

		deleted := "deleted"
		if !ec.markedForDeletion[key] {
			ips.AddAll(endpointData.allIPs())
			deleted = ""
		}

		for ip := range ips.All() {
			ipStr = append(ipStr, net.IP(ip[:16]).String())
		}
		lines = append(lines, endpointName(key)+": "+strings.Join(ipStr, ",")+deleted)
	}

	return strings.Join(lines, "\n")
}

// addOrUpdateNode tracks IP to node mappings.
func (ec *EndpointLookupsCache) addOrUpdateNode(name string, node *internalapi.Node) {
	ec.epMutex.Lock()
	defer ec.epMutex.Unlock()

	if existing, ok := ec.nodes[name]; ok {
		if reflect.DeepEqual(existing, node.Spec) {
			// Node data has not changed. Do nothing.
			return
		}

		// Node data has changed, keep the logic simple by removing the old service and re-adding the new one.
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
func (ec *EndpointLookupsCache) handleNode(name string, node internalapi.NodeSpec, nodeOp func(name string, ip [16]byte)) {
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

// CommonEndpointData contains the common fields between LocalEndpointData and RemoteEndpointData.
type CommonEndpointData struct {
	key model.EndpointKey

	// Labels contains the labels extracted from the endpoint.
	labels uniquelabels.Map
	// IP addresses extracted from the endpoint.
	ips [][16]byte
	// GenerateName is only populated for WorkloadEndpoints, it contains the
	// contents of the GenerateName field from the WorkloadEndpoint, which is
	// used by the collector for determining the aggregation name.
	generateName string
}

func (e *CommonEndpointData) Key() model.Key {
	return e.key
}

// IsHostEndpoint returns if this EndpointData corresponds to a hostendpoint.
func (e *CommonEndpointData) IsHostEndpoint() (isHep bool) {
	switch e.key.(type) {
	case model.HostEndpointKey:
		isHep = true
	}
	return
}

func (e *CommonEndpointData) allIPs() [][16]byte {
	return e.ips
}

func (e *CommonEndpointData) Labels() uniquelabels.Map {
	return e.labels
}

func (e *CommonEndpointData) GenerateName() string {
	return e.generateName
}

// LocalEndpointData is the cache entry struct for local endpoints.  We store
// additional information for local endpoints.  Namely the locally-active
// policy.
type LocalEndpointData struct {
	CommonEndpointData

	// Ingress keeps track of the ingress policies that apply to this endpoint.
	Ingress *MatchData
	// Egress keeps track of the egress policies that apply to this endpoint.
	Egress *MatchData
}

var (
	_ endpointData = &LocalEndpointData{}
	_ endpointData = &RemoteEndpointData{}
)

func (ed *LocalEndpointData) IsLocal() bool {
	return true
}

func (ed *LocalEndpointData) IngressMatchData() *MatchData {
	return ed.Ingress
}

func (ed *LocalEndpointData) EgressMatchData() *MatchData {
	return ed.Egress
}

type RemoteEndpointData struct {
	CommonEndpointData
}

func (ed *RemoteEndpointData) IsLocal() bool {
	return false
}

func (ed *RemoteEndpointData) IngressMatchData() *MatchData {
	return nil
}

func (ed *RemoteEndpointData) EgressMatchData() *MatchData {
	return nil
}
