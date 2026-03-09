// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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

package labelindex

import (
	"iter"
	"math"
	"slices"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/labelindex/labelnamevalueindex"
	"github.com/projectcalico/calico/felix/labelindex/labelrestrictionindex"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeNumEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_label_index_num_endpoints",
		Help: "Total number of endpoints and similar objects in the index.",
	})

	counterVecSelectorEvals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_label_index_selector_evals",
		Help: "Total number of selector evaluations.",
	}, []string{"result"})
	counterSelectorEvalsTrue  = counterVecSelectorEvals.WithLabelValues("true")
	counterSelectorEvalsFalse = counterVecSelectorEvals.WithLabelValues("false")

	gaugeVecSelectors = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_label_index_num_active_selectors",
		Help: "Total number of active selectors in the policy rule label index.",
	}, []string{"optimized"})
	gaugeSelectorsOpt    = gaugeVecSelectors.WithLabelValues("true")
	gaugeSelectorsNonOpt = gaugeVecSelectors.WithLabelValues("false")

	counterVecScanStrat = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_label_index_strategy_evals",
		Help: "Total number of index scans broken down by scan strategy.",
	}, []string{"strategy"})
)

func init() {
	prometheus.MustRegister(
		gaugeNumEndpoints,
		counterVecSelectorEvals,
		gaugeVecSelectors,
		counterVecScanStrat,
	)
}

// endpointData holds the data that we need to know about a particular endpoint.
type endpointData struct {
	labels  uniquelabels.Map
	nets    []ip.CIDR
	ports   []model.EndpointPort
	parents []*npParentData

	cachedMatchingIPSetIDs set.Adaptive[string]
}

func (d *endpointData) AddMatchingIPSetID(id string) {
	d.cachedMatchingIPSetIDs.Add(id)
}

func (d *endpointData) RemoveMatchingIPSetID(id string) {
	d.cachedMatchingIPSetIDs.Discard(id)
}

func (d *endpointData) HasParent(parent *npParentData) bool {
	return slices.Contains(d.parents, parent)
}

func (d *endpointData) LookupNamedPorts(name string, proto ipsetmember.Protocol) []uint16 {
	var matchingPorts []uint16
	for _, p := range d.ports {
		if p.Name == name && proto.MatchesModelProtocol(p.Protocol) {
			matchingPorts = append(matchingPorts, p.Port)
		}
	}
	return matchingPorts
}

type ipSetData struct {
	// The selector and named port that this IP set represents.  If the selector is nil then
	// this IP set represents an unfiltered named port.  If namedPortProtocol == ProtocolNone then
	// this IP set represents a selector only, with no named port component.
	selector          *selector.Selector
	namedPortProtocol ipsetmember.Protocol
	namedPort         string

	// memberToRefCount stores a reference count for each member in the IP set.  Reference counts
	// may be >1 if an IP address is shared by more than one endpoint.
	memberToRefCount map[ipsetmember.IPSetMember]uint64
}

// GetHandle implements the Labels interface for endpointData.  Combines the endpoint's own labels with
// those of its parents on the fly.  This reduces the number of allocations we need to do, and
// it's fast in the mainline case (where there are 0-1 parents).
func (d *endpointData) GetHandle(labelName uniquestr.Handle) (handle uniquestr.Handle, present bool) {
	if handle, present = d.labels.GetHandle(labelName); present {
		return
	}
	for _, parent := range d.parents {
		if handle, present = parent.labels.GetHandle(labelName); present {
			return
		}
	}
	return
}

func (d *endpointData) OwnLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return d.labels.AllHandles()
}

func (d *endpointData) AllOwnAndParentLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return func(yield func(k, v uniquestr.Handle) bool) {
		seenKeys := set.New[uniquestr.Handle]()
		defer seenKeys.Clear()

		for k, v := range d.labels.AllHandles() {
			if !yield(k, v) {
				return
			}
			seenKeys.Add(k)
		}

		for _, parent := range d.parents {
			for k, v := range parent.labels.AllHandles() {
				if seenKeys.Contains(k) {
					// label is shadowed.
					continue
				}
				// Non-shadowed parent label. Emit.
				if !yield(k, v) {
					return
				}
				seenKeys.Add(k)
			}
		}
	}
}

func (d *endpointData) Equals(other *endpointData) bool {
	if !d.labels.Equals(other.labels) {
		return false
	}
	if len(d.ports) != len(other.ports) {
		return false
	}
	if len(d.nets) != len(other.nets) {
		return false
	}
	if len(d.parents) != len(other.parents) {
		return false
	}

	for i, p := range d.ports {
		if other.ports[i] != p {
			return false
		}
	}
	for i, c := range d.nets {
		if other.nets[i] != c {
			return false
		}
	}
	for i, p := range d.parents {
		// Note: this is a pointer comparison; we know that pointers will be shared.
		if other.parents[i] != p {
			return false
		}
	}
	return true
}

// npParentData holds the data that we know about each parent (i.e. each security profile).  Since,
// profiles consist of multiple resources in our data-model, the labels fields may be nil
// if we have partial information.
type npParentData struct {
	id          string
	labels      uniquelabels.Map
	endpointIDs set.Typed[any]
}

func (d *npParentData) OwnLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return d.labels.AllHandles()
}

func (d *npParentData) OwnLabels() iter.Seq2[string, string] {
	return d.labels.AllStrings()
}

func (d *npParentData) DiscardEndpointID(id any) {
	if d.endpointIDs == nil {
		panic("discard of unknown ID")
	}
	d.endpointIDs.Discard(id)
	if d.endpointIDs.Len() == 0 {
		d.endpointIDs = nil
	}
}

func (d *npParentData) AddEndpointID(id any) {
	if d.endpointIDs == nil {
		d.endpointIDs = set.New[any]()
	}
	d.endpointIDs.Add(id)
}

func (d *npParentData) IterEndpointIDs(f func(id any) error) {
	if d.endpointIDs == nil {
		return
	}
	d.endpointIDs.Iter(f)
}

type NamedPortMatchCallback func(ipSetID string, member ipsetmember.IPSetMember)

type SelectorAndNamedPortIndex struct {
	endpointKVIdx *labelnamevalueindex.LabelNameValueIndex[any /*endpoint IDs*/, *endpointData]

	parentKVIdx           *labelnamevalueindex.LabelNameValueIndex[string, *npParentData]
	ipSetDataByID         map[string]*ipSetData
	selectorCandidatesIdx *labelrestrictionindex.LabelRestrictionIndex[string]

	// Callback functions
	OnMemberAdded   NamedPortMatchCallback
	OnMemberRemoved NamedPortMatchCallback

	suppressor OverlapSuppressor

	OnAlive        func()
	lastLiveReport time.Time
}

func NewSelectorAndNamedPortIndex(supressOverlaps bool) *SelectorAndNamedPortIndex {
	inheritIdx := SelectorAndNamedPortIndex{
		endpointKVIdx: labelnamevalueindex.New[any, *endpointData]("endpoints"),
		parentKVIdx:   labelnamevalueindex.New[string, *npParentData]("parents"),
		ipSetDataByID: map[string]*ipSetData{},
		selectorCandidatesIdx: labelrestrictionindex.New(
			labelrestrictionindex.WithGauges[string](
				gaugeSelectorsOpt,
				gaugeSelectorsNonOpt,
			)),

		// Callback functions
		OnMemberAdded:   func(ipSetID string, member ipsetmember.IPSetMember) {},
		OnMemberRemoved: func(ipSetID string, member ipsetmember.IPSetMember) {},
		OnAlive:         func() {},
	}
	if supressOverlaps {
		inheritIdx.suppressor = NewMemberOverlapSuppressor()
	} else {
		inheritIdx.suppressor = NewNoopMemberOverlapSuppressor()
	}
	return &inheritIdx
}

func (idx *SelectorAndNamedPortIndex) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.ResourceKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.NetworkSetKey{}, idx.OnUpdate)
}

// OnUpdate makes SelectorAndNamedPortIndex compatible with the Dispatcher.  It accepts
// updates for endpoints and profiles and passes them through to the Update/DeleteXXX methods.
func (idx *SelectorAndNamedPortIndex) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			log.Debugf("Updating NamedPortIndex with endpoint %v", key)
			endpoint := update.Value.(*model.WorkloadEndpoint)
			profileIDs := endpoint.ProfileIDs
			idx.UpdateEndpointOrSet(
				key,
				endpoint.Labels,
				extractCIDRsFromWorkloadEndpoint(endpoint),
				endpoint.Ports,
				profileIDs)
		} else {
			log.Debugf("Deleting endpoint %v from NamedPortIndex", key)
			idx.DeleteEndpoint(key)
		}
	case model.HostEndpointKey:
		if update.Value != nil {
			// Figure out what's changed and update the cache.
			log.Debugf("Updating NamedPortIndex for host endpoint %v", key)
			endpoint := update.Value.(*model.HostEndpoint)
			profileIDs := endpoint.ProfileIDs
			idx.UpdateEndpointOrSet(
				key,
				endpoint.Labels,
				extractCIDRsFromHostEndpoint(endpoint),
				endpoint.Ports,
				profileIDs)
		} else {
			log.Debugf("Deleting host endpoint %v from NamedPortIndex", key)
			idx.DeleteEndpoint(key)
		}
	case model.NetworkSetKey:
		if update.Value != nil {
			// Figure out what's changed and update the cache.
			log.Debugf("Updating NamedPortIndex for network set %v", key)
			netSet := update.Value.(*model.NetworkSet)
			profileIDs := netSet.ProfileIDs
			idx.UpdateEndpointOrSet(
				key,
				netSet.Labels,
				extractCIDRsFromNetworkSet(netSet),
				nil,
				profileIDs)
		} else {
			log.Debugf("Deleting network set %v from NamedPortIndex", key)
			idx.DeleteEndpoint(key)
		}
	case model.ResourceKey:
		if key.Kind != v3.KindProfile {
			return
		}
		if update.Value != nil {
			labels := update.Value.(*v3.Profile).Spec.LabelsToApply
			log.Debugf("Updating NamedPortIndex for profile labels %v: %v", key, labels)
			idx.UpdateParentLabels(key.Name, labels)
		} else {
			log.Debugf("Removing profile labels %v from NamedPortIndex", key)
			idx.DeleteParentLabels(key.Name)
		}
	}
	return
}

// extractCIDRsFromHostEndpoint converts the expected IPs of the host endpoint into /32 and /128
// CIDRs.
func extractCIDRsFromHostEndpoint(endpoint *model.HostEndpoint) []ip.CIDR {
	v4Addrs := endpoint.ExpectedIPv4Addrs
	v6Addrs := endpoint.ExpectedIPv6Addrs
	combined := make([]ip.CIDR, 0, len(v4Addrs)+len(v6Addrs))
	for _, addr := range v4Addrs {
		combined = append(combined, ip.FromNetIP(addr.IP).AsCIDR())
	}
	for _, addr := range v6Addrs {
		combined = append(combined, ip.FromNetIP(addr.IP).AsCIDR())
	}
	return combined
}

// extractCIDRsFromWorkloadEndpoint converts the IPv[46]Nets fields of the WorkloadEndpoint into
// /32 and /128 CIDRs.  It ignores any prefix length (but our validation ensures those nets are
// /32s or /128s in any case).
func extractCIDRsFromWorkloadEndpoint(endpoint *model.WorkloadEndpoint) []ip.CIDR {
	v4Nets := endpoint.IPv4Nets
	v6Nets := endpoint.IPv6Nets
	combined := make([]ip.CIDR, 0, len(v4Nets)+len(v6Nets))
	for _, addr := range v4Nets {
		combined = append(combined, ip.CIDRFromNetIP(addr.IP))
	}
	for _, addr := range v6Nets {
		combined = append(combined, ip.CIDRFromNetIP(addr.IP))
	}
	return combined
}

// extractCIDRsFromNetworkSet converts the Nets field of the NetworkSet into an []ip.CIDR slice.
func extractCIDRsFromNetworkSet(netSet *model.NetworkSet) []ip.CIDR {
	a := netSet.Nets
	combined := make([]ip.CIDR, 0, len(a))
	for _, addr := range a {
		cidr := ip.CIDRFromCalicoNet(addr)
		if cidr.Prefix() == 0 {
			// Special case: the linux dataplane can't handle 0-length CIDRs, so we split it into
			// multiple CIDRs.  Note: if the /1s were also in the network set, the deduplication is
			// handled by reference counting in the ipSetData struct.
			log.Debug("Converting 0 length CIDR to pair of /1s")
			switch cidr.Version() {
			case 4:
				combined = append(combined,
					ip.MustParseCIDROrIP("0.0.0.0/1"),
					ip.MustParseCIDROrIP("128.0.0.0/1"),
				)
			case 6:
				combined = append(combined,
					ip.MustParseCIDROrIP("::/1"),
					ip.MustParseCIDROrIP("8000::/1"),
				)
			default:
				log.WithField("cidr", cidr).Panic("Unknown IP version")
			}
		} else {
			// Normal case, just append the single CIDR.
			combined = append(combined, cidr)
		}
	}
	return combined
}

var defaultLogCtx = log.WithField("fieldsSuppressedAtThisLogLevel", "true")

func (idx *SelectorAndNamedPortIndex) UpdateIPSet(ipSetID string, sel *selector.Selector, namedPortProtocol ipsetmember.Protocol, namedPort string) {
	logCxt := defaultLogCtx
	if log.IsLevelEnabled(log.DebugLevel) {
		logCxt = log.WithFields(log.Fields{
			"ipSetID":           ipSetID,
			"selector":          sel,
			"namedPort":         namedPort,
			"namedPortProtocol": namedPortProtocol,
		})
		logCxt.Debug("Updating IP set")
	}
	if sel == nil {
		log.WithField("id", ipSetID).Panic("Selector should not be nil")
		panic("Selector should not be nil") // Keep linter happy.
	}

	// Check whether anything has actually changed before we do a scan.
	oldIPSetData := idx.ipSetDataByID[ipSetID]
	if oldIPSetData != nil {
		if oldIPSetData.selector.Equal(sel) &&
			oldIPSetData.namedPortProtocol == namedPortProtocol &&
			oldIPSetData.namedPort == namedPort {
			// Spurious refresh of existing IP set.
			logCxt.Debug("Skipping unchanged IP set")
			return
		}
		// This case indicates a change to the selector or named port without a change to the ID,
		// which isn't currently possible in Felix, since the ID is formed by hashing the other
		// values.  For completeness, handle (inefficiently) by simulating a deletion.
		log.WithField("ipSetID", ipSetID).Warn("IP set selector or named port changed for existing ID.")
		for m := range oldIPSetData.memberToRefCount {
			// Emit deletion events for the members.  We don't need to do that
			// for the expected, non-test code path because it's handled
			// en-masse.
			idx.onMemberRemoved(ipSetID, m)
		}
		idx.DeleteIPSet(ipSetID)
	}

	// If we get here, we have a new IP set, and we need to scan endpoints
	// against its selector.
	newIPSetData := &ipSetData{
		selector:          sel,
		namedPort:         namedPort,
		namedPortProtocol: namedPortProtocol,
		memberToRefCount:  map[ipsetmember.IPSetMember]uint64{},
	}
	idx.ipSetDataByID[ipSetID] = newIPSetData
	idx.selectorCandidatesIdx.AddSelector(ipSetID, sel)

	idx.iterEndpointCandidates(ipSetID, func(epID any, epData *endpointData) {
		idx.maybeReportLive()

		if !sel.EvaluateLabels(epData) {
			// Endpoint doesn't match.
			counterSelectorEvalsFalse.Inc()
			return
		}
		counterSelectorEvalsTrue.Inc()
		contrib := idx.CalculateEndpointContribution(epData, newIPSetData)
		if len(contrib) == 0 {
			return
		}
		if log.GetLevel() >= log.DebugLevel {
			logCxt = logCxt.WithField("epID", epID)
			logCxt.Debug("Endpoint contributes to IP set")
		}
		epData.AddMatchingIPSetID(ipSetID)
		for _, member := range contrib {
			refCount := newIPSetData.memberToRefCount[member]
			if refCount == 0 {
				if log.GetLevel() >= log.DebugLevel {
					logCxt.WithField("member", member).Debug("New IP set member")
				}
				idx.onMemberAdded(ipSetID, member)
			}
			newIPSetData.memberToRefCount[member] = refCount + 1
		}
	})
}

func (idx *SelectorAndNamedPortIndex) DeleteIPSet(setID string) {
	ipSetData := idx.ipSetDataByID[setID]

	if ipSetData == nil {
		log.WithField("id", setID).Warning("Delete of unknown IP set, ignoring")
		return
	} else {
		log.WithFields(log.Fields{
			"ipSetID":  setID,
			"selector": ipSetData.selector.String(),
		}).Info("Deleting IP set")
	}

	idx.iterEndpointCandidates(setID, func(epID any, epData *endpointData) {
		// Make sure we don't appear non-live if there are a lot of endpoints
		// to get through.  Note: we don't bother evaluating the selector
		// here since it's faster to just do the cleanup unconditionally.
		idx.maybeReportLive()
		epData.RemoveMatchingIPSetID(setID)
	})

	delete(idx.ipSetDataByID, setID)
	idx.selectorCandidatesIdx.DeleteSelector(setID)
	idx.suppressor.DeleteIPSet(setID)
}

func (idx *SelectorAndNamedPortIndex) UpdateEndpointOrSet(
	id any,
	labels uniquelabels.Map,
	nets []ip.CIDR,
	ports []model.EndpointPort,
	parentIDs []string,
) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"endpointOrSetID": id,
			"newLabels":       labels,
			"CIDRs":           nets,
			"ports":           ports,
			"parentIDs":       parentIDs,
		}).Debug("Updating endpoint/network set")
	}

	// Calculate the new endpoint data.
	newEndpointData := &endpointData{}
	if labels.Len() > 0 {
		newEndpointData.labels = labels
	}
	if len(parentIDs) > 0 {
		parents := make([]*npParentData, len(parentIDs))
		for i, pID := range parentIDs {
			parents[i] = idx.getOrCreateParent(pID)
		}
		newEndpointData.parents = parents
	}
	if len(nets) > 0 {
		newEndpointData.nets = nets
	}
	if len(ports) > 0 {
		newEndpointData.ports = ports
	}

	// Get the old endpoint data, so we can compare it.
	oldEndpointData, _ := idx.endpointKVIdx.Get(id)
	var oldIPSetContributions map[string][]ipsetmember.IPSetMember
	if oldEndpointData != nil {
		// Before we do the (potentially expensive) selector scan, check if there can possibly be a
		// change.
		if oldEndpointData.Equals(newEndpointData) {
			log.Debug("Endpoint update makes no changes, skipping.")
			return
		}

		// If we get here, something about the endpoint has changed.  Calculate the old endpoint's
		// contribution to the IP sets that it matched.
		oldIPSetContributions = idx.RecalcCachedContributions(oldEndpointData)
		// Must remove from the index and then re-add in case the labels
		// or parents have changed.
		idx.endpointKVIdx.Remove(id)
	}

	// Calculate and compare the contribution of the new endpoint to IP sets.  Emit events for
	// new contributions and then mop up deletions.
	idx.scanEndpointAgainstIPSets(newEndpointData, oldIPSetContributions)

	// Record the new endpoint data.
	idx.endpointKVIdx.Add(id, newEndpointData)

	newParentIDs := set.New[any]()
	for _, parent := range newEndpointData.parents {
		parent.AddEndpointID(id)
		newParentIDs.Add(parent.id)
	}
	if oldEndpointData != nil {
		for _, parent := range oldEndpointData.parents {
			if newParentIDs.Contains(parent.id) {
				continue
			}
			parent.DiscardEndpointID(id)
			idx.discardParentIfEmpty(parent.id)
		}
	}

	gaugeNumEndpoints.Set(float64(idx.endpointKVIdx.Len()))
}

// onMemberAdded is a wrapper around the OnMemberAdded callback that allows us to
// deduplicate any members that are masked by another member of the set, sending any necessary IPSet member
// removals for previously sent members that are now masked.
// For example, we don't need to send updates for both 10.0.0.0/24 and 10.0.0.1/32.
func (idx *SelectorAndNamedPortIndex) onMemberAdded(ipSetID string, member ipsetmember.IPSetMember) {
	if cidrMember, ok := member.(ipsetmember.CIDROrIPOnlyIPSetMember); ok {
		// We only deduplicate for IP set members that are CIDRs. Named port members and domains are always unique.
		add, removes := idx.suppressor.Add(ipSetID, cidrMember.CIDR())
		if add != nil {
			idx.OnMemberAdded(ipSetID, cidrMember)
		}
		for _, r := range removes {
			log.WithField("ipSetID", ipSetID).
				WithField("cidr", r).
				WithField("reason", cidrMember.CIDR()).
				Debug("Removing now-masked CIDR from IP set.")
			idx.OnMemberRemoved(ipSetID, ipsetmember.MakeCIDROrIPOnly(r))
		}
	} else {
		// No need to de-duplicate.
		idx.OnMemberAdded(ipSetID, member)
	}
}

// onMemberRemoved is a wrapper around the OnMemberRemoved callback that allows us to
// deduplicate any members that are masked by another member of the set, sending any necessary IPSet member
// IPSet member adds for members that were previously masked by the removed member.
func (idx *SelectorAndNamedPortIndex) onMemberRemoved(ipSetID string, member ipsetmember.IPSetMember) {
	if cidrMember, ok := member.(ipsetmember.CIDROrIPOnlyIPSetMember); ok {
		// We only deduplicate for IP set members that are CIDRs. Named port members are always unique.
		rem, adds := idx.suppressor.Remove(ipSetID, cidrMember.CIDR())
		if rem != nil {
			idx.OnMemberRemoved(ipSetID, cidrMember)
		}
		for _, a := range adds {
			log.WithField("ipSetID", ipSetID).
				WithField("cidr", a).
				WithField("reason", cidrMember.CIDR()).
				Debug("Adding previously masked CIDR to IP set.")
			idx.OnMemberAdded(ipSetID, ipsetmember.MakeCIDROrIPOnly(a))
		}
	} else {
		// No need to de-duplicate.
		idx.OnMemberRemoved(ipSetID, member)
	}
}

func (idx *SelectorAndNamedPortIndex) scanEndpointAgainstIPSets(
	epData *endpointData,
	oldIPSetContributions map[string][]ipsetmember.IPSetMember,
) {
	// Remove any previous match from the endpoint's cache.  We'll re-add it
	// below if the match is still correct.
	epData.cachedMatchingIPSetIDs.Clear()

	// Iterate over potential new matches and incref any members that
	// that produces.  (This may temporarily over count.)
	for ipSetID := range idx.selectorCandidatesIdx.AllPotentialMatches(epData) {
		// Make sure we don't appear non-live if there are a lot of IP sets to get through.
		idx.maybeReportLive()

		ipSetData := idx.ipSetDataByID[ipSetID]
		matches := ipSetData.selector.EvaluateLabels(epData)
		log.Debugf("Selector %q (%s) matches endpoint? %v", ipSetID, ipSetData.selector.String(), matches)
		if matches {
			// Record the match in the index.  This allows us to quickly recalculate the
			// contribution of this endpoint later.
			epData.AddMatchingIPSetID(ipSetID)

			// Incref all the new members.  If any of them go from 0 to 1 reference then we
			// know that they're new.  We'll temporarily double-count members that were already
			// present, then decref them below.
			//
			// This reference counting also allows us to tolerate duplicate members in the
			// input data.
			newIPSetContribution := idx.CalculateEndpointContribution(epData, ipSetData)
			for _, newMember := range newIPSetContribution {
				newRefCount := ipSetData.memberToRefCount[newMember] + 1
				if newRefCount == 1 {
					// New member in the IP set.
					idx.onMemberAdded(ipSetID, newMember)
				}
				ipSetData.memberToRefCount[newMember] = newRefCount
			}
		}
	}

	// Decref all the old matches, emitting events if we drop to zero.
	for ipSetID, oldMembers := range oldIPSetContributions {
		// Decref all the old members.  If they hit 0 references, then the member has been
		// removed so we emit an event.
		ipSetData := idx.ipSetDataByID[ipSetID]
		for _, oldMember := range oldMembers {
			newRefCount := ipSetData.memberToRefCount[oldMember] - 1
			if newRefCount == 0 {
				// Member no longer in the IP set.  Emit event and clean up the old reference
				// count.
				log.Debugf("Member removed: %s, %v", ipSetID, oldMember)
				idx.onMemberRemoved(ipSetID, oldMember)
				delete(ipSetData.memberToRefCount, oldMember)
			} else {
				ipSetData.memberToRefCount[oldMember] = newRefCount
			}
		}
	}
}

func (idx *SelectorAndNamedPortIndex) DeleteEndpoint(id any) {
	log.Debug("SelectorAndNamedPortIndex deleting endpoint", id)
	oldEndpointData, ok := idx.endpointKVIdx.Get(id)
	if !ok {
		return
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithField("oldContrib", oldEndpointData.cachedMatchingIPSetIDs.String()).Debug("Old matching IP sets")
	}
	oldIPSetContributions := idx.RecalcCachedContributions(oldEndpointData)
	for ipSetID, contributions := range oldIPSetContributions {
		// Decref all the old members.  If they hit 0 references, then the member has been
		// removed so we emit an event.
		log.WithField("ipSetID", ipSetID).Debug("Removing endpoint from IP set")
		ipSetData := idx.ipSetDataByID[ipSetID]
		for _, oldMember := range contributions {
			newRefCount := ipSetData.memberToRefCount[oldMember] - 1
			if newRefCount == 0 {
				// Member no longer in the IP set.  Emit event and clean up the old reference
				// count.
				idx.onMemberRemoved(ipSetID, oldMember)
				delete(ipSetData.memberToRefCount, oldMember)
			} else {
				ipSetData.memberToRefCount[oldMember] = newRefCount
			}
		}
	}

	// Record the new endpoint data.
	idx.endpointKVIdx.Remove(id)
	for _, parent := range oldEndpointData.parents {
		parent.DiscardEndpointID(id)
		idx.discardParentIfEmpty(parent.id)
	}
	gaugeNumEndpoints.Set(float64(idx.endpointKVIdx.Len()))
}

func (idx *SelectorAndNamedPortIndex) UpdateParentLabels(parentID string, rawLabels map[string]string) {
	parentData := idx.getOrCreateParent(parentID)
	labels := uniquelabels.Make(rawLabels) // FIXME Should we move this upstream?
	if parentData.labels.Equals(labels) {
		log.WithField("parentID", parentID).Debug("Skipping no-op update to parent labels")
		return
	}
	// Must remove the parent from the index while we mutate its labels.
	idx.parentKVIdx.Remove(parentID)
	oldLabels := parentData.labels
	idx.updateParent(
		parentData,
		// Function to apply the update.
		func() {
			parentData.labels = labels
		},
		// Function to back out the update.
		func() {
			parentData.labels = oldLabels
		},
	)
	idx.parentKVIdx.Add(parentID, parentData)
}

func (idx *SelectorAndNamedPortIndex) updateParent(parentData *npParentData, applyUpdate, revertUpdate func()) {
	parentData.IterEndpointIDs(func(id any) error {
		epData, _ := idx.endpointKVIdx.Get(id)
		// This endpoint matches this parent, calculate its old contribution.  (The revert function
		// is a no-op on the first loop but keeping it here, rather than at the bottom of the loop
		// makes it harder to accidentally skip it with a well-intentioned "continue".)
		revertUpdate()
		oldIPSetContributions := idx.RecalcCachedContributions(epData)

		// Apply the update to the parent while we calculate this endpoint's new contribution.
		applyUpdate()
		idx.scanEndpointAgainstIPSets(epData, oldIPSetContributions)

		return nil
	})

	// Defensive: make sure we leave the update applied to the parent.
	applyUpdate()
}

func (idx *SelectorAndNamedPortIndex) DeleteParentLabels(parentID string) {
	// Defer to the update function, which implements the endpoint scanning logic.
	log.Debugf("Deleting parent labels: %v", parentID)
	idx.UpdateParentLabels(parentID, nil)
	idx.discardParentIfEmpty(parentID)
}

// CalculateEndpointContribution calculates the given endpoint's contribution to the given IP set.
// If the IP set represents a named port then the returned members will have a named port component.
// Returns nil if the endpoint doesn't contribute to the IP set.
func (idx *SelectorAndNamedPortIndex) CalculateEndpointContribution(d *endpointData, ipSetData *ipSetData) (contrib []ipsetmember.IPSetMember) {
	if ipSetData.namedPortProtocol != ipsetmember.ProtocolNone {
		// This IP set represents a named port match, calculate the cross product of
		// matching named ports by IP address.
		portNumbers := d.LookupNamedPorts(ipSetData.namedPort, ipSetData.namedPortProtocol)
		for _, namedPort := range portNumbers {
			for _, cidr := range d.nets {
				// Named ports are always single IP addresses.
				ipAddr := cidr.Addr()
				contrib = append(
					contrib,
					ipsetmember.MakeIPPortProto(ipAddr, namedPort, ipSetData.namedPortProtocol),
				)
			}
		}
	} else {
		// Non-named port match, simply return the CIDRs.
		for _, addr := range d.nets {
			contrib = append(contrib, ipsetmember.MakeCIDROrIPOnly(addr))
		}
	}
	return
}

// RecalcCachedContributions uses the cached set of matching IP set IDs in the endpoint
// struct to quickly recalculate the endpoint's contribution to all IP sets.
func (idx *SelectorAndNamedPortIndex) RecalcCachedContributions(epData *endpointData) map[string][]ipsetmember.IPSetMember {
	if epData.cachedMatchingIPSetIDs.Len() == 0 {
		return nil
	}
	contrib := map[string][]ipsetmember.IPSetMember{}
	for ipSetID := range epData.cachedMatchingIPSetIDs.All() {
		ipSetData := idx.ipSetDataByID[ipSetID]
		if ipSetData == nil {
			log.WithField("ipSetID", ipSetID).Panic("Endpoint cachedMatchingIPSetIDs refers to nonexistent IP set.")
		}
		contrib[ipSetID] = idx.CalculateEndpointContribution(epData, ipSetData)
	}
	return contrib
}

func (idx *SelectorAndNamedPortIndex) getOrCreateParent(id string) *npParentData {
	parent, ok := idx.parentKVIdx.Get(id)
	if !ok {
		parent = &npParentData{
			id: id,
		}
		idx.parentKVIdx.Add(id, parent)
	}
	return parent
}

func (idx *SelectorAndNamedPortIndex) discardParentIfEmpty(id string) {
	parent, ok := idx.parentKVIdx.Get(id)
	if !ok {
		return
	}
	if parent.endpointIDs == nil && parent.labels.IsNil() {
		idx.parentKVIdx.Remove(id)
	}
}

func (idx *SelectorAndNamedPortIndex) maybeReportLive() {
	// We report from some tight loops so rate limit our reports.
	if time.Since(idx.lastLiveReport) < 100*time.Millisecond {
		return
	}
	idx.OnAlive()
	idx.lastLiveReport = time.Now()
}

// iterEndpointCandidates iterates over the subset of endpoints that the
// index says _may_ match the given IP set's selector.  It may produce additional
// non-matching endpoints (or all endpoints if no optimization is available).
func (idx *SelectorAndNamedPortIndex) iterEndpointCandidates(ipsetID string, f func(epID any, epData *endpointData)) {
	sel := idx.ipSetDataByID[ipsetID].selector
	restrictions := sel.LabelRestrictions()
	log.Debugf("Selector %s restrictions: %v", sel.String(), restrictions)

	// Implementation: endpoint labels and parent labels are each indexed
	// separately.  We consult the endpoint and parent indexes for each
	// "label restriction" extracted from the selector and keep track of the
	// best available scan strategy for endpoints and parents.  Then, compare
	// the best endpoint strategy vs the best parent strategy.

	bestEPStrategy := idx.endpointKVIdx.FullScanStrategy()
	bestParentStrategy := labelnamevalueindex.ScanStrategy[string](nil)
	bestParentEndpointEstimate := math.MaxInt

	for k, r := range restrictions.All() {
		epStrat := idx.endpointKVIdx.StrategyFor(k, r)
		parentStrat := idx.parentKVIdx.StrategyFor(k, r)
		epsToScan := epStrat.EstimatedItemsToScan()
		parentsToScan := parentStrat.EstimatedItemsToScan()

		if epsToScan > 0 && parentsToScan == 0 {
			// Label matches no parents, but it does match some endpoints.
			if epsToScan < bestEPStrategy.EstimatedItemsToScan() {
				bestEPStrategy = epStrat
				log.Debugf("New best endpoint strategy: %s (%d)", bestEPStrategy, bestEPStrategy.EstimatedItemsToScan())
			}
		} else if epsToScan == 0 && parentsToScan > 0 {
			// Label matches no endpoints but it does match some parents.
			// (e.g. a Kubernetes namespace selector).
			parentEstimate := idx.estimateParentEndpointScanCount(parentStrat)
			if bestParentStrategy == nil || parentEstimate < bestParentEndpointEstimate {
				log.Debugf("New best parent strategy: %s", parentStrat)
				bestParentStrategy = parentStrat
				bestParentEndpointEstimate = parentEstimate
			}
		} else if parentsToScan > 0 && epsToScan > 0 {
			// Label matches both endpoints and parents.  This is impossible in
			// Kubernetes but it may be possible in OpenStack (or something
			// home-grown using raw etcd data).  For now don't try to optimize.
			log.WithField("label", k).Debug(
				"Label applies to both endpoints and parents, cannot do optimised scan.")
		} else {
			// This restriction rules out both a match on parent and a match
			// on endpoint.
			log.Debugf("Label restriction on label %s rules out both parent and endpoint match.", k.Value())
			return
		}
	}

	if bestEPStrategy.EstimatedItemsToScan() <= bestParentEndpointEstimate {
		log.Debugf("Selector %q (%s) using endpoint scan strategy: %s", ipsetID, sel.String(), bestEPStrategy.String())
		counterVecScanStrat.WithLabelValues("endpoint-" + bestEPStrategy.Name()).Inc()
		bestEPStrategy.Scan(func(id any) bool {
			ep, _ := idx.endpointKVIdx.Get(id)
			f(id, ep)
			return true
		})
	} else {
		log.Debugf("Selector %s using parent scan strategy: %s", sel.String(), bestParentStrategy.String())
		seenEPIDs := set.New[any]()
		counterVecScanStrat.WithLabelValues("parent-" + bestParentStrategy.Name()).Inc()
		bestParentStrategy.Scan(func(parentID string) bool {
			parent, _ := idx.parentKVIdx.Get(parentID)
			parent.IterEndpointIDs(func(id any) error {
				if seenEPIDs.Contains(id) {
					return nil
				}
				seenEPIDs.Add(id)
				ep, _ := idx.endpointKVIdx.Get(id)
				f(id, ep)
				return nil
			})
			return true
		})
	}
}

func (idx *SelectorAndNamedPortIndex) estimateParentEndpointScanCount(s labelnamevalueindex.ScanStrategy[string]) int {
	numScanned := 0
	total := 0
	const maxNumToScan = 10
	s.Scan(func(id string) bool {
		parent, _ := idx.parentKVIdx.Get(id)
		if parent.endpointIDs != nil {
			parentSize := parent.endpointIDs.Len()
			total += parentSize
		}
		numScanned++
		return numScanned < maxNumToScan
	})
	if numScanned <= maxNumToScan {
		// Exact answer.
		return total
	}
	return (total*s.EstimatedItemsToScan() + maxNumToScan - 1) / maxNumToScan
}

func NewMemberOverlapSuppressor() OverlapSuppressor {
	return &memberDeduplicator{
		v4tries: map[string]*ip.CIDRTrie{},
		v6tries: map[string]*ip.CIDRTrie{},
	}
}

func NewNoopMemberOverlapSuppressor() OverlapSuppressor {
	return &noopMemberDeduplicator{}
}

type OverlapSuppressor interface {
	Add(set string, cidr ip.CIDR) (ip.CIDR, []ip.CIDR)
	Remove(set string, cidr ip.CIDR) (ip.CIDR, []ip.CIDR)
	DeleteIPSet(set string)
}

// noopMemberDeduplicator is a MemberDeduplicator that doesn't deduplicate members. Can be used
// when deduplication is not required.
type noopMemberDeduplicator struct{}

func (n *noopMemberDeduplicator) Add(set string, cidr ip.CIDR) (ip.CIDR, []ip.CIDR) {
	return cidr, nil
}

func (n *noopMemberDeduplicator) Remove(set string, cidr ip.CIDR) (ip.CIDR, []ip.CIDR) {
	return cidr, nil
}

func (n *noopMemberDeduplicator) DeleteIPSet(set string) {
}

// memberDeduplicator is a MemberDeduplicator that deduplicates members that are masked by other members.
type memberDeduplicator struct {
	v4tries map[string]*ip.CIDRTrie
	v6tries map[string]*ip.CIDRTrie

	// buf is a buffer used internally by the memberDeduplicator to minimize slice allocations.
	buf []ip.CIDR
}

func (t *memberDeduplicator) getTrie(set string, v6 bool) *ip.CIDRTrie {
	var tries map[string]*ip.CIDRTrie
	if v6 {
		tries = t.v6tries
	} else {
		tries = t.v4tries
	}
	trie, ok := tries[set]
	if !ok {
		trie = ip.NewCIDRTrie()
		tries[set] = trie
	}
	return trie
}

// Add adds the given CIDR to the trie. It returns a CIDR to add and a slice of CIDRs to remove if applicable.
func (t *memberDeduplicator) Add(set string, cidr ip.CIDR) (ip.CIDR, []ip.CIDR) {
	v6 := strings.Contains(cidr.String(), ":")
	trie := t.getTrie(set, v6)

	// Check if this IP is already covered by another entry in the trie.
	covered := trie.Covers(cidr)

	// Add to the trie.
	trie.Update(cidr, cidr)

	if covered {
		return nil, nil
	}

	// This is a new CIDR - we need to check to see if it masks any other CIDRs we have already sent.
	// Get the node and check if it has any children. If it does, those children are masked by this new CIDR
	// and need to be withdrawn.
	t.buf = t.buf[:0]
	masked := trie.ClosestDescendants(t.buf, cidr)
	return cidr, masked
}

// Remove removes the given CIDR from the trie. It returns a CIDR to remove and a slice of CIDRs to add back if applicable.
func (t *memberDeduplicator) Remove(set string, cidr ip.CIDR) (ip.CIDR, []ip.CIDR) {
	v6 := strings.Contains(cidr.String(), ":")
	trie := t.getTrie(set, v6)

	// If this node has children that are masked by this CIDR, we need to
	// advertise them against as part of this deletion.
	t.buf = t.buf[:0]
	masked := trie.ClosestDescendants(t.buf, cidr)

	// Remove from the trie.
	trie.Delete(cidr)

	return cidr, masked
}

func (t *memberDeduplicator) DeleteIPSet(set string) {
	delete(t.v4tries, set)
	delete(t.v6tries, set)
}
