// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	log "github.com/sirupsen/logrus"

	"reflect"

	"strings"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/set"
)

// endpointData holds the data that we need to know about a particular endpoint.
type endpointData struct {
	labels  map[string]string
	ipAddrs []ip.Addr
	ports   []model.EndpointPort
	parents []*npParentData

	cachedMatchingIPSetIDs set.Set /* or, as an optimization, nil if there are none */
}

func (d *endpointData) AddMatchingIPSetID(id string) {
	if d.cachedMatchingIPSetIDs == nil {
		d.cachedMatchingIPSetIDs = set.New()
	}
	d.cachedMatchingIPSetIDs.Add(id)
}

func (d *endpointData) RemoveMatchingIPSetID(id string) {
	if d.cachedMatchingIPSetIDs == nil {
		return
	}
	d.cachedMatchingIPSetIDs.Discard(id)
	if d.cachedMatchingIPSetIDs.Len() == 0 {
		d.cachedMatchingIPSetIDs = nil
	}
}

func (d *endpointData) HasParent(parent *npParentData) bool {
	for _, p := range d.parents {
		if p == parent {
			return true
		}
	}
	return false
}

func (d *endpointData) LookupNamedPort(name string, proto IPSetPortProtocol) *model.EndpointPort {
	for _, p := range d.ports {
		if p.Name == name && proto.MatchesModelProtocol(p.Protocol) {
			return &p
		}
	}
	return nil
}

type IPSetPortProtocol uint8

func (p IPSetPortProtocol) MatchesModelProtocol(protocol numorstring.Protocol) bool {
	if protocol.Type == numorstring.NumOrStringNum {
		if protocol.NumVal == 0 {
			// Special case: named ports default to TCP if protocol isn't specified.
			return p == ProtocolTCP
		}
		return protocol.NumVal == uint8(p)
	}
	switch p {
	case ProtocolTCP:
		return strings.ToLower(protocol.StrVal) == "tcp"
	case ProtocolUDP:
		return strings.ToLower(protocol.StrVal) == "udp"
	}
	log.WithField("protocol", p).Panic("Unknown protocol")
	return false
}

func (p IPSetPortProtocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolNone:
		return "none"
	default:
		return "unknown"
	}
}

const (
	ProtocolNone IPSetPortProtocol = 0
	ProtocolTCP  IPSetPortProtocol = 6
	ProtocolUDP  IPSetPortProtocol = 17
)

type IPSetMember struct {
	IP         ip.Addr
	Protocol   IPSetPortProtocol
	PortNumber uint16
}

type ipSetData struct {
	// The selector and named port that this IP set represents.  If the selector is nil then
	// this IP set represents an unfiltered named port.  If namedPortProtocol == ProtocolNone then
	// this IP set represents a selector only, with no named port component.
	selector          selector.Selector
	namedPortProtocol IPSetPortProtocol
	namedPort         string

	// memberToRefCount stores a reference count for each member in the IP set.  Reference counts
	// may be >1 if an IP address is shared by more than one endpoint.
	memberToRefCount map[IPSetMember]uint64
}

// Get implements the Labels interface for endpointData.  Combines the endpoint's own labels with
// those of its parents on the fly.  This reduces the number of allocations we need to do and
// it's fast in the mainline case (where there are 0-1 parents).
func (endpointData *endpointData) Get(labelName string) (value string, present bool) {
	if value, present = endpointData.labels[labelName]; present {
		return
	}
	for _, parent := range endpointData.parents {
		if value, present = parent.labels[labelName]; present {
			return
		}
		for _, tag := range parent.tags {
			if tag == labelName {
				present = true
				return
			}
		}
	}
	return
}

// npParentData holds the data that we know about each parent (i.e. each security profile).  Since,
// profiles consist of multiple resources in our data-model, the labels or tags fields may be nil
// if we have partial information.
type npParentData struct {
	id             string
	labels         map[string]string
	tags           []string
	referenceCount uint64
}

type NamedPortMatchCallback func(ipSetID string, member IPSetMember)

type SelectorAndNamedPortIndex struct {
	endpointDataByID     map[interface{}]*endpointData
	parentDataByParentID map[string]*npParentData
	ipSetDataByID        map[string]*ipSetData

	// Callback functions
	OnMemberAdded   NamedPortMatchCallback
	OnMemberRemoved NamedPortMatchCallback
}

func NewSelectorAndNamedPortIndex() *SelectorAndNamedPortIndex {
	inheritIdx := SelectorAndNamedPortIndex{
		endpointDataByID:     map[interface{}]*endpointData{},
		parentDataByParentID: map[string]*npParentData{},
		ipSetDataByID:        map[string]*ipSetData{},

		// Callback functions
		OnMemberAdded:   func(ipSetID string, member IPSetMember) {},
		OnMemberRemoved: func(ipSetID string, member IPSetMember) {},
	}
	return &inheritIdx
}

func (idx *SelectorAndNamedPortIndex) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.ProfileTagsKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.ProfileLabelsKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, idx.OnUpdate)
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
			idx.UpdateEndpoint(
				key,
				endpoint.Labels,
				convertNets(endpoint.IPv4Nets, endpoint.IPv6Nets),
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
			idx.UpdateEndpoint(
				key,
				endpoint.Labels,
				convertIPs(endpoint.ExpectedIPv4Addrs, endpoint.ExpectedIPv6Addrs),
				endpoint.Ports,
				profileIDs)
		} else {
			log.Debugf("Deleting host endpoint %v from NamedPortIndex", key)
			idx.DeleteEndpoint(key)
		}
	case model.ProfileLabelsKey:
		if update.Value != nil {
			log.Debugf("Updating NamedPortIndex for profile labels %v", key)
			labels := update.Value.(map[string]string)
			idx.UpdateParentLabels(key.Name, labels)
		} else {
			log.Debugf("Removing profile labels %v from NamedPortIndex", key)
			idx.DeleteParentLabels(key.Name)
		}
	case model.ProfileTagsKey:
		if update.Value != nil {
			log.Debugf("Updating NamedPortIndex for profile tags %v", key)
			labels := update.Value.([]string)
			idx.UpdateParentTags(key.Name, labels)
		} else {
			log.Debugf("Removing profile tags %v from NamedPortIndex", key)
			idx.DeleteParentTags(key.Name)
		}
	}
	return
}

func convertIPs(a, b []net.IP) []ip.Addr {
	combined := make([]ip.Addr, 0, len(a)+len(b))
	for _, addr := range a {
		combined = append(combined, ip.FromNetIP(addr.IP))
	}
	for _, addr := range b {
		combined = append(combined, ip.FromNetIP(addr.IP))
	}
	return combined
}

func convertNets(a, b []net.IPNet) []ip.Addr {
	combined := make([]ip.Addr, 0, len(a)+len(b))
	for _, addr := range a {
		combined = append(combined, ip.FromNetIP(addr.IP))
	}
	for _, addr := range b {
		combined = append(combined, ip.FromNetIP(addr.IP))
	}
	return combined
}

func (idx *SelectorAndNamedPortIndex) UpdateIPSet(ipSetID string, sel selector.Selector, namedPortProtocol IPSetPortProtocol, namedPort string) {
	logCxt := log.WithFields(log.Fields{
		"ipSetID":           ipSetID,
		"selector":          sel,
		"namedPort":         namedPort,
		"namedPortProtocol": namedPortProtocol,
	})
	logCxt.Debug("Updating IP set")
	if sel == nil {
		log.WithField("id", ipSetID).Panic("Selector should not be nil")
	}

	// Check whether anything has actually changed before we do a scan.
	oldIPSetData := idx.ipSetDataByID[ipSetID]
	if oldIPSetData != nil {
		if oldIPSetData.selector.UniqueID() == sel.UniqueID() &&
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
		idx.DeleteIPSet(ipSetID)
	}

	// If we get here, we have a new IP set and we need to do a full scan of all endpoints.
	newIPSetData := &ipSetData{
		selector:          sel,
		namedPort:         namedPort,
		namedPortProtocol: namedPortProtocol,
		memberToRefCount:  map[IPSetMember]uint64{},
	}
	idx.ipSetDataByID[ipSetID] = newIPSetData

	// Then scan all endpoints.
	for epID, epData := range idx.endpointDataByID {
		if !sel.EvaluateLabels(epData) {
			// Endpoint doesn't match.
			continue
		}
		contrib := idx.CalculateEndpointContribution(epData, newIPSetData)
		if len(contrib) == 0 {
			continue
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
				idx.OnMemberAdded(ipSetID, member)
			}
			newIPSetData.memberToRefCount[member] = refCount + 1
		}
	}
}

func (idx *SelectorAndNamedPortIndex) DeleteIPSet(id string) {
	log.WithField("ipSetID", id).Info("Deleting IP set")

	ipSetData := idx.ipSetDataByID[id]
	if ipSetData == nil {
		log.WithField("id", id).Warning("Delete of unknown IP set, ignoring")
		return
	}

	// Emit events for all the removed IPs.
	for member := range ipSetData.memberToRefCount {
		if log.GetLevel() >= log.DebugLevel {
			log.WithField("member", member).Debug("Emitting deletion event.")
		}
		idx.OnMemberRemoved(id, member)
	}

	// Then scan all endpoints and fix up their indexes to remove the match.
	for _, epData := range idx.endpointDataByID {
		epData.RemoveMatchingIPSetID(id)
	}

	delete(idx.ipSetDataByID, id)
}

func (idx *SelectorAndNamedPortIndex) UpdateEndpoint(
	id interface{},
	labels map[string]string,
	ips []ip.Addr,
	ports []model.EndpointPort,
	parentIDs []string,
) {
	logCxt := log.WithFields(log.Fields{
		"endpointID": id,
		"newLabels":  labels,
		"IPs":        ips,
		"ports":      ports,
		"parentIDs":  parentIDs,
	})
	logCxt.Debug("Updating endpoint")

	// Calculate the new endpoint data.
	newEndpointData := &endpointData{}
	if len(labels) > 0 {
		newEndpointData.labels = labels
	}
	if len(parentIDs) > 0 {
		parents := make([]*npParentData, len(parentIDs))
		for i, pID := range parentIDs {
			parents[i] = idx.getOrCreateParent(pID)
		}
		newEndpointData.parents = parents
	}
	if len(ips) > 0 {
		newEndpointData.ipAddrs = ips
	}
	if len(ports) > 0 {
		newEndpointData.ports = ports
	}

	// Get the old endpoint data so we can compare it.
	oldEndpointData := idx.endpointDataByID[id]
	var oldIPSetContributions map[string][]IPSetMember
	if oldEndpointData != nil {
		// Before we do the (potentially expensive) selector scan, check if there can possibly be a
		// change.
		if reflect.DeepEqual(oldEndpointData.labels, newEndpointData.labels) &&
			reflect.DeepEqual(oldEndpointData.ports, newEndpointData.ports) &&
			reflect.DeepEqual(oldEndpointData.ipAddrs, newEndpointData.ipAddrs) &&
			reflect.DeepEqual(oldEndpointData.parents, newEndpointData.parents) {
			log.Debug("Endpoint update makes no changes, skipping.")
			return
		}

		// If we get here, something about the endpoint has changed.  Calculate the old endpoint's
		// contribution to the IP sets that it matched.
		oldIPSetContributions = idx.RecalcCachedContributions(oldEndpointData)
	}

	// Calculate and compare the contribution of the new endpoint to IP sets.  Emit events for
	// new contributions and then mop up deletions.
	idx.scanEndpointAgainstAllIPSets(newEndpointData, oldIPSetContributions)

	// Record the new endpoint data.
	idx.endpointDataByID[id] = newEndpointData

	for _, parent := range newEndpointData.parents {
		parent.referenceCount++
	}
	if oldEndpointData != nil {
		for _, parent := range oldEndpointData.parents {
			parent.referenceCount--
			idx.discardParentIfEmpty(parent.id)
		}
	}
}

func (idx *SelectorAndNamedPortIndex) scanEndpointAgainstAllIPSets(
	epData *endpointData,
	oldIPSetContributions map[string][]IPSetMember,
) {
	for ipSetID, ipSetData := range idx.ipSetDataByID {
		// Remove any previous match from the endpoint's cache.  We'll re-add it below if the match
		// is still correct.  (This is a no-op when we're called from UpdateEndpoint(), which always
		// creates a new endpointData struct.)
		epData.RemoveMatchingIPSetID(ipSetID)

		if ipSetData.selector.EvaluateLabels(epData) {
			newIPSetContribution := idx.CalculateEndpointContribution(epData, ipSetData)
			if len(newIPSetContribution) > 0 {
				// Record the match in the index.  This allows us to quickly recalculate the
				// contribution of this endpoint later.
				epData.AddMatchingIPSetID(ipSetID)

				// Incref all the new members.  If any of them go from 0 to 1 reference then we
				// know that they're new.  We'll temporarily double-count members that were already
				// present, then decref them below.
				for _, newMember := range newIPSetContribution {
					newRefCount := ipSetData.memberToRefCount[newMember] + 1
					if newRefCount == 1 {
						// New member in the IP set.
						idx.OnMemberAdded(ipSetID, newMember)
					}
					ipSetData.memberToRefCount[newMember] = newRefCount
				}
			}
		}

		// Decref all the old members.  If they hit 0 references, then the member has been
		// removed so we emit an event.
		for _, oldMember := range oldIPSetContributions[ipSetID] {
			newRefCount := ipSetData.memberToRefCount[oldMember] - 1
			if newRefCount == 0 {
				// Member no longer in the IP set.  Emit event and clean up the old reference
				// count.
				idx.OnMemberRemoved(ipSetID, oldMember)
				delete(ipSetData.memberToRefCount, oldMember)
			} else {
				ipSetData.memberToRefCount[oldMember] = newRefCount
			}
		}
	}
}

func (idx *SelectorAndNamedPortIndex) DeleteEndpoint(id interface{}) {
	log.Debug("SelectorAndNamedPortIndex deleting endpoint", id)
	oldEndpointData := idx.endpointDataByID[id]
	if oldEndpointData == nil {
		return
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
				idx.OnMemberRemoved(ipSetID, oldMember)
				delete(ipSetData.memberToRefCount, oldMember)
			} else {
				ipSetData.memberToRefCount[oldMember] = newRefCount
			}
		}
	}

	// Record the new endpoint data.
	delete(idx.endpointDataByID, id)
	for _, parent := range oldEndpointData.parents {
		parent.referenceCount--
		idx.discardParentIfEmpty(parent.id)
	}
}

func (idx *SelectorAndNamedPortIndex) UpdateParentLabels(parentID string, labels map[string]string) {
	parentData := idx.getOrCreateParent(parentID)
	if reflect.DeepEqual(parentData.labels, labels) {
		log.WithField("parentID", parentID).Debug("Skipping no-op update to parent labels")
		return
	}
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
}

func (idx *SelectorAndNamedPortIndex) UpdateParentTags(parentID string, tags []string) {
	parentData := idx.getOrCreateParent(parentID)
	if reflect.DeepEqual(parentData.tags, tags) {
		log.WithField("parentID", parentID).Debug("Skipping no-op update to parent labels")
		return
	}
	oldTags := parentData.tags
	idx.updateParent(
		parentData,
		// Function to apply the update.
		func() {
			parentData.tags = tags
		},
		// Function to back out the update.
		func() {
			parentData.tags = oldTags
		},
	)
}

func (idx *SelectorAndNamedPortIndex) updateParent(parentData *npParentData, applyUpdate, revertUpdate func()) {
	for _, epData := range idx.endpointDataByID {
		if !epData.HasParent(parentData) {
			continue
		}

		// This endpoint matches this parent, calculate its old contribution.  (The revert function
		// is a no-op on the first loop but keeping it here, rather than at the bottom of the loop
		// makes it harder to accidentally skip it with a well-intentioned "continue".)
		revertUpdate()
		oldIPSetContributions := idx.RecalcCachedContributions(epData)

		// Apply the update to the parent while we calculate this endpoint's new contribution.
		applyUpdate()
		idx.scanEndpointAgainstAllIPSets(epData, oldIPSetContributions)
	}

	// Defensive: make sure we leave the update applied to the parent.
	applyUpdate()
}

func (idx *SelectorAndNamedPortIndex) DeleteParentLabels(parentID string) {
	// Defer to the update function, which implements the endpoint scanning logic.
	idx.UpdateParentLabels(parentID, nil)
	idx.discardParentIfEmpty(parentID)
}

// CalculateEndpointContribution calculates the given endpoint's contribution to the given IP set.
// If the IP set represents a named port then the returned members will have a named port component.
// Returns nil if the endpoint doesn't contribute to the IP set.
func (idx *SelectorAndNamedPortIndex) CalculateEndpointContribution(d *endpointData, ipSetData *ipSetData) (contrib []IPSetMember) {
	var namedPort *model.EndpointPort
	if ipSetData.namedPortProtocol != ProtocolNone {
		namedPort = d.LookupNamedPort(ipSetData.namedPort, ipSetData.namedPortProtocol)
		if namedPort == nil {
			return
		}
	}
	for _, addr := range d.ipAddrs {
		member := IPSetMember{
			IP: addr,
		}
		if ipSetData.namedPortProtocol != ProtocolNone {
			member.Protocol = ipSetData.namedPortProtocol
			member.PortNumber = namedPort.Port
		}
		contrib = append(contrib, member)
	}
	return
}

// RecalcCachedContributions uses the cached set of matching IP set IDs in the endpoint
// struct to quickly recalculate the endpoint's contribution to all IP sets.
func (idx *SelectorAndNamedPortIndex) RecalcCachedContributions(epData *endpointData) map[string][]IPSetMember {
	if epData.cachedMatchingIPSetIDs == nil {
		return nil
	}
	contrib := map[string][]IPSetMember{}
	epData.cachedMatchingIPSetIDs.Iter(func(item interface{}) error {
		ipSetID := item.(string)
		ipSetData := idx.ipSetDataByID[ipSetID]
		contrib[ipSetID] = idx.CalculateEndpointContribution(epData, ipSetData)
		return nil
	})
	return contrib
}

func (idx *SelectorAndNamedPortIndex) DeleteParentTags(parentID string) {
	idx.UpdateParentTags(parentID, nil)
	idx.discardParentIfEmpty(parentID)
}

func (idx *SelectorAndNamedPortIndex) getOrCreateParent(id string) *npParentData {
	parent := idx.parentDataByParentID[id]
	if parent == nil {
		parent = &npParentData{
			id: id,
		}
		idx.parentDataByParentID[id] = parent
	}
	return parent
}

func (idx *SelectorAndNamedPortIndex) discardParentIfEmpty(id string) {
	parent := idx.parentDataByParentID[id]
	if parent == nil {
		return
	}
	if parent.referenceCount == 0 && parent.labels == nil && parent.tags == nil {
		delete(idx.parentDataByParentID, id)
	}
}
