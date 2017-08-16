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

// The labelindex package provides the NamedPortIndex type, which emits events as the set of
// endpoints (currently WorkloadEndpoints/HostEndpoint) it has been told about start (or stop) matching
// the label selectors (which are extracted from the active policy rules) it has been told about.
//
// Label inheritance
//
// As the name suggests, the NamedPortIndex supports the notion of label inheritance.  In our
// data-model:
//
//     - endpoints have their own labels; these take priority over any inherited labels
//     - endpoints also inherit labels from any explicitly-named profiles in their data
//     - profiles have explicit labels
//     - profiles also have (now deprecated) tags, which we now treat as implicit <tagName>=""
//       labels; explicit profile labels take precidence over implicit tag labels.
//
// For example, suppose an endpoint had labels
//
//     {"a": "ep-a", "b": "ep-b"}
//
// and it explicitly referenced profile "profile-A", which had these labels and tags:
//
//     {"a": "prof-a", "c": "prof-c", "d": "prof-d"}
//     ["a", "tag-x", "d"]
//
// then the resulting labels for the endpoint after considering inheritance would be:
//
//     {
//         "a": "ep-a",    // Explicit endpoint label "wins" over profile labels/tags.
//         "b": "ep-b",
//         "c": "prof-c",  // Profile label gets inherited.
//         "d": "prof-d",  // Profile label "wins" over profile tag with same name.
//         "tag-x": "",    // Profile tag inherited as empty label.
//     }
package labelindex

import (
	log "github.com/sirupsen/logrus"

	"reflect"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type namedPort struct {
	name     string
	port     uint16
	protocol IPSetPortProtocol
}

// endpointData holds the data that we need to know about a particular endpoint.
type endpointData struct {
	labels  map[string]string
	ips     []ip.Addr
	ports   []namedPort
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

func (d *endpointData) CachedContribution(ipSetDataByID map[string]*ipSetData) map[string][]IPSetMember {
	if d.cachedMatchingIPSetIDs == nil {
		return nil
	}
	contrib := map[string][]IPSetMember{}
	d.cachedMatchingIPSetIDs.Iter(func(item interface{}) error {
		ipSetID := item.(string)
		ipSetData := ipSetDataByID[ipSetID]
		contrib[ipSetID] = d.CalculateContribution(ipSetData)
		return nil
	})
	return contrib
}

func (d *endpointData) CalculateContribution(ipSetData *ipSetData) (contrib []IPSetMember) {
	for _, ip := range d.ips {
		member := IPSetMember{
			IP: ip,
		}
		if ipSetData.namedPortProtocol != ProtocolNone {
			namedPort := d.LookupNamedPort(ipSetData.namedPort, ipSetData.namedPortProtocol)
			member.PortNumber = namedPort.port
			member.Protocol = ipSetData.namedPortProtocol
		}
		contrib = append(contrib, member)
	}
	return
}

func (d *endpointData) LookupNamedPort(name string, proto IPSetPortProtocol) *namedPort {
	for _, p := range d.ports {
		if p.name == name && p.protocol == proto {
			return &p
		}
	}
	return nil
}

type IPSetPortProtocol uint8

const (
	ProtocolNone IPSetPortProtocol = 0
	ProtocolTCP                    = 6
	ProtocolUDP                    = 17
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
// profiles consist of multiple resources in our data-model, any of the fields may be nil if we
// have partial information.
type npParentData struct {
	id             string
	labels         map[string]string
	tags           []string
	referenceCount uint64
}

type NamedPortMatchCallback func(ipSetID string, member IPSetMember)

type NamedPortIndex struct {
	endpointDataByID     map[interface{}]*endpointData
	parentDataByParentID map[string]*npParentData
	ipSetDataByID        map[string]*ipSetData

	// Callback functions
	OnMatchStarted NamedPortMatchCallback
	OnMatchStopped NamedPortMatchCallback
}

func NewNamedPortIndex(onMatchStarted, onMatchStopped NamedPortMatchCallback) *NamedPortIndex {
	inheritIDx := NamedPortIndex{
		endpointDataByID:     map[interface{}]*endpointData{},
		parentDataByParentID: map[string]*npParentData{},
		ipSetDataByID:        map[string]*ipSetData{},

		// Callback functions
		OnMatchStarted: onMatchStarted,
		OnMatchStopped: onMatchStopped,
	}
	return &inheritIDx
}

func (idx *NamedPortIndex) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.ProfileTagsKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.ProfileLabelsKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, idx.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, idx.OnUpdate)
}

// OnUpdate makes LabelInheritanceIndex compatible with the UpdateHandler interface
// allowing it to be used in a calculation graph more easily.  It accepts updates for endpoints
// and profiles and passes them through to the Update/DeleteXXX methods.
func (idx *NamedPortIndex) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			log.Debugf("Updating NamedPortIndex with endpoint %v", key)
			endpoint := update.Value.(*model.WorkloadEndpoint)
			profileIDs := endpoint.ProfileIDs
			idx.UpdateEndpoint(key, endpoint.Labels, convertNets(endpoint.IPv4Nets, endpoint.IPv6Nets), nil, profileIDs)
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
			idx.UpdateEndpoint(key, endpoint.Labels, convertIPs(endpoint.ExpectedIPv4Addrs, endpoint.ExpectedIPv6Addrs), nil, profileIDs)
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

func (idx *NamedPortIndex) UpdateIPSet(ipSetID string, sel selector.Selector, namedPortProtocol IPSetPortProtocol, namedPort string) {
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
		if oldIPSetData.selector.UniqueID() == oldIPSetData.selector.UniqueID() &&
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
		contrib := epData.CalculateContribution(newIPSetData)
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
				idx.OnMatchStarted(ipSetID, member)
			}
			newIPSetData.memberToRefCount[member] = refCount + 1
		}
	}
}

func (idx *NamedPortIndex) DeleteIPSet(id string) {
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
		idx.OnMatchStopped(id, member)
	}

	// Then scan all endpoints and fix up their indexes to remove the match.
	for _, epData := range idx.endpointDataByID {
		epData.RemoveMatchingIPSetID(id)
	}

	delete(idx.ipSetDataByID, id)
}

// type endpointData struct {
//   labels           map[string]string
//   ips              []ip.Addr
//   ports            []namedPort
//   parents          []*npParentData
//   cachedMatchingIPSetIDs set.Set
// }
func (idx *NamedPortIndex) UpdateEndpoint(
	id interface{},
	labels map[string]string,
	ips []ip.Addr,
	ports []namedPort,
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
		newEndpointData.ips = ips
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
			reflect.DeepEqual(oldEndpointData.ips, newEndpointData.ips) &&
			reflect.DeepEqual(oldEndpointData.parents, newEndpointData.parents) {
			log.Debug("Endpoint update makes no changes, skipping.")
			return
		}

		// If we get here, something about the endpoint has changed.  Calculate the old endpoint's
		// contribution to the IP sets that it matched.
		oldIPSetContributions = oldEndpointData.CachedContribution(idx.ipSetDataByID)
	}

	// Calculate and compare the contribution of the new endpoint to IP sets.  Emit events for
	// new contributions and then mop up deletions.
	for ipSetID, ipSetData := range idx.ipSetDataByID {
		if ipSetData.selector.EvaluateLabels(newEndpointData) {
			newIPSetContribution := newEndpointData.CalculateContribution(ipSetData)
			if len(newIPSetContribution) > 0 {
				// Record the match in the index.  This allows us to quickly recalculate the
				// contribution of this endpoint later.
				newEndpointData.AddMatchingIPSetID(ipSetID)

				// Incref all the new members.  If any of them go from 0 to 1 reference then we know
				// that they're new.  We'll temporarily double-count members that were already present,
				// then decref them below.
				for _, newMember := range newIPSetContribution {
					newRefCount := ipSetData.memberToRefCount[newMember] + 1
					if newRefCount == 1 {
						// New member in the IP set.
						idx.OnMatchStarted(ipSetID, newMember)
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
				idx.OnMatchStopped(ipSetID, oldMember)
				delete(ipSetData.memberToRefCount, oldMember)
			} else {
				ipSetData.memberToRefCount[oldMember] = newRefCount
			}
		}
	}

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

func (idx *NamedPortIndex) DeleteEndpoint(id interface{}) {
	log.Debug("Inherit index deleting endpoint", id)
	oldEndpointData := idx.endpointDataByID[id]
	if oldEndpointData == nil {
		return
	}

	oldIPSetContributions := oldEndpointData.CachedContribution(idx.ipSetDataByID)
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
				idx.OnMatchStopped(ipSetID, oldMember)
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

func (idx *NamedPortIndex) UpdateParentLabels(parentID string, labels map[string]string) {
	parentData := idx.getOrCreateParent(parentID)
	if reflect.DeepEqual(parentData.labels, labels) {
		log.WithField("parentID", parentID).Debug("Skipping no-op update to parent labels")
		return
	}

	// Now, scan over all endpoints looking for ones with this parent and calculate the change to
	// its contribution.  For occupancy reasons, the endpoint data references its parents by
	// pointer so, to calculate the delta we have to temporarily swap the labels back and forth.
	oldLabels := parentData.labels
	for _, epData := range idx.endpointDataByID {
		if !epData.HasParent(parentData) {
			continue
		}

		// This endpoint matches this parent, calculate its old contribution.
		parentData.labels = oldLabels
		oldIPSetContributions := epData.CachedContribution(idx.ipSetDataByID)

		// Temporarily swap in the new labels.
		parentData.labels = labels
		for ipSetID, ipSetData := range idx.ipSetDataByID {
			epData.RemoveMatchingIPSetID(ipSetID)
			if ipSetData.selector.EvaluateLabels(epData) {
				newIPSetContribution := epData.CalculateContribution(ipSetData)
				if len(newIPSetContribution) > 0 {
					// Record the match in the index.  This allows us to quickly recalculate the
					// contribution of this endpoint later.
					epData.AddMatchingIPSetID(ipSetID)

					// Incref all the new members.  If any of them go from 0 to 1 reference then we know
					// that they're new.  We'll temporarily double-count members that were already present,
					// then decref them below.
					for _, newMember := range newIPSetContribution {
						newRefCount := ipSetData.memberToRefCount[newMember] + 1
						if newRefCount == 1 {
							// New member in the IP set.
							idx.OnMatchStarted(ipSetID, newMember)
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
					idx.OnMatchStopped(ipSetID, oldMember)
					delete(ipSetData.memberToRefCount, oldMember)
				} else {
					ipSetData.memberToRefCount[oldMember] = newRefCount
				}
			}
		}
	}

	parentData.labels = labels
}

func (idx *NamedPortIndex) DeleteParentLabels(parentID string) {
	// Defer to the update function, which implements the endpoint scanning logic.
	idx.UpdateParentLabels(parentID, nil)
	idx.discardParentIfEmpty(parentID)
}

func (idx *NamedPortIndex) UpdateParentTags(parentID string, tags []string) {
	// TODO Make this logic common with label processing version.
	parentData := idx.getOrCreateParent(parentID)
	if reflect.DeepEqual(parentData.tags, tags) {
		log.WithField("parentID", parentID).Debug("Skipping no-op update to parent labels")
		return
	}

	// Now, scan over all endpoints looking for ones with this parent and calculate the change to
	// its contribution.  For occupancy reasons, the endpoint data references its parents by
	// pointer so, to calculate the delta we have to temporarily swap the labels back and forth.
	oldLabels := parentData.labels
	for _, epData := range idx.endpointDataByID {
		if !epData.HasParent(parentData) {
			continue
		}

		// This endpoint matches this parent, calculate its old contribution.
		parentData.labels = oldLabels
		oldIPSetContributions := epData.CachedContribution(idx.ipSetDataByID)

		// Temporarily swap in the new labels.
		parentData.tags = tags
		for ipSetID, ipSetData := range idx.ipSetDataByID {
			epData.RemoveMatchingIPSetID(ipSetID)
			if ipSetData.selector.EvaluateLabels(epData) {
				newIPSetContribution := epData.CalculateContribution(ipSetData)
				if len(newIPSetContribution) > 0 {
					// Record the match in the index.  This allows us to quickly recalculate the
					// contribution of this endpoint later.
					epData.AddMatchingIPSetID(ipSetID)

					// Incref all the new members.  If any of them go from 0 to 1 reference then we know
					// that they're new.  We'll temporarily double-count members that were already present,
					// then decref them below.
					for _, newMember := range newIPSetContribution {
						newRefCount := ipSetData.memberToRefCount[newMember] + 1
						if newRefCount == 1 {
							// New member in the IP set.
							idx.OnMatchStarted(ipSetID, newMember)
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
					idx.OnMatchStopped(ipSetID, oldMember)
					delete(ipSetData.memberToRefCount, oldMember)
				} else {
					ipSetData.memberToRefCount[oldMember] = newRefCount
				}
			}
		}
	}

	parentData.tags = tags
}

func (idx *NamedPortIndex) DeleteParentTags(parentID string) {
	idx.UpdateParentTags(parentID, nil)
	idx.discardParentIfEmpty(parentID)
}

func (idx *NamedPortIndex) getOrCreateParent(id string) *npParentData {
	parent := idx.parentDataByParentID[id]
	if parent == nil {
		parent = &npParentData{
			id: id,
		}
		idx.parentDataByParentID[id] = parent
	}
	return parent
}

func (idx *NamedPortIndex) discardParentIfEmpty(id string) {
	parent := idx.parentDataByParentID[id]
	if parent == nil {
		return
	}
	if parent.referenceCount == 0 && parent.labels == nil && parent.tags == nil {
		delete(idx.parentDataByParentID, id)
	}
}
