// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	bpfIPSetsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_num_ip_sets",
		Help: "Number of BPF IP sets managed in the dataplane.",
	})
)

func init() {
	prometheus.MustRegister(bpfIPSetsGauge)
}

type bpfIPSets struct {
	IPVersionConfig *ipsets.IPVersionConfig

	// ipSets contains an entry for each IP set containing the state of that IP set.
	ipSets map[uint64]*bpfIPSet

	ipSetIDAllocator *idalloc.IDAllocator

	bpfMap bpf.Map

	dirtyIPSetIDs   set.Set[uint64]
	resyncScheduled bool

	opRecorder logutils.OpRecorder
}

func NewBPFIPSets(
	ipVersionConfig *ipsets.IPVersionConfig,
	ipSetIDAllocator *idalloc.IDAllocator,
	ipSetsMap bpf.Map,
	opRecorder logutils.OpRecorder,
) *bpfIPSets {
	return &bpfIPSets{
		IPVersionConfig:  ipVersionConfig,
		ipSets:           map[uint64]*bpfIPSet{},
		dirtyIPSetIDs:    set.New[uint64](),
		bpfMap:           ipSetsMap,
		resyncScheduled:  true,
		ipSetIDAllocator: ipSetIDAllocator,
		opRecorder:       opRecorder,
	}
}

// getExistingIPSetString gets the IP set data given the string set ID; returns nil if the IP set wasn't present.
// Never allocates an IP set ID from the allocator.
func (m *bpfIPSets) getExistingIPSetString(setID string) *bpfIPSet {
	id := m.ipSetIDAllocator.GetNoAlloc(setID)
	if id == 0 {
		return nil
	}
	return m.ipSets[id]
}

// getExistingIPSet gets the IP set data given the uint64 ID; returns nil if the IP set wasn't present.
// Never allocates an IP set ID from the allocator.
func (m *bpfIPSets) getExistingIPSet(setID uint64) *bpfIPSet {
	return m.ipSets[setID]
}

// getOrCreateIPSet gets the IP set data given the string set ID; allocates a new uint64 ID and creates the tracking
// struct if needed.  The returned struct will never have Deleted=true.
//
// Call deleteIPSetAndReleaseID to release the ID again and discard the tracking struct.
func (m *bpfIPSets) getOrCreateIPSet(setID string) *bpfIPSet {
	id := m.ipSetIDAllocator.GetOrAlloc(setID)
	ipSet := m.ipSets[id]
	if ipSet == nil {
		ipSet = &bpfIPSet{
			ID:             id,
			OriginalID:     setID,
			DesiredEntries: set.New[IPSetEntry](),
			PendingAdds:    set.New[IPSetEntry](),
			PendingRemoves: set.New[IPSetEntry](),
		}
		m.ipSets[id] = ipSet
	} else {
		// Possible that this IP set was queued for deletion but it just got recreated.
		ipSet.Deleted = false
	}
	return ipSet
}

// deleteIPSetAndReleaseID deleted the IP set tracking struct from the map and releases the ID.
func (m *bpfIPSets) deleteIPSetAndReleaseID(ipSet *bpfIPSet) {
	delete(m.ipSets, ipSet.ID)
	err := m.ipSetIDAllocator.ReleaseUintID(ipSet.ID)
	if err != nil {
		log.WithField("id", ipSet.ID).WithError(err).Panic("Failed to release IP set UID")
	}
}

// AddOrReplaceIPSet queues up the creation (or replacement) of an IP set.  After the next call
// to ApplyUpdates(), the IP sets will be replaced with the new contents and the set's metadata
// will be updated as appropriate.
func (m *bpfIPSets) AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, members []string) {
	ipSet := m.getOrCreateIPSet(setMetadata.SetID)
	ipSet.Type = setMetadata.Type
	log.WithFields(log.Fields{"stringID": setMetadata.SetID, "uint64ID": ipSet.ID}).Info("IP set added")
	ipSet.ReplaceMembers(members)
	m.markIPSetDirty(ipSet)
}

// RemoveIPSet queues up the removal of an IP set, it need not be empty.  The IP sets will be
// removed on the next call to ApplyDeletions().
func (m *bpfIPSets) RemoveIPSet(setID string) {
	ipSet := m.getExistingIPSetString(setID)
	if ipSet == nil {
		log.WithField("setID", setID).Panic("Received deletion for unknown IP set")
		return
	}
	if ipSet.Deleted {
		log.WithField("setID", setID).Panic("Received deletion for already-deleted IP set")
		return
	}
	ipSet.RemoveAll()
	ipSet.Deleted = true
	m.markIPSetDirty(ipSet)
}

// AddMembers adds the given members to the IP set.  Filters out members that are of the incorrect
// IP version.
func (m *bpfIPSets) AddMembers(setID string, newMembers []string) {
	ipSet := m.getExistingIPSetString(setID)
	if ipSet == nil {
		log.WithField("setID", setID).Panic("Received delta for unknown IP set")
		return
	}
	if ipSet.Deleted {
		log.WithField("setID", setID).Panic("Received delta for already-deleted IP set")
		return
	}
	log.WithFields(log.Fields{
		"stringID": setID,
		"uint64ID": ipSet.ID,
		"added":    len(newMembers),
	}).Info("IP delta update (adding)")
	for _, member := range newMembers {
		entry := ProtoIPSetMemberToBPFEntry(ipSet.ID, member)
		if entry != nil {
			ipSet.AddMember(*entry)
		}
	}
	m.markIPSetDirty(ipSet)
}

// RemoveMembers queues up removal of the given members from an IP set.  Members of the wrong IP
// version are ignored.
func (m *bpfIPSets) RemoveMembers(setID string, removedMembers []string) {
	ipSet := m.getExistingIPSetString(setID)
	if ipSet == nil {
		log.WithField("setID", setID).Panic("Received delta for unknown IP set")
		return
	}
	if ipSet.Deleted {
		log.WithField("setID", setID).Panic("Received delta for already-deleted IP set")
		return
	}
	log.WithFields(log.Fields{
		"stringID": setID,
		"uint64ID": ipSet.ID,
		"removed":  len(removedMembers),
	}).Info("IP delta update (removing)")
	for _, member := range removedMembers {
		entry := ProtoIPSetMemberToBPFEntry(ipSet.ID, member)
		if entry != nil {
			ipSet.RemoveMember(*entry)
		}
	}
	m.markIPSetDirty(ipSet)
}

// QueueResync forces a resync with the dataplane on the next ApplyUpdates() call.
func (m *bpfIPSets) QueueResync() {
	log.Debug("Asked to resync with the dataplane on next update.")
	m.resyncScheduled = true
}

func (m *bpfIPSets) GetIPFamily() ipsets.IPFamily {
	return m.IPVersionConfig.Family
}

func (m *bpfIPSets) GetTypeOf(setID string) (ipsets.IPSetType, error) {
	ipSet := m.getExistingIPSetString(setID)
	if ipSet == nil {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return ipSet.Type, nil
}

func (m *bpfIPSets) GetMembers(setID string) (set.Set[string], error) {
	// GetMembers is only called from XDPState, and XDPState does not coexist with
	// config.BPFEnabled.
	panic("Not implemented")
}

func (m *bpfIPSets) ApplyUpdates() {
	var numAdds, numDels uint
	startTime := time.Now()

	debug := log.GetLevel() >= log.DebugLevel
	if m.resyncScheduled {
		log.Debug("Doing full resync of BPF IP sets map")
		m.opRecorder.RecordOperation("resync-bpf-ipsets")
		m.resyncScheduled = false

		m.dirtyIPSetIDs.Clear()

		// Start by configuring every IP set to add all its entries to the dataplane.  Then, as we scan the dataplane,
		// we'll make sure that each gets cleaned up.
		for _, ipSet := range m.ipSets {
			ipSet.PendingAdds = ipSet.DesiredEntries.Copy()
			ipSet.PendingRemoves.Clear()
		}

		var unknownEntries []IPSetEntry
		err := m.bpfMap.Iter(func(k, v []byte) bpf.IteratorAction {
			var entry IPSetEntry
			copy(entry[:], k)
			setID := entry.SetID()
			if debug {
				log.WithFields(log.Fields{"setID": setID,
					"addr":      entry.Addr(),
					"prefixLen": entry.PrefixLen()}).Debug("Found entry in dataplane")
			}
			ipSet := m.ipSets[setID]
			if ipSet == nil {
				// Found en entry from an unknown IP set.  Mark it for deletion at the end.
				unknownEntries = append(unknownEntries, entry)
			} else {
				// Entry is from a known IP set.  Check if the entry is wanted.
				if ipSet.DesiredEntries.Contains(entry) {
					ipSet.PendingAdds.Discard(entry)
				} else {
					ipSet.PendingRemoves.Add(entry)
				}
			}
			return bpf.IterNone
		})
		if err != nil {
			log.WithError(err).Error("Failed to iterate over BPF map; IP sets may be out of sync")
			m.resyncScheduled = true
		}

		for _, entry := range unknownEntries {
			err := m.bpfMap.Delete(entry[:])
			if err != nil {
				log.WithError(err).WithField("key", entry).Error("Failed to remove unexpected IP set entry")
				m.resyncScheduled = true
			}
		}

		for _, ipSet := range m.ipSets {
			if ipSet.Dirty() {
				m.markIPSetDirty(ipSet)
			}
		}
	}

	m.dirtyIPSetIDs.Iter(func(setID uint64) error {
		leaveDirty := false
		ipSet := m.getExistingIPSet(setID)
		if ipSet == nil {
			log.WithField("id", setID).Warn("Couldn't find IP set that was marked as dirty.")
			m.resyncScheduled = true
			return set.RemoveItem
		}

		ipSet.PendingRemoves.Iter(func(entry IPSetEntry) error {
			if debug {
				log.WithFields(log.Fields{"setID": setID, "entry": entry}).Debug("Removing entry from IP set")
			}
			err := m.bpfMap.Delete(entry[:])
			if err != nil {
				log.WithFields(log.Fields{"setID": setID, "entry": entry}).WithError(err).Error("Failed to remove IP set entry")
				leaveDirty = true
				return nil
			}
			numDels++
			return set.RemoveItem
		})

		ipSet.PendingAdds.Iter(func(entry IPSetEntry) error {
			if debug {
				log.WithFields(log.Fields{"setID": setID, "entry": entry}).Debug("Adding entry to IP set")
			}
			err := m.bpfMap.Update(entry[:], DummyValue)
			if err != nil {
				log.WithFields(log.Fields{"setID": setID, "entry": entry}).WithError(err).Error("Failed to add IP set entry")
				leaveDirty = true
				return nil
			}
			numAdds++
			return set.RemoveItem
		})

		if leaveDirty {
			log.WithField("setID", setID).Debug("IP set still dirty, queueing resync")
			m.resyncScheduled = true
			return nil
		}

		if ipSet.Deleted {
			// Clean and deleted, time to release the IP set ID.
			m.deleteIPSetAndReleaseID(ipSet)
		}

		log.WithField("setID", setID).Debug("IP set is now clean")
		return set.RemoveItem
	})

	duration := time.Since(startTime)
	if numDels > 0 || numAdds > 0 {
		log.WithFields(log.Fields{
			"timeTaken": duration,
			"numAdds":   numAdds,
			"numDels":   numDels,
		}).Info("Completed updates to BPF IP sets.")
	}

	bpfIPSetsGauge.Set(float64(len(m.ipSets)))
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (m *bpfIPSets) ApplyDeletions() {
	// No-op.
}

func (m *bpfIPSets) markIPSetDirty(data *bpfIPSet) {
	m.dirtyIPSetIDs.Add(data.ID)
}

func (m *bpfIPSets) SetFilter(ipSetNames set.Set[string]) {
	// Not needed for this IP set dataplane.  All known IP sets
	// are written into the corresponding BPF map.
}

type bpfIPSet struct {
	OriginalID string
	ID         uint64

	// DesiredEntries contains all the entries that we _want_ to be in the set.
	DesiredEntries set.Set[IPSetEntry]
	// PendingAdds contains all the entries that we need to add to bring the dataplane into sync with DesiredEntries.
	PendingAdds set.Set[IPSetEntry]
	// PendingRemoves contains all the entries that we need to remove from the dataplane to bring the
	// dataplane into sync with DesiredEntries.
	PendingRemoves set.Set[IPSetEntry]

	Deleted bool

	Type ipsets.IPSetType
}

func (m *bpfIPSet) ReplaceMembers(members []string) {
	m.RemoveAll()
	m.AddMembers(members)
}

func (m *bpfIPSet) RemoveAll() {
	m.DesiredEntries.Iter(func(entry IPSetEntry) error {
		m.RemoveMember(entry)
		return nil
	})
}

func (m *bpfIPSet) AddMembers(members []string) {
	for _, member := range members {
		entry := ProtoIPSetMemberToBPFEntry(m.ID, member)
		if entry != nil {
			m.AddMember(*entry)
		}
	}
}

// AddMember adds a member to the set of desired entries. Idempotent, if the member is already present, makes no change.
func (m *bpfIPSet) AddMember(entry IPSetEntry) {
	if m.DesiredEntries.Contains(entry) {
		return
	}
	m.DesiredEntries.Add(entry)
	if m.PendingRemoves.Contains(entry) {
		m.PendingRemoves.Discard(entry)
	} else {
		m.PendingAdds.Add(entry)
	}
}

// RemoveMember removes a member from the set of desired entries. Idempotent, if the member is no present, makes no
// change.
func (m *bpfIPSet) RemoveMember(entry IPSetEntry) {
	if !m.DesiredEntries.Contains(entry) {
		return
	}
	m.DesiredEntries.Discard(entry)
	if m.PendingAdds.Contains(entry) {
		m.PendingAdds.Discard(entry)
	} else {
		m.PendingRemoves.Add(entry)
	}
}

func (m *bpfIPSet) Dirty() bool {
	return m.PendingRemoves.Len() > 0 || m.PendingAdds.Len() > 0 || m.Deleted
}
