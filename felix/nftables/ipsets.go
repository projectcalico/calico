// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"
)

var _ common.IPSetsDataplane = &IPSets{}

// IPSets manages a whole "plane" of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type IPSets struct {
	IPVersionConfig *ipsets.IPVersionConfig

	// setNameToAllMetadata contains an entry for each IP set that has been
	// added by a call to AddOrReplaceIPSet (and not subsequently removed).
	// It is *not* filtered by neededIPSetNames.
	setNameToAllMetadata map[string]ipsets.IPSetMetadata

	// setNameToProgrammedMetadata tracks the IP sets that we want to program and
	// those that are actually in the dataplane.  It's Desired() map is the
	// subset of setNameToAllMetadata that matches the neededIPSetNames filter.
	// Its Dataplane() map contains all IP sets matching the IPVersionConfig
	// that we think are in the dataplane.  This includes any temporary IP
	// sets and IP sets that we discovered on a resync (neither of which will
	// have entries in the Desired() map).
	setNameToProgrammedMetadata *deltatracker.DeltaTracker[string, ipsets.IPSetMetadata]

	// mainSetNameToMembers contains entries for all IP sets that are in
	// setNameToAllMetadata along with entries for "main" (non-temporary) IP
	// sets that we think are still in the dataplane.  It is not filtered by
	// neededIPSetNames.  For IP sets that are in setNameToAllMetadata, the
	// Desired() side of the tracker contains the members that we've been told
	// about.  Otherwise, Desired() is empty.  The Dataplane() side of the
	// tracker contains the members that are thought to be in the dataplane.
	mainSetNameToMembers   map[string]*deltatracker.SetDeltaTracker[ipsets.IPSetMember]
	ipSetsWithDirtyMembers set.Set[string]

	opReporter logutils.OpRecorder

	sleep func(time.Duration)

	resyncRequired bool

	logCxt *log.Entry

	// Optional filter.  When non-nil, only these IP set IDs will be rendered into the dataplane
	// as Linux IP sets.
	neededIPSetNames set.Set[string]

	nft knftables.Interface
}

func NewIPSets(ipVersionConfig *ipsets.IPVersionConfig, nft knftables.Interface, recorder logutils.OpRecorder) *IPSets {
	return NewIPSetsWithShims(
		ipVersionConfig,
		time.Sleep,
		nft,
		recorder,
	)
}

// NewIPSetsWithShims is an internal test constructor.
func NewIPSetsWithShims(ipVersionConfig *ipsets.IPVersionConfig, sleep func(time.Duration), nft knftables.Interface, recorder logutils.OpRecorder) *IPSets {
	return &IPSets{
		IPVersionConfig:      ipVersionConfig,
		setNameToAllMetadata: map[string]ipsets.IPSetMetadata{},
		opReporter:           recorder,
		setNameToProgrammedMetadata: deltatracker.New(
			deltatracker.WithValuesEqualFn[string](func(a, b ipsets.IPSetMetadata) bool {
				return a == b
			}),
			deltatracker.WithLogCtx[string, ipsets.IPSetMetadata](log.WithFields(log.Fields{
				"ipsetFamily": ipVersionConfig.Family,
			})),
		),
		mainSetNameToMembers:   map[string]*deltatracker.SetDeltaTracker[ipsets.IPSetMember]{},
		ipSetsWithDirtyMembers: set.New[string](),
		resyncRequired:         true,
		logCxt: log.WithFields(log.Fields{
			"family": ipVersionConfig.Family,
		}),
		sleep: sleep,
		nft:   nft,
	}
}

// AddOrReplaceIPSet queues up the creation (or replacement) of an IP set.  After the next call
// to ApplyUpdates(), the IP sets will be replaced with the new contents and the set's metadata
// will be updated as appropriate.
func (s *IPSets) AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, members []string) {
	// We need to convert members to a canonical representation (which may be, for example,
	// an ip.Addr instead of a string) so that we can compare them with members that we read
	// back from the dataplane.  This also filters out IPs of the incorrect IP version.
	setID := setMetadata.SetID

	// Mark that we want this IP set to exist and with the correct size etc.
	// If the IP set exists, but it has the wrong metadata then the
	// DeltaTracker will catch that and mark it for recreation.
	mainIPSetName := s.nameForMainIPSet(setID)
	dpMeta := ipsets.IPSetMetadata{
		Type:     setMetadata.Type,
		MaxSize:  setMetadata.MaxSize,
		RangeMin: setMetadata.RangeMin,
		RangeMax: setMetadata.RangeMax,
	}
	s.setNameToAllMetadata[mainIPSetName] = dpMeta
	if s.ipSetNeeded(mainIPSetName) {
		s.logCxt.WithFields(log.Fields{
			"setID":   setID,
			"setType": setMetadata.Type,
		}).Info("Queueing IP set for creation")
		s.setNameToProgrammedMetadata.Desired().Set(mainIPSetName, dpMeta)
	} else if log.IsLevelEnabled(log.DebugLevel) {
		s.logCxt.WithFields(log.Fields{
			"setID":   setID,
			"setType": setMetadata.Type,
		}).Debug("IP set is filtered out, skipping creation.")
	}

	// Set the desired contents of the IP set.
	canonMembers := s.filterAndCanonicaliseMembers(setMetadata.Type, members)
	memberTracker := s.getOrCreateMemberTracker(mainIPSetName)

	desiredMembers := memberTracker.Desired()
	desiredMembers.Iter(func(k ipsets.IPSetMember) {
		if canonMembers.Contains(k) {
			canonMembers.Discard(k)
		} else {
			desiredMembers.Delete(k)
		}
	})
	canonMembers.Iter(func(m ipsets.IPSetMember) error {
		desiredMembers.Add(m)
		return nil
	})
	s.updateDirtiness(mainIPSetName)
}

func (s *IPSets) getOrCreateMemberTracker(mainIPSetName string) *deltatracker.SetDeltaTracker[ipsets.IPSetMember] {
	dt := s.mainSetNameToMembers[mainIPSetName]
	if dt == nil {
		dt = deltatracker.NewSetDeltaTracker[ipsets.IPSetMember]()
		s.mainSetNameToMembers[mainIPSetName] = dt
	}
	return dt
}

// RemoveIPSet queues up the removal of an IP set, it need not be empty.  The IP sets will be
// removed on the next call to ApplyDeletions().
func (s *IPSets) RemoveIPSet(setID string) {
	// Mark that we no longer need this IP set.  The DeltaTracker will keep track of the metadata
	// until we actually delete the IP set.  We clean up mainSetNameToMembers only when we actually
	// delete it.
	setName := s.nameForMainIPSet(setID)

	delete(s.setNameToAllMetadata, setName)
	s.setNameToProgrammedMetadata.Desired().Delete(setName)
	if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(setName); ok {
		// Set is currently in the dataplane, clear its desired members but
		// we keep the member tracker until we actually delete the IP set
		// from the dataplane later.
		s.logCxt.WithField("setID", setName).Info("Queueing IP set for removal")
		s.mainSetNameToMembers[setName].Desired().DeleteAll()
	} else {
		// If it's not in the dataplane, clean it up immediately.
		log.Debug("IP set to remove not in the dataplane.")
		delete(s.mainSetNameToMembers, setName)
	}
	s.updateDirtiness(setName)
}

// nameForMainIPSet takes the given set ID and returns the name of the IP set as seen in nftables. This
// helper should be used to sanitize any set IDs, ensuring they are a consistent format.
func (s *IPSets) nameForMainIPSet(setID string) string {
	return LegalizeSetName(s.IPVersionConfig.NameForMainIPSet(setID))
}

// AddMembers adds the given members to the IP set.  Filters out members that are of the incorrect
// IP version.
func (s *IPSets) AddMembers(setID string, newMembers []string) {
	setName := s.nameForMainIPSet(setID)
	setMeta, ok := s.setNameToAllMetadata[setName]
	if !ok {
		log.WithField("setName", setName).Panic("AddMembers called for nonexistent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, newMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to add")
		return
	}
	membersTracker := s.mainSetNameToMembers[setName]
	canonMembers.Iter(func(member ipsets.IPSetMember) error {
		membersTracker.Desired().Add(member)
		return nil
	})
	s.updateDirtiness(setName)
}

// RemoveMembers queues up removal of the given members from an IP set.  Members of the wrong IP
// version are ignored.
func (s *IPSets) RemoveMembers(setID string, removedMembers []string) {
	setName := s.nameForMainIPSet(setID)
	setMeta, ok := s.setNameToAllMetadata[setName]
	if !ok {
		log.WithField("setName", setName).Panic("RemoveMembers called for nonexistent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, removedMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to remove")
		return
	}
	membersTracker := s.mainSetNameToMembers[setName]
	canonMembers.Iter(func(member ipsets.IPSetMember) error {
		membersTracker.Desired().Delete(member)
		return nil
	})
	s.updateDirtiness(setName)
}

// QueueResync forces a resync with the dataplane on the next ApplyUpdates() call.
func (s *IPSets) QueueResync() {
	s.logCxt.Debug("Asked to resync with the dataplane on next update.")
	s.resyncRequired = true
}

func (s *IPSets) GetIPFamily() ipsets.IPFamily {
	return s.IPVersionConfig.Family
}

func (s *IPSets) GetTypeOf(setID string) (ipsets.IPSetType, error) {
	setName := s.nameForMainIPSet(setID)
	setMeta, ok := s.setNameToAllMetadata[setName]
	if !ok {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return setMeta.Type, nil
}

func (s *IPSets) filterAndCanonicaliseMembers(ipSetType ipsets.IPSetType, members []string) set.Set[ipsets.IPSetMember] {
	filtered := set.New[ipsets.IPSetMember]()
	wantIPV6 := s.IPVersionConfig.Family == ipsets.IPFamilyV6
	for _, member := range members {
		isIPV6 := ipSetType.IsMemberIPV6(member)
		if wantIPV6 != isIPV6 {
			continue
		}
		filtered.Add(CanonicaliseMember(ipSetType, member))
	}
	return filtered
}

func (s *IPSets) GetDesiredMembers(setID string) (set.Set[string], error) {
	setName := s.nameForMainIPSet(setID)

	_, ok := s.setNameToAllMetadata[setName]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found", setID)
	}

	memberTracker, ok := s.mainSetNameToMembers[setName]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found in members tracker", setID)
	}
	strs := set.New[string]()
	memberTracker.Desired().Iter(func(k ipsets.IPSetMember) {
		strs.Add(k.String())
	})
	return strs, nil
}

// ApplyUpdates applies the updates to the dataplane.  Returns a set of programmed IPs in the IPSets included by the
// ipsetFilter.
func (s *IPSets) ApplyUpdates() {
	success := false
	retryDelay := 1 * time.Millisecond
	backOff := func() {
		s.sleep(retryDelay)
		retryDelay *= 2
	}

	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			s.logCxt.Info("Retrying after an ipsets update failure...")
		}
		if s.resyncRequired {
			// Compare our in-memory state against the dataplane and queue up
			// modifications to fix any inconsistencies.
			s.logCxt.Debug("Resyncing ipsets with dataplane.")
			s.opReporter.RecordOperation(fmt.Sprint("resync-nft-sets-v", s.IPVersionConfig.Family.Version()))

			if err := s.tryResync(); err != nil {
				s.logCxt.WithError(err).Warning("Failed to resync with dataplane")
				backOff()
				continue
			}
			s.resyncRequired = false
		}

		if err := s.tryUpdates(); err != nil {
			// Update failures may mean that our iptables updates fail.  We need to do an immediate resync.
			s.logCxt.WithError(err).Warning("Failed to update IP sets. Marking dataplane for resync.")
			s.resyncRequired = true
			backOff()
			continue
		}

		success = true
		break
	}
	if !success {
		s.logCxt.Panic("Failed to update IP sets after multiple retries.")
	}
}

// tryResync attempts to bring our state into sync with the dataplane.  It scans the contents of the
// IP sets in the dataplane and queues up updates to any IP sets that are out-of-sync.
func (s *IPSets) tryResync() error {
	// Log the time spent as we exit the function.
	resyncStart := time.Now()
	defer func() {
		s.logCxt.WithFields(log.Fields{
			"resyncDuration":           time.Since(resyncStart),
			"ipSetsWithDirtyMembers":   s.ipSetsWithDirtyMembers.Len(),
			"ipSetsToCreateOrRecreate": s.setNameToProgrammedMetadata.PendingUpdates().Len(),
			"ipSetsToDelete":           s.setNameToProgrammedMetadata.PendingDeletions().Len(),
		}).Debug("Finished IPSets resync")
	}()

	// Clear the dataplane metadata view, we'll build it back up again as we scan.
	s.setNameToProgrammedMetadata.Dataplane().DeleteAll()

	// Load sets from the dataplane. Update our Dataplane() maps with the actual contents
	// of the data plane so that the next ApplyUpdates() call will be able to properly make
	// incremental updates.
	//
	// For any set that doesn't match the desired data plane state, we'll queue up an update.
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	sets, err := s.nft.List(ctx, "set")
	if err != nil {
		if knftables.IsNotFound(err) {
			// Table doesn't exist - nothing to resync.
			return nil
		}
		return fmt.Errorf("error listing nftables sets: %s", err)
	}

	// We'll process each set in parallel, so we need a struct to hold the results.
	// Once knftables is augmented to support reading many sets at once, we can remove this.
	type setData struct {
		setName string
		elems   []string
		err     error
	}
	setsChan := make(chan setData)
	defer close(setsChan)

	// Start a goroutine to list the elements of each set.
	for _, setName := range sets {
		go func(name string) {
			elems, err := s.nft.ListElements(ctx, "set", name)
			if err != nil {
				setsChan <- setData{setName: name, err: err}
			}
			strElems := []string{}
			for _, e := range elems {
				if len(e.Key) == 3 {
					// This is a concatination of IP, protocol and port. Format it back into Felix's internal representation.
					strElems = append(strElems, fmt.Sprintf("%s,%s:%s", e.Key[0], e.Key[1], e.Key[2]))
				} else {
					// This is just an IP address / CIDR.
					strElems = append(strElems, e.Key[0])
				}
			}
			setsChan <- setData{setName: name, elems: strElems}
		}(setName)
	}

	// We expect a response for every set we asked for.
	responses := make([]setData, len(sets))
	for range sets {
		setData := <-setsChan
		responses = append(responses, setData)
	}

	for _, setData := range responses {
		setName := setData.setName
		strElems := setData.elems
		logCxt := s.logCxt.WithField("setName", setName)
		if setData.err != nil {
			logCxt.WithError(err).Error("Failed to list set elements.")
			return err
		}

		metadata, ok := s.setNameToAllMetadata[setName]
		if !ok {
			// Programmed in the data plane, but not in memory. Skip this one - we'll clean up
			// state for this below.
			continue
		}
		elemsSet := s.filterAndCanonicaliseMembers(metadata.Type, strElems)

		memberTracker := s.getOrCreateMemberTracker(setName)
		numExtrasExpected := memberTracker.PendingDeletions().Len()
		err = memberTracker.Dataplane().ReplaceFromIter(func(f func(k ipsets.IPSetMember)) error {
			elemsSet.Iter(func(item ipsets.IPSetMember) error {
				f(item)
				return nil
			})
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to read set memebers: %w", err)
		}

		// Mark us as having seen the programmed IP set.
		// TODO: Ideally we'd extract this information from the data plane itself, but it's not exposed
		// via knftables at the moment.
		s.setNameToProgrammedMetadata.Dataplane().Set(setName, ipsets.IPSetMetadata{
			Type:     metadata.Type,
			MaxSize:  metadata.MaxSize,
			RangeMin: metadata.RangeMin,
			RangeMax: metadata.RangeMax,
		})

		if numMissing := memberTracker.PendingUpdates().Len(); numMissing > 0 {
			logCxt.WithField("numMissing", numMissing).Info(
				"Resync found members missing from dataplane.")
		}
		if numExtras := memberTracker.PendingDeletions().Len() - numExtrasExpected; numExtras > 0 {
			logCxt.WithField("numExtras", numExtras).Info(
				"Resync found extra members in dataplane.")
		}
		s.updateDirtiness(setName)
	}

	// Mark any sets that we didn't see as empty.
	for name, members := range s.mainSetNameToMembers {
		if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(name); ok {
			// In the dataplane, we should have updated its members above.
			continue
		}
		if _, ok := s.setNameToAllMetadata[name]; !ok {
			// Defensive: this set is not in the dataplane, and it's not
			// one we are tracking, clean up its member tracker.
			log.WithField("name", name).Warn("Cleaning up leaked(?) set member tracker.")
			delete(s.mainSetNameToMembers, name)
			continue
		}
		// We're tracking this set, but we didn't find it in the dataplane;
		// reset the members set to empty.
		members.Dataplane().DeleteAll()
	}

	return nil
}

func LegalizeSetName(setName string) string {
	return strings.Replace(setName, ":", "-", -1)
}

func (s *IPSets) NFTablesSet(name string) *knftables.Set {
	metadata, ok := s.setNameToAllMetadata[name]
	if !ok {
		return nil
	}

	flags := make([]knftables.SetFlag, 0, 1)
	switch metadata.Type {
	case ipsets.IPSetTypeHashIPPort:
		// IP and port sets don't support the interval flag.
	case ipsets.IPSetTypeHashIP:
		// IP addr sets don't use the interval flag.
	case ipsets.IPSetTypeHashNet:
		// Net sets require the interval flag.
		flags = append(flags, knftables.IntervalFlag)
	default:
		log.WithField("type", metadata.Type).Panic("Unexpected IP set type")
	}

	return &knftables.Set{
		Name:  name,
		Type:  setType(metadata.Type, s.IPVersionConfig.Family.Version()),
		Flags: flags,
	}
}

// tryUpdates attempts to apply any pending updates to the dataplane.
func (s *IPSets) tryUpdates() error {
	var dirtyIPSets []string

	s.ipSetsWithDirtyMembers.Iter(func(setName string) error {
		if _, ok := s.setNameToProgrammedMetadata.Desired().Get(setName); !ok {
			// Skip deletions and IP sets that aren't needed due to the filter.
			return nil
		}
		dirtyIPSets = append(dirtyIPSets, setName)
		return nil
	})

	s.setNameToProgrammedMetadata.PendingUpdates().Iter(func(setName string, v ipsets.IPSetMetadata) deltatracker.IterAction {
		if !s.ipSetsWithDirtyMembers.Contains(setName) {
			dirtyIPSets = append(dirtyIPSets, setName)
		}
		return deltatracker.IterActionNoOp
	})
	if len(dirtyIPSets) == 0 {
		s.logCxt.Debug("No dirty IP sets.")
		return nil
	}

	start := time.Now()

	// Create a new transaction to update the IP sets.
	tx := s.nft.NewTransaction()

	if s.setNameToProgrammedMetadata.Dataplane().Len() == 0 {
		// Use the total number of IP sets that we believe we have programmed as a proxy for whether
		// or not the table exists. If this is the first time we've programmed IP sets, make sure we
		// create the table as part of the transaction as well.
		tx.Add(&knftables.Table{})
	}

	for _, setName := range dirtyIPSets {
		// If the set is already programmed, we can skip it.
		if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(setName); !ok {
			if set := s.NFTablesSet(setName); set != nil {
				tx.Add(set)
			}
		}

		// Delete an IP set member if it's not in the desired set. Do this first in case new members conflict.
		// TODO: This doesn't check the actual members in the dataplane, only our in memory
		// representation. This means that any out-of-band modifications to the IP set may cause
		// us to get out of sync.
		members := s.getOrCreateMemberTracker(setName)
		members.PendingDeletions().Iter(func(member ipsets.IPSetMember) deltatracker.IterAction {
			tx.Delete(&knftables.Element{
				Set: setName,
				Key: []string{member.String()},
			})
			return deltatracker.IterActionNoOp
		})

		// Add desired members to the set.
		members.Desired().Iter(func(member ipsets.IPSetMember) {
			if members.Dataplane().Contains(member) {
				return
			}
			tx.Add(&knftables.Element{
				Set: setName,
				Key: []string{member.String()},
			})
		})
	}

	if tx.NumOperations() > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if err := s.nft.Run(ctx, tx); err != nil {
			s.logCxt.WithError(err).Errorf("Failed to update IP sets. %s", tx.String())
			return fmt.Errorf("error updating nftables sets: %s", err)
		}

		// If we get here, the writes were successful, reset the IP sets delta tracking now the
		// dataplane should be in sync.
		log.Debugf("Updated %d IPSets in %v", len(dirtyIPSets), time.Since(start))
		for _, setName := range dirtyIPSets {
			// Mark all pending updates and memebers handled above as programmed.
			v, _ := s.setNameToProgrammedMetadata.Desired().Get(setName)
			s.setNameToProgrammedMetadata.Dataplane().Set(setName, v)
			members := s.mainSetNameToMembers[setName]
			members.Dataplane().DeleteAll()
			members.Desired().Iter(func(member ipsets.IPSetMember) {
				members.Dataplane().Add(member)
			})
		}
		s.ipSetsWithDirtyMembers.Clear()
	}
	return nil
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (s *IPSets) ApplyDeletions() bool {
	// We rate limit the number of sets we delete in one go to avoid blocking the main loop for too long.
	// nftables supports deleting multiple sets in a single transactions, which means we delete more at once
	// than the iptables dataplane which deletes one at a time.
	maxDeletions := 500

	tx := s.nft.NewTransaction()
	deletedSets := set.New[string]()
	s.setNameToProgrammedMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if deletedSets.Len() >= maxDeletions {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of %d IP sets, rate limiting further IP set deletions.", maxDeletions)
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return deltatracker.IterActionNoOpStopIteration
		}

		// Add to the transaction.
		logCxt := s.logCxt.WithField("setName", setName)
		logCxt.Info("Deleting IP set in next transaction.")
		tx.Delete(&knftables.Set{Name: setName})
		deletedSets.Add(setName)

		if _, ok := s.setNameToAllMetadata[setName]; !ok {
			// IP set is not just filtered out, clean up the members cache.
			logCxt.Debug("IP set now gone from dataplane, removing from members tracker.")
			delete(s.mainSetNameToMembers, setName)
		} else {
			// We're still tracking this IP set in case it needs to be recreated.
			// Record that the dataplane is now empty.
			logCxt.Debug("IP set now gone from dataplane but still tracking its members (it is filtered out).")
			s.mainSetNameToMembers[setName].Dataplane().DeleteAll()
		}
		return deltatracker.IterActionNoOp
	})

	if deletedSets.Len() > 0 {
		s.logCxt.WithField("numSets", deletedSets.Len()).Info("Deleting IP sets.")
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if err := s.nft.Run(ctx, tx); err != nil {
			s.logCxt.WithError(err).Errorf("Failed to delete IP sets. %s", tx.String())
			return true
		}
	}

	// We need to clear pending deletions now that we have successfully deleted the sets.
	s.setNameToProgrammedMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if deletedSets.Contains(setName) {
			return deltatracker.IterActionUpdateDataplane
		}
		return deltatracker.IterActionNoOp
	})

	// ApplyDeletions() marks the end of the two-phase "apply". Piggyback on that to
	// update the gauge that records how many IP sets we own.
	numDeletionsPending := s.setNameToProgrammedMetadata.Dataplane().Len()
	if deletedSets.Len() == 0 {
		// We had nothing to delete, or we only encountered errors, don't
		// ask to be rescheduled.
		return false
	}
	return numDeletionsPending > 0 // Reschedule if we have sets left to delete.
}

func (s *IPSets) updateDirtiness(name string) {
	memberTracker, ok := s.mainSetNameToMembers[name]
	if !ok {
		s.ipSetsWithDirtyMembers.Discard(name)
		return
	}
	if !s.ipSetNeeded(name) {
		// If the IP set is filtered out we don't program its members.
		s.ipSetsWithDirtyMembers.Discard(name)
		return
	}
	if memberTracker.InSync() {
		s.ipSetsWithDirtyMembers.Discard(name)
	} else {
		s.ipSetsWithDirtyMembers.Add(name)
	}
}

func (s *IPSets) SetFilter(ipSetNames set.Set[string]) {
	oldSetNames := s.neededIPSetNames
	if oldSetNames == nil && ipSetNames == nil {
		return
	}
	s.logCxt.Debugf("Filtering to needed IP set names: %v", ipSetNames)
	s.neededIPSetNames = ipSetNames
	for name, meta := range s.setNameToAllMetadata {
		if s.ipSetNeeded(name) {
			s.setNameToProgrammedMetadata.Desired().Set(name, meta)
		} else {
			s.setNameToProgrammedMetadata.Desired().Delete(name)
		}
		s.updateDirtiness(name)
	}
}

func (s *IPSets) ipSetNeeded(name string) bool {
	if s.neededIPSetNames == nil {
		// We're not filtering down to a "needed" set, so all IP sets are needed.
		return true
	}

	// We are filtering down, so compare against the needed set.
	return s.neededIPSetNames.Contains(name)
}

// CanonicaliseMember converts the string representation of an nftables set member to a canonical
// object of some kind that implements the IPSetMember interface.  The object is required to by hashable.
func CanonicaliseMember(t ipsets.IPSetType, member string) ipsets.IPSetMember {
	switch t {
	case ipsets.IPSetTypeHashIP:
		// Convert the string into our ip.Addr type, which is backed by an array.
		ipAddr := ip.FromIPOrCIDRString(member)
		if ipAddr == nil {
			// This should be prevented by validation in libcalico-go.
			log.WithField("ip", member).Panic("Failed to parse IP")
		}
		return ipAddr
	case ipsets.IPSetTypeHashIPPort:
		// The member should be of the format "IP,protocol:port"
		parts := strings.Split(member, ",")
		if len(parts) != 2 {
			log.WithField("member", member).Panic("Failed to parse IP,proto:port set member")
		}
		ipAddr := ip.FromIPOrCIDRString(parts[0])
		if ipAddr == nil {
			// This should be prevented by validation.
			log.WithField("member", member).Panic("Failed to parse IP part of IP,port member")
		}
		parts = strings.Split(parts[1], ":")
		if len(parts) != 2 {
			log.WithField("member", member).Panic("Failed to parse IP part of IP,port member")
		}
		proto := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			log.WithField("member", member).WithError(err).Panic("Bad port")
		}
		if port > math.MaxUint16 || port < 0 {
			log.WithField("member", member).Panic("Bad port range (should be between 0 and 65535)")
		}
		// Return a dedicated struct for V4 or V6.  This slightly reduces occupancy over storing
		// the address as an interface by storing one fewer interface headers.  That is worthwhile
		// because we store many IP set members.
		if ipAddr.Version() == 4 {
			return v4NFTIPPort{
				IP:       ipAddr.(ip.V4Addr),
				Port:     uint16(port),
				Protocol: proto,
			}
		} else {
			return v6NFTIPPort{
				IP:       ipAddr.(ip.V6Addr),
				Port:     uint16(port),
				Protocol: proto,
			}
		}
	case ipsets.IPSetTypeHashNet:
		// Convert the string into our ip.CIDR type, which is backed by a struct.  When
		// pretty-printing, the hash:net ipset type prints IPs with no "/32" or "/128"
		// suffix.
		return ip.MustParseCIDROrIP(member)
	case ipsets.IPSetTypeBitmapPort:
		// Trim the family if it exists
		if member[0] == 'v' {
			member = member[3:]
		}
		port, err := strconv.Atoi(member)
		if err == nil && port >= 0 && port <= 0xffff {
			return ipsets.Port(port)
		}
	}
	log.WithField("type", string(t)).Warn("Unknown IPSetType")
	return nil
}

// v4NFTIPPort is a struct that represents an IPv4 address, protocol and port for IPv4, and implements
// the ipsets.IPSetMember interface.
type v4NFTIPPort struct {
	IP       ip.V4Addr
	Port     uint16
	Protocol string
}

func (p v4NFTIPPort) String() string {
	return fmt.Sprintf("%s . %s . %d", p.IP.String(), p.Protocol, p.Port)
}

// v6NFTIPPort is a struct that represents an IPv6 address, protocol and port for IPv6, and implements
// the ipsets.IPSetMember interface.
type v6NFTIPPort struct {
	IP       ip.V6Addr
	Port     uint16
	Protocol string
}

func (p v6NFTIPPort) String() string {
	return fmt.Sprintf("%s . %s . %d", p.IP.String(), p.Protocol, p.Port)
}

// setType returns the nftables type to use for the given IPSetType and IP version.
func setType(t ipsets.IPSetType, ipVersion int) string {
	switch t {
	case ipsets.IPSetTypeHashIP:
		return fmt.Sprintf("ipv%d_addr", ipVersion)
	case ipsets.IPSetTypeHashNet:
		return fmt.Sprintf("ipv%d_addr", ipVersion)
	case ipsets.IPSetTypeHashIPPort:
		return fmt.Sprintf("ipv%d_addr . inet_proto . inet_service", ipVersion)
	}
	return string(t)
}
