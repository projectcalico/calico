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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"
)

type MapsDataplane interface{}

var _ MapsDataplane = &Maps{}

type MapMetadata struct{}

// Maps manages a whole "plane" of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type Maps struct {
	IPVersionConfig *ipsets.IPVersionConfig

	// mapNameToAllMetadata contains an entry for each IP set that has been
	// added by a call to AddOrReplaceMap (and not subsequently removed).
	// It is *not* filtered by neededMapNames.
	mapNameToAllMetadata map[string]MapMetadata

	// mapNameToProgrammedMetadata tracks the IP sets that we want to program and
	// those that are actually in the dataplane.  It's Desired() map is the
	// subset of mapNameToAllMetadata that matches the neededMapNames filter.
	// Its Dataplane() map contains all IP sets matching the IPVersionConfig
	// that we think are in the dataplane.  This includes any temporary IP
	// sets and IP sets that we discovered on a resync (neither of which will
	// have entries in the Desired() map).
	mapNameToProgrammedMetadata *deltatracker.DeltaTracker[string, MapMetadata]

	// mainSetNameToMembers contains entries for all IP sets that are in
	// mapNameToAllMetadata along with entries for "main" (non-temporary) IP
	// sets that we think are still in the dataplane.  It is not filtered by
	// neededMapNames.  For IP sets that are in mapNameToAllMetadata, the
	// Desired() side of the tracker contains the members that we've been told
	// about.  Otherwise, Desired() is empty.  The Dataplane() side of the
	// tracker contains the members that are thought to be in the dataplane.
	mainSetNameToMembers map[string]*deltatracker.SetDeltaTracker[MapMember]
	mapsWithDirtyMembers set.Set[string]

	gaugeNumSets   prometheus.Gauge
	opReporter     logutils.OpRecorder
	sleep          func(time.Duration)
	resyncRequired bool
	logCxt         *log.Entry

	// Optional filter.  When non-nil, only these IP set IDs will be rendered into the dataplane
	// as Linux IP sets.
	neededMapNames set.Set[string]

	nft knftables.Interface
}

func NewMaps(ipVersionConfig *ipsets.IPVersionConfig, nft knftables.Interface, recorder logutils.OpRecorder) *Maps {
	return NewMapsWithShims(
		ipVersionConfig,
		time.Sleep,
		nft,
		recorder,
	)
}

// NewMapsWithShims is an internal test constructor.
func NewMapsWithShims(ipVersionConfig *ipsets.IPVersionConfig, sleep func(time.Duration), nft knftables.Interface, recorder logutils.OpRecorder) *Maps {
	familyStr := string(ipVersionConfig.Family)
	familyLogger := log.WithFields(log.Fields{"family": ipVersionConfig.Family})

	return &Maps{
		IPVersionConfig:      ipVersionConfig,
		mapNameToAllMetadata: map[string]MapMetadata{},
		opReporter:           recorder,
		mapNameToProgrammedMetadata: deltatracker.New(
			deltatracker.WithValuesEqualFn[string](func(a, b MapMetadata) bool { return a == b }),
			deltatracker.WithLogCtx[string, MapMetadata](familyLogger),
		),
		mainSetNameToMembers: map[string]*deltatracker.SetDeltaTracker[MapMember]{},
		mapsWithDirtyMembers: set.New[string](),
		resyncRequired:       true,
		logCxt:               familyLogger,
		gaugeNumSets:         gaugeVecNumSets.WithLabelValues(familyStr),
		sleep:                sleep,
		nft:                  nft,
	}
}

// AddOrReplaceMap queues up the creation (or replacement) of an IP set.  After the next call
// to ApplyUpdates(), the IP sets will be replaced with the new contents and the set's metadata
// will be updated as appropriate.
func (s *Maps) AddOrReplaceMap(setMetadata MapMetadata, members []string) {
	// We need to convert members to a canonical representation (which may be, for example,
	// an ip.Addr instead of a string) so that we can compare them with members that we read
	// back from the dataplane.  This also filters out IPs of the incorrect IP version.
	setID := setMetadata.SetID

	// Mark that we want this IP set to exist and with the correct size etc.
	// If the IP set exists, but it has the wrong metadata then the
	// DeltaTracker will catch that and mark it for recreation.
	mainMapName := s.nameForMainMap(setID)
	dpMeta := MapMetadata{
		Type: setMetadata.Type,
	}

	s.mapNameToAllMetadata[mainMapName] = dpMeta
	if s.ipSetNeeded(mainMapName) {
		s.logCxt.WithFields(log.Fields{
			"setID":   setID,
			"setType": setMetadata.Type,
		}).Info("Queueing IP set for creation")
		s.mapNameToProgrammedMetadata.Desired().Set(mainMapName, dpMeta)
	} else if log.IsLevelEnabled(log.DebugLevel) {
		s.logCxt.WithFields(log.Fields{
			"setID":   setID,
			"setType": setMetadata.Type,
		}).Debug("IP set is filtered out, skipping creation.")
	}

	// Set the desired contents of the IP set.
	canonMembers := s.filterAndCanonicaliseMembers(setMetadata.Type, members)
	memberTracker := s.getOrCreateMemberTracker(mainMapName)

	desiredMembers := memberTracker.Desired()
	desiredMembers.Iter(func(k MapMember) {
		if canonMembers.Contains(k) {
			canonMembers.Discard(k)
		} else {
			desiredMembers.Delete(k)
		}
	})
	canonMembers.Iter(func(m MapMember) error {
		desiredMembers.Add(m)
		return nil
	})
	s.updateDirtiness(mainMapName)
}

func (s *Maps) getOrCreateMemberTracker(mainMapName string) *deltatracker.SetDeltaTracker[MapMember] {
	dt := s.mainSetNameToMembers[mainMapName]
	if dt == nil {
		dt = deltatracker.NewSetDeltaTracker[MapMember]()
		s.mainSetNameToMembers[mainMapName] = dt
	}
	return dt
}

// RemoveMap queues up the removal of an IP set, it need not be empty.  The IP sets will be
// removed on the next call to ApplyDeletions().
func (s *Maps) RemoveMap(setID string) {
	// Mark that we no longer need this IP set.  The DeltaTracker will keep track of the metadata
	// until we actually delete the IP set.  We clean up mainSetNameToMembers only when we actually
	// delete it.
	mapName := s.nameForMainMap(setID)

	delete(s.mapNameToAllMetadata, mapName)
	s.mapNameToProgrammedMetadata.Desired().Delete(mapName)
	if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(mapName); ok {
		// Set is currently in the dataplane, clear its desired members but
		// we keep the member tracker until we actually delete the IP set
		// from the dataplane later.
		s.logCxt.WithField("setID", mapName).Info("Queueing IP set for removal")
		s.mainSetNameToMembers[mapName].Desired().DeleteAll()
	} else {
		// If it's not in the dataplane, clean it up immediately.
		log.Debug("IP set to remove not in the dataplane.")
		delete(s.mainSetNameToMembers, mapName)
	}
	s.updateDirtiness(mapName)
}

// nameForMainMap takes the given set ID and returns the name of the IP set as seen in nftables. This
// helper should be used to sanitize any set IDs, ensuring they are a consistent format.
func (s *Maps) nameForMainMap(setID string) string {
	return LegalizeSetName(s.IPVersionConfig.NameForMainMap(setID))
}

// AddMembers adds the given members to the IP set.  Filters out members that are of the incorrect
// IP version.
func (s *Maps) AddMembers(setID string, newMembers []string) {
	mapName := s.nameForMainMap(setID)
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		log.WithField("mapName", mapName).Panic("AddMembers called for nonexistent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, newMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to add")
		return
	}
	membersTracker := s.mainSetNameToMembers[mapName]
	canonMembers.Iter(func(member MapMember) error {
		membersTracker.Desired().Add(member)
		return nil
	})
	s.updateDirtiness(mapName)
}

// RemoveMembers queues up removal of the given members from an IP set.  Members of the wrong IP
// version are ignored.
func (s *Maps) RemoveMembers(setID string, removedMembers []string) {
	mapName := s.nameForMainMap(setID)
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		log.WithField("mapName", mapName).Panic("RemoveMembers called for nonexistent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, removedMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to remove")
		return
	}
	membersTracker := s.mainSetNameToMembers[mapName]
	canonMembers.Iter(func(member MapMember) error {
		membersTracker.Desired().Delete(member)
		return nil
	})
	s.updateDirtiness(mapName)
}

// QueueResync forces a resync with the dataplane on the next ApplyUpdates() call.
func (s *Maps) QueueResync() {
	s.logCxt.Debug("Asked to resync with the dataplane on next update.")
	s.resyncRequired = true
}

func (s *Maps) GetIPFamily() ipsets.IPFamily {
	return s.IPVersionConfig.Family
}

func (s *Maps) GetTypeOf(setID string) (ipsets.MapType, error) {
	mapName := s.nameForMainMap(setID)
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return setMeta.Type, nil
}

func (s *Maps) filterAndCanonicaliseMembers(ipSetType ipsets.MapType, members []string) set.Set[MapMember] {
	filtered := set.New[MapMember]()
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

func (s *Maps) GetDesiredMembers(setID string) (set.Set[string], error) {
	mapName := s.nameForMainMap(setID)

	_, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found", setID)
	}

	memberTracker, ok := s.mainSetNameToMembers[mapName]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found in members tracker", setID)
	}
	strs := set.New[string]()
	memberTracker.Desired().Iter(func(k MapMember) {
		strs.Add(k.String())
	})
	return strs, nil
}

// ApplyUpdates applies the updates to the dataplane.  Returns a set of programmed IPs in the Maps included by the
// ipsetFilter.
func (s *Maps) ApplyUpdates() {
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
func (s *Maps) tryResync() error {
	// Log the time spent as we exit the function.
	resyncStart := time.Now()
	defer func() {
		s.logCxt.WithFields(log.Fields{
			"resyncDuration":           time.Since(resyncStart),
			"ipSetsWithDirtyMembers":   s.mapsWithDirtyMembers.Len(),
			"ipSetsToCreateOrRecreate": s.mapNameToProgrammedMetadata.PendingUpdates().Len(),
			"ipSetsToDelete":           s.mapNameToProgrammedMetadata.PendingDeletions().Len(),
		}).Debug("Finished Maps resync")
	}()

	// Clear the dataplane metadata view, we'll build it back up again as we scan.
	s.mapNameToProgrammedMetadata.Dataplane().DeleteAll()

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
		mapName string
		elems   []*knftables.Element
		err     error
	}
	setsChan := make(chan setData)
	defer close(setsChan)

	// Start a goroutine to list the elements of each set. Limit concurrent set reads to
	// avoid spawning too many goroutines if there are a large number of sets.
	routineLimit := make(chan struct{}, 100)
	defer close(routineLimit)
	for _, mapName := range sets {
		// Wait for room in the limiting channel.
		routineLimit <- struct{}{}

		// Start a goroutine to read this set.
		go func(name string) {
			// Make sure to indicate that we're done by removing ourselves from the limiter channel.
			defer func() { <-routineLimit }()

			elems, err := s.nft.ListElements(ctx, "set", name)
			if err != nil {
				setsChan <- setData{mapName: name, err: err}
				return
			}
			setsChan <- setData{mapName: name, elems: elems}
		}(mapName)
	}

	// We expect a response for every set we asked for.
	responses := make([]setData, len(sets))
	for i := range responses {
		setData := <-setsChan
		responses[i] = setData
	}

	for _, setData := range responses {
		mapName := setData.mapName
		logCxt := s.logCxt.WithField("mapName", mapName)
		if setData.err != nil {
			logCxt.WithError(err).Error("Failed to list set elements.")
			return setData.err
		}

		// TODO: We need to be able to extract the set type from the dataplane, otherwise we cannot
		// tell whether or not an IP set has the correct type.
		metadata, ok := s.mapNameToAllMetadata[mapName]
		if !ok {
			// Programmed in the data plane, but not in memory. Skip this one - we'll clean up
			// state for this below.
			s.mapNameToProgrammedMetadata.Dataplane().Set(mapName, MapMetadata{})
			continue
		}
		// At this point, we know what type the set is and so we can parse the elements.
		// Any IP sets that this version of Felix cannot parse will be deleted below.
		// In theory, it is possible that the same IP set will contain differently formatted members
		// if programmed by different versions of Felix. This can be detected by looking at the programmed
		// set metadata and extracting the type. However, knftables does not yet support this operation. For now,
		// assume that we haven't modified the type of an IP set across Felix versions.

		// Build a set of canonicalized elements in the set by first converting to Felix's internal string representation,
		// and then canonicalizing the members to match the format that we use in the desired state.
		strElems := []string{}
		unknownElems := set.New[MapMember]()
		for _, e := range setData.elems {
			switch metadata.Type {
			case ipsets.MapTypeHashIP, ipsets.MapTypeHashNet:
				if len(e.Key) == 1 {
					// These types are just IP addresses / CIDRs.
					strElems = append(strElems, e.Key[0])
				} else {
					unknownElems.Add(UnknownMember(e.Key))
				}
			case ipsets.MapTypeHashIPPort:
				if len(e.Key) == 3 {
					// This is a concatination of IP, protocol and port. Format it back into Felix's internal representation.
					strElems = append(strElems, fmt.Sprintf("%s,%s:%s", e.Key[0], e.Key[1], e.Key[2]))
				} else {
					unknownElems.Add(UnknownMember(e.Key))
				}
			case ipsets.MapTypeBitmapPort:
				if len(e.Key) == 1 {
					// A single port.
					strElems = append(strElems, e.Key[0])
				} else {
					unknownElems.Add(UnknownMember(e.Key))
				}
			case ipsets.MapTypeHashNetNet:
				if len(e.Key) == 2 {
					// This is a concatination of two CIDRs. Format it back into Felix's internal representation.
					strElems = append(strElems, fmt.Sprintf("%s,%s", e.Key[0], e.Key[1]))
				} else {
					unknownElems.Add(UnknownMember(e.Key))
				}
			default:
				unknownElems.Add(UnknownMember(e.Key))
			}
		}
		elemsSet := s.filterAndCanonicaliseMembers(metadata.Type, strElems)
		elemsSet.AddAll(unknownElems.Slice())

		memberTracker := s.getOrCreateMemberTracker(mapName)
		numExtrasExpected := memberTracker.PendingDeletions().Len()
		err = memberTracker.Dataplane().ReplaceFromIter(func(f func(k MapMember)) error {
			elemsSet.Iter(func(item MapMember) error {
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
		s.mapNameToProgrammedMetadata.Dataplane().Set(mapName, MapMetadata{
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
		s.updateDirtiness(mapName)
	}

	// Mark any sets that we didn't see as empty.
	for name, members := range s.mainSetNameToMembers {
		if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(name); ok {
			// In the dataplane, we should have updated its members above.
			continue
		}
		if _, ok := s.mapNameToAllMetadata[name]; !ok {
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

func (s *Maps) NFTablesSet(name string) *knftables.Set {
	metadata, ok := s.mapNameToAllMetadata[name]
	if !ok {
		return nil
	}

	var flags []knftables.SetFlag
	switch metadata.Type {
	case ipsets.MapTypeHashIPPort:
		// IP and port sets don't support the interval flag.
	case ipsets.MapTypeHashIP:
		// IP addr sets don't use the interval flag.
	case ipsets.MapTypeBitmapPort:
		// Bitmap port sets don't use the interval flag.
	case ipsets.MapTypeHashNetNet:
		// Net sets don't use the interval flag.
	case ipsets.MapTypeHashNet:
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
func (s *Maps) tryUpdates() error {
	var dirtyMaps []string

	s.mapsWithDirtyMembers.Iter(func(mapName string) error {
		if _, ok := s.mapNameToProgrammedMetadata.Desired().Get(mapName); !ok {
			// Skip deletions and IP sets that aren't needed due to the filter.
			return nil
		}
		dirtyMaps = append(dirtyMaps, mapName)
		return nil
	})

	s.mapNameToProgrammedMetadata.PendingUpdates().Iter(func(mapName string, v MapMetadata) deltatracker.IterAction {
		if !s.mapsWithDirtyMembers.Contains(mapName) {
			dirtyMaps = append(dirtyMaps, mapName)
		}
		return deltatracker.IterActionNoOp
	})
	if len(dirtyMaps) == 0 {
		s.logCxt.Debug("No dirty IP sets.")
		return nil
	}

	start := time.Now()

	// Create a new transaction to update the IP sets.
	tx := s.nft.NewTransaction()

	if s.mapNameToProgrammedMetadata.Dataplane().Len() == 0 {
		// Use the total number of IP sets that we believe we have programmed as a proxy for whether
		// or not the table exists. If this is the first time we've programmed IP sets, make sure we
		// create the table as part of the transaction as well.
		tx.Add(&knftables.Table{})
	}

	for _, mapName := range dirtyMaps {
		// If the set is already programmed, we can skip it.
		if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(mapName); !ok {
			if set := s.NFTablesSet(mapName); set != nil {
				tx.Add(set)
			}
		}

		// Delete an IP set member if it's not in the desired set. Do this first in case new members conflict.
		members := s.getOrCreateMemberTracker(mapName)
		members.PendingDeletions().Iter(func(member MapMember) deltatracker.IterAction {
			tx.Delete(&knftables.Element{
				Set: mapName,
				Key: member.Key(),
			})
			return deltatracker.IterActionNoOp
		})

		// Add desired members to the set.
		members.Desired().Iter(func(member MapMember) {
			if members.Dataplane().Contains(member) {
				return
			}
			tx.Add(&knftables.Element{
				Set: mapName,
				Key: member.Key(),
			})
		})
	}

	if tx.NumOperations() > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if err := s.runTransaction(ctx, tx); err != nil {
			s.logCxt.WithError(err).Errorf("Failed to update IP sets. %s", tx.String())
			return fmt.Errorf("error updating nftables sets: %s", err)
		}

		// If we get here, the writes were successful, reset the IP sets delta tracking now the
		// dataplane should be in sync.
		log.Debugf("Updated %d Maps in %v", len(dirtyMaps), time.Since(start))
		for _, mapName := range dirtyMaps {
			// Mark all pending updates and memebers handled above as programmed.
			v, _ := s.mapNameToProgrammedMetadata.Desired().Get(mapName)
			s.mapNameToProgrammedMetadata.Dataplane().Set(mapName, v)
			members := s.mainSetNameToMembers[mapName]
			members.Dataplane().DeleteAll()
			members.Desired().Iter(func(member MapMember) {
				members.Dataplane().Add(member)
			})
		}
		s.mapsWithDirtyMembers.Clear()
	}
	return nil
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (s *Maps) ApplyDeletions() bool {
	// We rate limit the number of sets we delete in one go to avoid blocking the main loop for too long.
	// nftables supports deleting multiple sets in a single transactions, which means we delete more at once
	// than the iptables dataplane which deletes one at a time.
	maxDeletions := 500

	tx := s.nft.NewTransaction()
	deletedSets := set.New[string]()
	s.mapNameToProgrammedMetadata.PendingDeletions().Iter(func(mapName string) deltatracker.IterAction {
		if deletedSets.Len() >= maxDeletions {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of %d IP sets, rate limiting further IP set deletions.", maxDeletions)
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return deltatracker.IterActionNoOpStopIteration
		}

		// Add to the transaction.
		logCxt := s.logCxt.WithField("mapName", mapName)
		logCxt.Info("Deleting IP set in next transaction.")
		tx.Delete(&knftables.Set{Name: mapName})
		deletedSets.Add(mapName)

		if _, ok := s.mapNameToAllMetadata[mapName]; !ok {
			// IP set is not just filtered out, clean up the members cache.
			logCxt.Debug("IP set now gone from dataplane, removing from members tracker.")
			delete(s.mainSetNameToMembers, mapName)
		} else {
			// We're still tracking this IP set in case it needs to be recreated.
			// Record that the dataplane is now empty.
			logCxt.Debug("IP set now gone from dataplane but still tracking its members (it is filtered out).")
			s.mainSetNameToMembers[mapName].Dataplane().DeleteAll()
		}
		return deltatracker.IterActionNoOp
	})

	if deletedSets.Len() > 0 {
		s.logCxt.WithField("numSets", deletedSets.Len()).Info("Deleting IP sets.")
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if err := s.runTransaction(ctx, tx); err != nil {
			s.logCxt.WithError(err).Errorf("Failed to delete IP sets. %s", tx.String())
			return true
		}
	}

	// We need to clear pending deletions now that we have successfully deleted the sets.
	s.mapNameToProgrammedMetadata.PendingDeletions().Iter(func(mapName string) deltatracker.IterAction {
		if deletedSets.Contains(mapName) {
			return deltatracker.IterActionUpdateDataplane
		}
		return deltatracker.IterActionNoOp
	})

	// ApplyDeletions() marks the end of the two-phase "apply". Piggyback on that to
	// update the gauge that records how many IP sets we own.
	s.gaugeNumSets.Set(float64(s.mapNameToProgrammedMetadata.Dataplane().Len()))

	// Determine if we need to be rescheduled.
	numDeletionsPending := s.mapNameToProgrammedMetadata.PendingDeletions().Len()
	if deletedSets.Len() == 0 {
		// We had nothing to delete, or we only encountered errors, don't
		// ask to be rescheduled.
		return false
	}
	return numDeletionsPending > 0 // Reschedule if we have sets left to delete.
}

func (s *Maps) runTransaction(ctx context.Context, tx *knftables.Transaction) error {
	countNumSetTransactions.Inc()
	err := s.nft.Run(ctx, tx)
	if err != nil {
		countNumSetErrors.Inc()
	}
	return err
}

func (s *Maps) updateDirtiness(name string) {
	memberTracker, ok := s.mainSetNameToMembers[name]
	if !ok {
		s.mapsWithDirtyMembers.Discard(name)
		return
	}
	if !s.ipSetNeeded(name) {
		// If the IP set is filtered out we don't program its members.
		s.mapsWithDirtyMembers.Discard(name)
		return
	}
	if memberTracker.InSync() {
		s.mapsWithDirtyMembers.Discard(name)
	} else {
		s.mapsWithDirtyMembers.Add(name)
	}
}

func (s *Maps) ipSetNeeded(name string) bool {
	if s.neededMapNames == nil {
		// We're not filtering down to a "needed" set, so all IP sets are needed.
		return true
	}

	// We are filtering down, so compare against the needed set.
	return s.neededMapNames.Contains(name)
}
