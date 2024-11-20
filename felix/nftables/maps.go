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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeVecNumMaps = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_nft_maps",
		Help: "Number of active Calico nftables maps.",
	}, []string{"ip_version"})
	countNumMapTransactions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_nft_map_calls",
		Help: "Number of nftables map transactions executed.",
	})
	countNumMapErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_nft_map_errors",
		Help: "Number of nftables map transaction failures.",
	})
)

type MapType string

const MapTypeInterfaceMatch MapType = "interfaceMatch"

type MapsDataplane interface {
	AddOrReplaceMap(meta MapMetadata, members map[string][]string)
	RemoveMap(setID string)

	// ApplyMapUpdates applies any updates to the dataplane, and returns whether or not there are still
	// pending updates to apply.
	ApplyMapUpdates() bool
	ApplyMapDeletions() bool
}

var _ MapsDataplane = &Maps{}

type MapMetadata struct {
	ID   string
	Type MapType
}

type chainExistsFunc func(chain string) (bool, error)

// Maps manages a whole "plane" of maps, i.e. all the IPv4 maps, or all the IPv6 maps.
type Maps struct {
	IPVersionConfig *ipsets.IPVersionConfig

	// mapNameToAllMetadata contains an entry for each map that has been
	// added by a call to AddOrReplaceMap (and not subsequently removed).
	mapNameToAllMetadata map[string]MapMetadata

	// mapNameToProgrammedMetadata tracks the maps that we want to program and
	// those that are actually in the dataplane.  It's Desired() map is the
	// subset of mapNameToAllMetadata.
	// Its Dataplane() map contains all maps matching the IPVersionConfig
	// that we think are in the dataplane.  This includes any temporary IP
	// maps and maps that we discovered on a resync (neither of which will
	// have entries in the Desired() map).
	mapNameToProgrammedMetadata *deltatracker.DeltaTracker[string, MapMetadata]

	// mainSetNameToMembers contains entries for all maps that are in
	// mapNameToAllMetadata along with entries for "main" (non-temporary)
	// maps that we think are still in the dataplane. For maps that are in mapNameToAllMetadata, the
	// Desired() side of the tracker contains the members that we've been told
	// about.  Otherwise, Desired() is empty.  The Dataplane() side of the
	// tracker contains the members that are thought to be in the dataplane.
	mainSetNameToMembers map[string]*deltatracker.SetDeltaTracker[MapMember]
	mapsWithDirtyMembers set.Set[string]

	gaugeNumMaps   prometheus.Gauge
	opReporter     logutils.OpRecorder
	sleep          func(time.Duration)
	resyncRequired bool
	logCxt         *logrus.Entry

	nft knftables.Interface

	// function to determine if a chain exists in the dataplane. Needed to skip programming of entries
	// until the requisite chains are programmed by the Table.
	chainExists chainExistsFunc

	// Callbacks to increment and decrement reference counts for chains so that chains
	// referenced in maps are programmed by the Table implementation as needed.
	increfChain func(chain string)
	decrefChain func(chain string)
}

func NewMaps(
	ipVersionConfig *ipsets.IPVersionConfig,
	nft knftables.Interface,
	chainExists chainExistsFunc,
	increfChain func(chain string),
	decrefChain func(chain string),
	recorder logutils.OpRecorder,
) *Maps {
	return NewMapsWithShims(
		ipVersionConfig,
		time.Sleep,
		nft,
		chainExists,
		increfChain,
		decrefChain,
		recorder,
	)
}

// NewMapsWithShims is an internal test constructor.
func NewMapsWithShims(
	ipVersionConfig *ipsets.IPVersionConfig,
	sleep func(time.Duration),
	nft knftables.Interface,
	chainExists chainExistsFunc,
	increfChain func(chain string),
	decrefChain func(chain string),
	recorder logutils.OpRecorder,
) *Maps {
	familyStr := string(ipVersionConfig.Family)
	familyLogger := logrus.WithFields(logrus.Fields{"family": ipVersionConfig.Family})

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
		gaugeNumMaps:         gaugeVecNumMaps.WithLabelValues(familyStr),
		sleep:                sleep,
		nft:                  nft,
		chainExists:          chainExists,
		increfChain:          increfChain,
		decrefChain:          decrefChain,
	}
}

func (s *Maps) AddOrReplaceMap(meta MapMetadata, members map[string][]string) {
	id := meta.ID

	// Mark that we want this map to exist and with the correct size etc.
	// If the map exists, but it has the wrong metadata then the
	// DeltaTracker will catch that and mark it for recreation.
	name := s.nameForMainMap(id)
	s.mapNameToAllMetadata[name] = meta

	logCtx := s.logCxt.WithFields(logrus.Fields{"id": id, "type": meta.Type})

	logCtx.Info("Queueing map for creation")
	logCtx.WithField("members", members).Info("Queueing map for creation")
	s.mapNameToProgrammedMetadata.Desired().Set(name, meta)

	// Set the desired contents of the map.
	canonMembers := s.filterAndCanonicaliseMembers(meta.Type, members)
	memberTracker := s.getOrCreateMemberTracker(name)

	desiredMembers := memberTracker.Desired()
	desiredMembers.Iter(func(k MapMember) {
		if canonMembers.Contains(k) {
			canonMembers.Discard(k)
		} else {
			// Decref any chain referenced by the member.
			s.maybeDecrefChain(k)
			desiredMembers.Delete(k)
		}
	})
	canonMembers.Iter(func(m MapMember) error {
		if !desiredMembers.Contains(m) {
			// Incref any chain referenced by the member.
			s.maybeIncrefChain(m)
			desiredMembers.Add(m)
		}
		return nil
	})
	s.updateDirtiness(name)
}

// maybeDecrefChain takes a MapMember and decrefs any referenced chain (if it has one).
func (s *Maps) maybeDecrefChain(member MapMember) {
	switch t := member.(type) {
	case interfaceToChain:
		s.decrefChain(t.chain)
	}
}

// maybeIncrefChain takes a MapMember and increfs any referenced chain (if it has one).
func (s *Maps) maybeIncrefChain(member MapMember) {
	switch t := member.(type) {
	case interfaceToChain:
		s.increfChain(t.chain)
	}
}

func (s *Maps) getOrCreateMemberTracker(mainMapName string) *deltatracker.SetDeltaTracker[MapMember] {
	dt := s.mainSetNameToMembers[mainMapName]
	if dt == nil {
		dt = deltatracker.NewSetDeltaTracker[MapMember]()
		s.mainSetNameToMembers[mainMapName] = dt
	}
	return dt
}

// RemoveMap queues up the removal of an map, it need not be empty.  The maps will be
// removed on the next call to ApplyDeletions().
func (s *Maps) RemoveMap(setID string) {
	// Mark that we no longer need this map.  The DeltaTracker will keep track of the metadata
	// until we actually delete the map.  We clean up mainSetNameToMembers only when we actually
	// delete it.
	mapName := s.nameForMainMap(setID)

	delete(s.mapNameToAllMetadata, mapName)
	s.mapNameToProgrammedMetadata.Desired().Delete(mapName)
	if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(mapName); ok {
		// Set is currently in the dataplane, clear its desired members but
		// we keep the member tracker until we actually delete the map
		// from the dataplane later.
		s.logCxt.WithField("id", mapName).Info("Queueing map for removal")
		s.mainSetNameToMembers[mapName].Desired().DeleteAll()
	} else {
		// If it's not in the dataplane, clean it up immediately.
		logrus.WithField("id", mapName).Debug("map to remove not in the dataplane.")
		delete(s.mainSetNameToMembers, mapName)
	}
	s.updateDirtiness(mapName)
}

// nameForMainMap takes the given set ID and returns the name of the map as seen in nftables. This
// helper should be used to sanitize any set IDs, ensuring they are a consistent format.
func (s *Maps) nameForMainMap(setID string) string {
	return LegalizeSetName(setID)
}

// AddMembers adds the given members to the map.  Filters out members that are of the incorrect
// IP version.
func (s *Maps) AddMembers(setID string, newMembers map[string][]string) {
	mapName := s.nameForMainMap(setID)
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		logrus.WithField("mapName", mapName).Panic("AddMembers called for nonexistent map.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, newMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to add")
		return
	}
	membersTracker := s.mainSetNameToMembers[mapName]
	canonMembers.Iter(func(member MapMember) error {
		s.maybeIncrefChain(member)
		membersTracker.Desired().Add(member)
		return nil
	})
	s.updateDirtiness(mapName)
}

// RemoveMembers queues up removal of the given members from an map.  Members of the wrong IP
// version are ignored.
func (s *Maps) RemoveMembers(setID string, removedMembers map[string][]string) {
	mapName := s.nameForMainMap(setID)
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		logrus.WithField("mapName", mapName).Panic("RemoveMembers called for nonexistent map.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, removedMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to remove")
		return
	}
	membersTracker := s.mainSetNameToMembers[mapName]
	canonMembers.Iter(func(member MapMember) error {
		s.maybeDecrefChain(member)
		membersTracker.Desired().Delete(member)
		return nil
	})
	s.updateDirtiness(mapName)
}

// QueueResync forces a resync with the dataplane on the next ApplyMapUpdates() call.
func (s *Maps) QueueResync() {
	s.logCxt.Debug("Asked to resync with the dataplane on next update.")
	s.resyncRequired = true
}

func (s *Maps) GetIPFamily() ipsets.IPFamily {
	return s.IPVersionConfig.Family
}

func (s *Maps) GetTypeOf(setID string) (MapType, error) {
	mapName := s.nameForMainMap(setID)
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return setMeta.Type, nil
}

func (s *Maps) filterAndCanonicaliseMembers(mtype MapType, members map[string][]string) set.Set[MapMember] {
	filtered := set.New[MapMember]()
	for k, v := range members {
		filtered.Add(CanonicaliseMapMember(mtype, k, v))
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

// ApplyMapUpdates applies the updates to the dataplane.  Returns a set of programmed IPs in the Maps included by the
// ipsetFilter.
func (s *Maps) ApplyMapUpdates() bool {
	success := false
	retryDelay := 1 * time.Millisecond
	backOff := func() {
		s.sleep(retryDelay)
		retryDelay *= 2
	}

	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			s.logCxt.Info("Retrying after an nftables map update failure...")
		}
		if s.resyncRequired {
			// Compare our in-memory state against the dataplane and queue up
			// modifications to fix any inconsistencies.
			s.logCxt.Debug("Resyncing maps with dataplane.")
			s.opReporter.RecordOperation(fmt.Sprint("resync-nft-maps-v", s.IPVersionConfig.Family.Version()))

			if err := s.tryResync(); err != nil {
				s.logCxt.WithError(err).Warning("Failed to resync with dataplane")
				backOff()
				continue
			}
			s.resyncRequired = false
		}

		if err := s.tryUpdates(); err != nil {
			// Update failures may mean that our iptables updates fail.  We need to do an immediate resync.
			s.logCxt.WithError(err).Warning("Failed to update maps. Marking dataplane for resync.")
			s.resyncRequired = true
			backOff()
			continue
		}

		success = true
		break
	}
	if !success {
		s.logCxt.Panic("Failed to update maps after multiple retries.")
	}
	return s.mapsWithDirtyMembers.Len() > 0
}

// tryResync attempts to bring our state into sync with the dataplane.  It scans the contents of the
// maps in the dataplane and queues up updates to any maps that are out-of-sync.
func (s *Maps) tryResync() error {
	// Log the time spent as we exit the function.
	resyncStart := time.Now()
	defer func() {
		s.logCxt.WithFields(logrus.Fields{
			"resyncDuration":         time.Since(resyncStart),
			"mapsWithDirtyMembers":   s.mapsWithDirtyMembers.Len(),
			"mapsToCreateOrRecreate": s.mapNameToProgrammedMetadata.PendingUpdates().Len(),
			"mapsToDelete":           s.mapNameToProgrammedMetadata.PendingDeletions().Len(),
		}).Debug("Finished Maps resync")
	}()

	// Clear the dataplane metadata view, we'll build it back up again as we scan.
	s.mapNameToProgrammedMetadata.Dataplane().DeleteAll()

	// Load from the dataplane. Update our Dataplane() maps with the actual contents
	// of the data plane so that the next ApplyMapUpdates() call will be able to properly make
	// incremental updates.
	//
	// For any set that doesn't match the desired data plane state, we'll queue up an update.
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	maps, err := s.nft.List(ctx, "map")
	if err != nil {
		if knftables.IsNotFound(err) {
			// Table doesn't exist - nothing to resync.
			return nil
		}
		return fmt.Errorf("error listing nftables maps: %s", err)
	}

	// We'll process each set in parallel, so we need a struct to hold the results.
	// Once knftables is augmented to support reading many maps at once, we can remove this.
	type mapData struct {
		name  string
		elems []*knftables.Element
		err   error
	}
	mapsCh := make(chan mapData)
	defer close(mapsCh)

	// Start a goroutine to list the elements of each set. Limit concurrent set reads to
	// avoid spawning too many goroutines if there are a large number of maps.
	routineLimit := make(chan struct{}, 100)
	defer close(routineLimit)
	for _, name := range maps {
		// Wait for room in the limiting channel.
		routineLimit <- struct{}{}

		// Start a goroutine to read this set.
		go func(name string) {
			// Make sure to indicate that we're done by removing ourselves from the limiter channel.
			defer func() { <-routineLimit }()

			elems, err := s.nft.ListElements(ctx, "map", name)
			if err != nil {
				mapsCh <- mapData{name: name, err: err}
				return
			}
			mapsCh <- mapData{name: name, elems: elems}
		}(name)
	}

	// We expect a response for every set we asked for.
	responses := make([]mapData, len(maps))
	for i := range responses {
		setData := <-mapsCh
		responses[i] = setData
	}

	for _, setData := range responses {
		mapName := setData.name
		logCxt := s.logCxt.WithField("mapName", mapName)
		if setData.err != nil {
			logCxt.WithError(err).Error("Failed to list map elements.")
			return setData.err
		}

		// TODO: We need to be able to extract the set type from the dataplane, otherwise we cannot
		// tell whether or not an map has the correct type.
		metadata, ok := s.mapNameToAllMetadata[mapName]
		if !ok {
			// Programmed in the data plane, but not in memory. We should still load any members of this map in order
			// to perform our multi-step map deletion logic (delete members, delete map).
			logCxt.Info("Map in dataplane but not in memory, will remove it.")
		}

		// At this point, we likely know what type the set is and so we can parse the elements.
		//
		// Any maps that this version of Felix cannot parse will have their members removed, and then be deleted.
		// In theory, it is possible that the same map will contain differently formatted members
		// if programmed by different versions of Felix. This can be detected by looking at the programmed
		// set metadata and extracting the type. However, knftables does not yet support this operation. For now,
		// assume that we haven't modified the type of an map across Felix versions.

		// Build a set of canonicalized elements in the set by first converting to Felix's internal string representation,
		// and then canonicalizing the members to match the format that we use in the desired state.
		strElems := map[string][]string{}
		unknownElems := set.New[MapMember]()
		for _, e := range setData.elems {
			logCxt.WithField("element", e).Debug("Processing element")
			switch metadata.Type {
			case MapTypeInterfaceMatch:
				strElems[e.Key[0]] = e.Value
			default:
				unknownElems.Add(UnknownMapMember(e.Key, e.Value))
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

		// Mark us as having seen the programmed map.
		// TODO: Ideally we'd extract this information from the data plane itself, but it's not exposed
		// via knftables at the moment.
		s.mapNameToProgrammedMetadata.Dataplane().Set(mapName, MapMetadata{
			ID:   metadata.ID,
			Type: metadata.Type,
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

	// Mark any maps that we didn't see as empty.
	for name, members := range s.mainSetNameToMembers {
		if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(name); ok {
			// In the dataplane, we should have updated its members above.
			continue
		}
		if _, ok := s.mapNameToAllMetadata[name]; !ok {
			// Defensive: this set is not in the dataplane, and it's not
			// one we are tracking, clean up its member tracker.
			logrus.WithField("name", name).Warn("Cleaning up leaked(?) set member tracker.")
			delete(s.mainSetNameToMembers, name)
			continue
		}
		// We're tracking this set, but we didn't find it in the dataplane;
		// reset the members set to empty.
		members.Dataplane().DeleteAll()
	}

	return nil
}

func (s *Maps) NFTablesMap(name string) *knftables.Map {
	metadata, ok := s.mapNameToAllMetadata[name]
	if !ok {
		return nil
	}

	var flags []knftables.SetFlag
	switch metadata.Type {
	case MapTypeInterfaceMatch:
	default:
		logrus.WithField("type", metadata.Type).Panic("Unexpected map type")
	}

	return &knftables.Map{
		Name:  name,
		Type:  mapType(metadata.Type, s.IPVersionConfig.Family.Version()),
		Flags: flags,
	}
}

// tryUpdates attempts to apply any pending updates to the dataplane.
func (s *Maps) tryUpdates() error {
	var dirtyMaps []string

	// Collect any maps with dirty members that need to be updated based on resync with the dataplane.
	s.mapsWithDirtyMembers.Iter(func(mapName string) error {
		if _, ok := s.mapNameToProgrammedMetadata.Desired().Get(mapName); !ok {
			// Skip deletions and maps that aren't needed due to the filter.
			return nil
		}
		dirtyMaps = append(dirtyMaps, mapName)
		return nil
	})

	// Any maps that are marked for deletion should have their members cleared out if there are any.
	// Because of the potential interdependency between maps and chains, we need to:
	// 1. Delete the members of the map, as they may reference chains that are about to be deleted.
	// 2. Delete any chains that are marked for deletion (which may reference the map).
	// 3. Delete the map itself, once all references to / from it have been removed.
	s.mapNameToProgrammedMetadata.PendingDeletions().Iter(func(mapName string) deltatracker.IterAction {
		dirtyMaps = append(dirtyMaps, mapName)
		return deltatracker.IterActionNoOp
	})

	// Add in any maps that have pending updates to program.
	s.mapNameToProgrammedMetadata.PendingUpdates().Iter(func(mapName string, v MapMetadata) deltatracker.IterAction {
		if !s.mapsWithDirtyMembers.Contains(mapName) {
			dirtyMaps = append(dirtyMaps, mapName)
		}
		return deltatracker.IterActionNoOp
	})

	// If there are no dirty maps, we can skip the update entirely.
	if len(dirtyMaps) == 0 {
		s.logCxt.Debug("No dirty maps.")
		return nil
	}
	s.logCxt.WithField("numMaps", len(dirtyMaps)).Info("Updating maps.")

	// Create a new transaction to update the maps.
	start := time.Now()
	tx := s.nft.NewTransaction()

	if s.mapNameToProgrammedMetadata.Dataplane().Len() == 0 {
		// Use the total number of maps that we believe we have programmed as a proxy for whether
		// or not the table exists. If this is the first time we've programmed maps, make sure we
		// create the table as part of the transaction as well.
		tx.Add(&knftables.Table{})
	}

	// Track any maps we're not able to fully program, so we don't clear the dirty flag.
	incompleteMaps := set.New[string]()

	mapToAddedMembers := map[string]set.Set[MapMember]{}
	mapToDeletedMembers := map[string]set.Set[MapMember]{}

	for _, mapName := range dirtyMaps {
		// If the set is already programmed, we can skip it.
		if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(mapName); !ok {
			if set := s.NFTablesMap(mapName); set != nil {
				tx.Add(set)
			}
		}

		// Delete map member if it's not in the desired set. Do this first in case new members conflict.
		members := s.getOrCreateMemberTracker(mapName)
		members.PendingDeletions().Iter(func(member MapMember) deltatracker.IterAction {
			tx.Delete(&knftables.Element{
				Map:   mapName,
				Key:   member.Key(),
				Value: member.Value(),
			})
			if mapToDeletedMembers[mapName] == nil {
				mapToDeletedMembers[mapName] = set.New[MapMember]()
			}
			mapToDeletedMembers[mapName].Add(member)
			return deltatracker.IterActionNoOp
		})

		// Add desired members to the set.
		members.Desired().Iter(func(member MapMember) {
			if members.Dataplane().Contains(member) {
				return
			}
			ready, err := s.readyToProgram(member)
			if err != nil {
				s.logCxt.WithError(err).Errorf("Failed to check readiness of member %s", member)
				incompleteMaps.Add(mapName)
				return
			} else if !ready {
				s.logCxt.WithField("member", member).Debug("Skipping member until it is ready.")
				incompleteMaps.Add(mapName)
				return
			}

			if mapToAddedMembers[mapName] == nil {
				mapToAddedMembers[mapName] = set.New[MapMember]()
			}
			mapToAddedMembers[mapName].Add(member)
			tx.Add(&knftables.Element{
				Map:   mapName,
				Key:   member.Key(),
				Value: member.Value(),
			})
		})
	}

	if tx.NumOperations() > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if err := s.runTransaction(ctx, tx); err != nil {
			s.logCxt.WithError(err).Errorf("Failed to update maps. %s", tx.String())
			return fmt.Errorf("error updating nftables maps: %s", err)
		}

		// If we get here, the writes were successful, reset the maps delta tracking now the
		// dataplane should be in sync.
		logrus.Debugf("Updated %d Maps in %v", len(dirtyMaps), time.Since(start))
		for _, mapName := range dirtyMaps {
			// Update state tracking for each map based on the modifications we just made.
			v, _ := s.mapNameToProgrammedMetadata.Desired().Get(mapName)
			s.mapNameToProgrammedMetadata.Dataplane().Set(mapName, v)
			members := s.mainSetNameToMembers[mapName]
			if adds, ok := mapToAddedMembers[mapName]; ok {
				adds.Iter(func(member MapMember) error {
					members.Dataplane().Add(member)
					return nil
				})
			}
			if dels, ok := mapToDeletedMembers[mapName]; ok {
				dels.Iter(func(member MapMember) error {
					members.Dataplane().Delete(member)
					return nil
				})
			}
		}
		s.mapsWithDirtyMembers.Clear()
		s.mapsWithDirtyMembers.AddAll(incompleteMaps.Slice())
	}
	return nil
}

// ApplyDeletions tries to delete any maps that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (s *Maps) ApplyMapDeletions() bool {
	// We rate limit the number of maps we delete in one go to avoid blocking the main loop for too long.
	// nftables supports deleting multiple maps in a single transactions, which means we delete more at once
	// than the iptables dataplane which deletes one at a time.
	maxDeletions := 500

	tx := s.nft.NewTransaction()
	deletedMaps := set.New[string]()
	s.mapNameToProgrammedMetadata.PendingDeletions().Iter(func(mapName string) deltatracker.IterAction {
		if deletedMaps.Len() >= maxDeletions {
			// Deleting maps is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining maps pending deletion and mop them up next time.
			logrus.Debugf("Deleted batch of %d maps, rate limiting further map deletions.", maxDeletions)
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return deltatracker.IterActionNoOpStopIteration
		}

		// Add to the transaction.
		logCxt := s.logCxt.WithField("mapName", mapName)
		logCxt.Info("Deleting map in next transaction.")
		tx.Delete(&knftables.Set{Name: mapName})
		deletedMaps.Add(mapName)

		if _, ok := s.mapNameToAllMetadata[mapName]; !ok {
			// map is not just filtered out, clean up the members cache.
			logCxt.Debug("map now gone from dataplane, removing from members tracker.")
			delete(s.mainSetNameToMembers, mapName)
		} else {
			// We're still tracking this map in case it needs to be recreated.
			// Record that the dataplane is now empty.
			logCxt.Debug("map now gone from dataplane but still tracking its members (it is filtered out).")
			s.mainSetNameToMembers[mapName].Dataplane().DeleteAll()
		}
		return deltatracker.IterActionNoOp
	})

	if deletedMaps.Len() > 0 {
		s.logCxt.WithField("numMaps", deletedMaps.Len()).Info("Deleting maps.")
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if err := s.runTransaction(ctx, tx); err != nil {
			s.logCxt.WithError(err).Errorf("Failed to delete maps. %s", tx.String())
			return true
		}
	}

	// We need to clear pending deletions now that we have successfully deleted the maps.
	s.mapNameToProgrammedMetadata.PendingDeletions().Iter(func(mapName string) deltatracker.IterAction {
		if deletedMaps.Contains(mapName) {
			return deltatracker.IterActionUpdateDataplane
		}
		return deltatracker.IterActionNoOp
	})

	// ApplyDeletions() marks the end of the two-phase "apply". Piggyback on that to
	// update the gauge that records how many maps we own.
	s.gaugeNumMaps.Set(float64(s.mapNameToProgrammedMetadata.Dataplane().Len()))

	// Determine if we need to be rescheduled.
	numDeletionsPending := s.mapNameToProgrammedMetadata.PendingDeletions().Len()
	if deletedMaps.Len() == 0 {
		// We had nothing to delete, or we only encountered errors, don't
		// ask to be rescheduled.
		return false
	}
	return numDeletionsPending > 0 // Reschedule if we have maps left to delete.
}

func (s *Maps) runTransaction(ctx context.Context, tx *knftables.Transaction) error {
	logrus.WithField("tx", tx).Debug("Running nftables map transaction.")
	countNumMapTransactions.Inc()
	err := s.nft.Run(ctx, tx)
	if err != nil {
		countNumMapErrors.Inc()
	}
	return err
}

func (s *Maps) updateDirtiness(name string) {
	memberTracker, ok := s.mainSetNameToMembers[name]
	if !ok {
		s.mapsWithDirtyMembers.Discard(name)
		return
	}
	if memberTracker.InSync() {
		s.mapsWithDirtyMembers.Discard(name)
	} else {
		s.mapsWithDirtyMembers.Add(name)
	}
}

func (s *Maps) readyToProgram(member MapMember) (bool, error) {
	switch t := member.(type) {
	case interfaceToChain:
		return s.chainExists(t.chain)
	default:
		logrus.WithField("member", member).Warn("Unknown member type")
	}
	return false, nil
}

func CanonicaliseMapMember(mtype MapType, key string, value []string) MapMember {
	switch mtype {
	case MapTypeInterfaceMatch:
		splits := strings.Split(value[0], " ")
		return interfaceToChain{key, splits[0], splits[1]}
	default:
		logrus.Errorf("Unknown map type: %v", mtype)
	}
	return nil
}

type interfaceToChain struct {
	iface  string
	action string
	chain  string
}

func (m interfaceToChain) Key() []string {
	return []string{m.iface}
}

func (m interfaceToChain) String() string {
	return fmt.Sprintf("%s -> %s %s", m.iface, m.action, m.chain)
}

func (m interfaceToChain) Value() []string {
	return []string{fmt.Sprintf("%s %s", m.action, m.chain)}
}

func mapType(t MapType, ipVersion int) string {
	switch t {
	case MapTypeInterfaceMatch:
		return "ifname : verdict"
	default:
		logrus.WithField("type", string(t)).Panic("Unknown MapType")
	}
	return ""
}
