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
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var gaugeVecNumMaps = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "felix_nft_maps",
	Help: "Number of active Calico nftables maps.",
}, []string{"ip_version"})

type MapType string

const MapTypeInterfaceMatch MapType = "interfaceMatch"

type MapsDataplane interface {
	AddOrReplaceMap(meta MapMetadata, members map[string][]string)
	RemoveMap(id string)

	MapUpdates() *MapUpdates
	FinishMapUpdates(updates *MapUpdates)
	LoadDataplaneState() error
}

var _ MapsDataplane = &Maps{}

type MapMetadata struct {
	Name string
	Type MapType
}

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
	// that we think are in the dataplane.  This includes any temporary
	// maps and maps that we discovered on a resync (neither of which will
	// have entries in the Desired() map).
	mapNameToProgrammedMetadata *deltatracker.DeltaTracker[string, MapMetadata]

	// mapNameToMembers contains entries for all maps that are in
	// mapNameToAllMetadata along with entries for "main" (non-temporary)
	// maps that we think are still in the dataplane. For maps that are in mapNameToAllMetadata, the
	// Desired() side of the tracker contains the members that we've been told
	// about.  Otherwise, Desired() is empty.  The Dataplane() side of the
	// tracker contains the members that are thought to be in the dataplane.
	mapNameToMembers     map[string]*deltatracker.SetDeltaTracker[MapMember]
	mapsWithDirtyMembers set.Set[string]

	gaugeNumMaps prometheus.Gauge
	opReporter   logutils.OpRecorder
	sleep        func(time.Duration)
	logCxt       *logrus.Entry

	nft knftables.Interface

	// Callbacks to increment and decrement reference counts for chains so that chains
	// referenced in maps are programmed by the Table implementation as needed.
	increfChain func(chain string)
	decrefChain func(chain string)
}

func NewMaps(
	ipVersionConfig *ipsets.IPVersionConfig,
	nft knftables.Interface,
	increfChain func(chain string),
	decrefChain func(chain string),
	recorder logutils.OpRecorder,
) *Maps {
	return NewMapsWithShims(
		ipVersionConfig,
		time.Sleep,
		nft,
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
		mapNameToMembers:     map[string]*deltatracker.SetDeltaTracker[MapMember]{},
		mapsWithDirtyMembers: set.New[string](),
		logCxt:               familyLogger,
		gaugeNumMaps:         gaugeVecNumMaps.WithLabelValues(familyStr),
		sleep:                sleep,
		nft:                  nft,
		increfChain:          increfChain,
		decrefChain:          decrefChain,
	}
}

func (s *Maps) AddOrReplaceMap(meta MapMetadata, members map[string][]string) {
	// Mark that we want this map to exist and with the correct size etc.
	// If the map exists, but it has the wrong metadata then the
	// DeltaTracker will catch that and mark it for recreation.
	s.mapNameToAllMetadata[meta.Name] = meta

	logCtx := s.logCxt.WithFields(logrus.Fields{"name": meta.Name, "type": meta.Type})

	logCtx.Info("Queueing map for creation")
	logCtx.WithField("members", members).Info("Queueing map for creation")
	s.mapNameToProgrammedMetadata.Desired().Set(meta.Name, meta)

	// Set the desired contents of the map.
	canonMembers := s.filterAndCanonicaliseMembers(meta.Type, members)
	memberTracker := s.getOrCreateMemberTracker(meta.Name)

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
	s.updateDirtiness(meta.Name)
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
	dt := s.mapNameToMembers[mainMapName]
	if dt == nil {
		dt = deltatracker.NewSetDeltaTracker[MapMember]()
		s.mapNameToMembers[mainMapName] = dt
	}
	return dt
}

// RemoveMap queues up the removal of an map, it need not be empty.
func (s *Maps) RemoveMap(mapName string) {
	// Mark that we no longer need this map.  The DeltaTracker will keep track of the metadata
	// until we actually delete the map.  We clean up mainSetNameToMembers only when we actually
	// delete it.
	delete(s.mapNameToAllMetadata, mapName)
	s.mapNameToProgrammedMetadata.Desired().Delete(mapName)

	// Decref any chains referenced by members of the map.
	s.mapNameToMembers[mapName].Desired().Iter(func(member MapMember) {
		s.maybeDecrefChain(member)
	})

	if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(mapName); ok {
		// Set is currently in the dataplane, clear its desired members but
		// we keep the member tracker until we actually delete the map
		// from the dataplane later.
		s.logCxt.WithField("id", mapName).Info("Queueing map for removal")
		s.mapNameToMembers[mapName].Desired().DeleteAll()
	} else {
		// If it's not in the dataplane, clean it up immediately.
		logrus.WithField("id", mapName).Debug("map to remove not in the dataplane.")
		delete(s.mapNameToMembers, mapName)
	}
	s.updateDirtiness(mapName)
}

// AddMembers adds the given members to the map.  Filters out members that are of the incorrect
// IP version.
func (s *Maps) AddMembers(mapName string, newMembers map[string][]string) {
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		logrus.WithField("mapName", mapName).Panic("AddMembers called for nonexistent map.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, newMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to add")
		return
	}
	membersTracker := s.mapNameToMembers[mapName]
	canonMembers.Iter(func(member MapMember) error {
		s.maybeIncrefChain(member)
		membersTracker.Desired().Add(member)
		return nil
	})
	s.updateDirtiness(mapName)
}

// RemoveMembers queues up removal of the given members from an map.  Members of the wrong IP
// version are ignored.
func (s *Maps) RemoveMembers(mapName string, removedMembers map[string][]string) {
	setMeta, ok := s.mapNameToAllMetadata[mapName]
	if !ok {
		logrus.WithField("mapName", mapName).Panic("RemoveMembers called for nonexistent map.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, removedMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to remove")
		return
	}
	membersTracker := s.mapNameToMembers[mapName]
	canonMembers.Iter(func(member MapMember) error {
		s.maybeDecrefChain(member)
		membersTracker.Desired().Delete(member)
		return nil
	})
	s.updateDirtiness(mapName)
}

func (s *Maps) GetIPFamily() ipsets.IPFamily {
	return s.IPVersionConfig.Family
}

func (s *Maps) filterAndCanonicaliseMembers(mtype MapType, members map[string][]string) set.Set[MapMember] {
	filtered := set.New[MapMember]()
	for k, v := range members {
		filtered.Add(CanonicaliseMapMember(mtype, k, v))
	}
	return filtered
}

// tryResync attempts to bring our state into sync with the dataplane.  It scans the contents of the
// maps in the dataplane and queues up updates to any maps that are out-of-sync.
func (s *Maps) LoadDataplaneState() error {
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
	// of the data plane.
	//
	// For any map that doesn't match the desired data plane state, we'll queue up an update.
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

	// We'll process each map in parallel, so we need a struct to hold the results.
	// Once knftables is augmented to support reading many maps at once, we can remove this.
	type mapData struct {
		name  string
		elems []*knftables.Element
	}

	// Create an errgroup to manage the fleet of goroutines.
	g, egCtx := errgroup.WithContext(ctx)
	g.SetLimit(100)
	responses := make([]mapData, len(maps))

	for i, name := range maps {
		// Start a goroutine to read this map.
		g.Go(func() error {
			elems, err := s.nft.ListElements(egCtx, "map", name)
			if err != nil {
				return err
			}
			responses[i] = mapData{name: name, elems: elems}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("failed to list map elements: %w", err)
	}

	for _, mapData := range responses {
		mapName := mapData.name
		logCxt := s.logCxt.WithField("mapName", mapName)

		// TODO: We need to be able to extract the map type from the dataplane, otherwise we cannot
		// tell whether or not the map has the correct type.
		metadata, ok := s.mapNameToAllMetadata[mapName]
		if !ok {
			// Programmed in the data plane, but not in memory. We should still load any members of this map in order
			// to perform map deletion logic (delete members, delete map).
			logCxt.Info("Map in dataplane but not in memory, will remove it.")
		}

		// At this point, we likely know what type the map is and so we can parse the elements.
		//
		// Any maps that this version of Felix cannot parse will have their members removed, and then be deleted.
		// In theory, it is possible that the same map will contain differently formatted members
		// if programmed by different versions of Felix. This can be detected by looking at the programmed
		// map metadata and extracting the type. However, knftables does not yet support this operation. For now,
		// assume that we haven't modified the type of an map across Felix versions.

		// Build a set of canonicalized elements in the map by first converting to Felix's internal string representation,
		// and then canonicalizing the members to match the format that we use in the desired state.
		strElems := map[string][]string{}
		unknownElems := set.New[MapMember]()
		for _, e := range mapData.elems {
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
			return fmt.Errorf("failed to read map memebers: %w", err)
		}

		// Mark us as having seen the programmed map.
		// TODO: Ideally we'd extract this information from the data plane itself, but it's not exposed
		// via knftables at the moment.
		s.mapNameToProgrammedMetadata.Dataplane().Set(mapName, MapMetadata{
			Name: metadata.Name,
			Type: metadata.Type,
		})

		if numMissing := memberTracker.PendingUpdates().Len(); numMissing > 0 {
			logCxt.WithField("numMissing", numMissing).Info("Resync found members missing from dataplane.")
		}
		if numExtras := memberTracker.PendingDeletions().Len() - numExtrasExpected; numExtras > 0 {
			logCxt.WithField("numExtras", numExtras).Info("Resync found extra members in dataplane.")
		}
		s.updateDirtiness(mapName)
	}

	// Mark any maps that we didn't see as empty.
	for name, members := range s.mapNameToMembers {
		if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(name); ok {
			// In the dataplane, we should have updated its members above.
			continue
		}
		if _, ok := s.mapNameToAllMetadata[name]; !ok {
			// Defensive: this map is not in the dataplane, and it's not
			// one we are tracking, clean up its member tracker.
			logrus.WithField("name", name).Warn("Cleaning up leaked(?) map member tracker.")
			delete(s.mapNameToMembers, name)
			continue
		}
		// We're tracking this map, but we didn't find it in the dataplane;
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

func newMapUpdates() *MapUpdates {
	return &MapUpdates{
		MapToAddedMembers:   map[string]set.Set[MapMember]{},
		MapToDeletedMembers: map[string]set.Set[MapMember]{},
	}
}

type MapUpdates struct {
	MapsToCreate []*knftables.Map
	MapsToDelete []*knftables.Map
	MembersToAdd []*knftables.Element
	MembersToDel []*knftables.Element

	// Track MapMembers so we can update internal state after a successful write.
	MapToAddedMembers   map[string]set.Set[MapMember]
	MapToDeletedMembers map[string]set.Set[MapMember]
}

// MapUpdates returns a mapUpdates structure containing the pending work to be done in the next nftables
// transaction. After a successful transaction, the FinishMapUpdates function should be called to update
// internal state tracking.
func (s *Maps) MapUpdates() *MapUpdates {
	updates := newMapUpdates()

	for _, mapName := range s.dirtyMaps() {
		// Add any maps that we need to program.
		if _, ok := s.mapNameToProgrammedMetadata.Dataplane().Get(mapName); !ok {
			if m := s.NFTablesMap(mapName); m != nil {
				updates.MapsToCreate = append(updates.MapsToCreate, m)
			}
		}

		// Remove any elements that are no longer needed.
		members := s.getOrCreateMemberTracker(mapName)
		members.PendingDeletions().Iter(func(member MapMember) deltatracker.IterAction {
			updates.MembersToDel = append(updates.MembersToDel, &knftables.Element{
				Map:   mapName,
				Key:   member.Key(),
				Value: member.Value(),
			})
			if updates.MapToDeletedMembers[mapName] == nil {
				updates.MapToDeletedMembers[mapName] = set.New[MapMember]()
			}
			updates.MapToDeletedMembers[mapName].Add(member)
			return deltatracker.IterActionNoOp
		})

		// Add desired members to the set.
		members.Desired().Iter(func(member MapMember) {
			if members.Dataplane().Contains(member) {
				return
			}
			updates.MembersToAdd = append(updates.MembersToAdd, &knftables.Element{
				Map:   mapName,
				Key:   member.Key(),
				Value: member.Value(),
			})
			if updates.MapToAddedMembers[mapName] == nil {
				updates.MapToAddedMembers[mapName] = set.New[MapMember]()
			}
			updates.MapToAddedMembers[mapName].Add(member)
		})
	}

	// Add any maps that are marked for deletion.
	s.mapNameToProgrammedMetadata.PendingDeletions().Iter(func(mapName string) deltatracker.IterAction {
		updates.MapsToDelete = append(updates.MapsToDelete, &knftables.Map{Name: mapName})
		return deltatracker.IterActionNoOp
	})

	return updates
}

// FinishMapUpdates updates internal state after a successful nftables transaction to keep our
// model of the data plane in sync.
// It receives the mapUpdates structure returned by MapUpdates as input.
func (s *Maps) FinishMapUpdates(updates *MapUpdates) {
	// Helper function for updating our Dataplane view after a successful write.
	setMap := func(mapName string) {
		v, _ := s.mapNameToProgrammedMetadata.Desired().Get(mapName)
		s.mapNameToProgrammedMetadata.Dataplane().Set(mapName, v)
	}

	// If we get here, the writes were successful, reset the maps delta tracking now the
	// dataplane should be in sync.
	for mapName, members := range updates.MapToAddedMembers {
		setMap(mapName)
		members.Iter(func(member MapMember) error {
			s.mapNameToMembers[mapName].Dataplane().Add(member)
			return nil
		})
	}
	for mapName, members := range updates.MapToDeletedMembers {
		setMap(mapName)
		members.Iter(func(member MapMember) error {
			s.mapNameToMembers[mapName].Dataplane().Delete(member)
			return nil
		})
	}

	// We need to clear pending deletions now that we have successfully deleted the maps.
	s.mapNameToProgrammedMetadata.PendingDeletions().Iter(func(mapName string) deltatracker.IterAction {
		return deltatracker.IterActionUpdateDataplane
	})

	// Update the gauge that records how many maps we own.
	s.gaugeNumMaps.Set(float64(s.mapNameToProgrammedMetadata.Dataplane().Len()))

	// Dirty maps have all been processed.
	s.mapsWithDirtyMembers.Clear()
}

func (s *Maps) dirtyMaps() []string {
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

	return dirtyMaps
}

func (s *Maps) updateDirtiness(name string) {
	memberTracker, ok := s.mapNameToMembers[name]
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
