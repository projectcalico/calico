package nftables

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ipsets"
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

	sleep func(time.Duration)

	resyncRequired bool

	logCxt *log.Entry

	// Optional filter.  When non-nil, only these IP set IDs will be rendered into the dataplane
	// as Linux IP sets.
	neededIPSetNames set.Set[string]

	nft knftables.Interface
}

func NewIPSets(ipVersionConfig *ipsets.IPVersionConfig, nft knftables.Interface) *IPSets {
	return NewIPSetsWithShims(
		ipVersionConfig,
		time.Sleep,
		nft,
	)
}

// NewIPSetsWithShims is an internal test constructor.
func NewIPSetsWithShims(ipVersionConfig *ipsets.IPVersionConfig, sleep func(time.Duration), nft knftables.Interface) *IPSets {
	return &IPSets{
		IPVersionConfig:      ipVersionConfig,
		setNameToAllMetadata: map[string]ipsets.IPSetMetadata{},
		setNameToProgrammedMetadata: deltatracker.New[string, ipsets.IPSetMetadata](
			deltatracker.WithValuesEqualFn[string, ipsets.IPSetMetadata](func(a, b ipsets.IPSetMetadata) bool {
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
	mainIPSetName := s.IPVersionConfig.NameForMainIPSet(setID)
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
		s.logCxt.WithField("setID", setID).Info("Queueing IP set for removal")
		s.mainSetNameToMembers[setName].Desired().DeleteAll()
	} else {
		// If it's not in the dataplane, clean it up immediately.
		log.Debug("IP set to remove not in the dataplane.")
		delete(s.mainSetNameToMembers, setName)
	}
	s.updateDirtiness(setName)
}

func (s *IPSets) nameForMainIPSet(setID string) string {
	return s.IPVersionConfig.NameForMainIPSet(setID)
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
		filtered.Add(ipSetType.CanonicaliseMember(member))
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
			// s.opReporter.RecordOperation(fmt.Sprint("resync-ipsets-v", s.IPVersionConfig.Family.Version()))

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
			// countNumIPSetErrors.Inc()
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

	// TODO - implement resync.

	return nil
}

func CanonicalizeSetName(setName string) string {
	return strings.Replace(setName, ":", "-", -1)
}

// tryUpdates attempts to create and/or update IP sets.  It attempts to do the updates as a single
// 'ipset restore' session in order to minimise process forking overhead.  Note: unlike
// 'iptables-restore', 'ipset restore' is not atomic, updates are applied individually.
// This function updates the set of programmed IPs - that is the IPs that were added or replaced in the IPSets
// included by the ipsetFilter.
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

	// Make sure the table exists.
	tx.Add(&knftables.Table{})

	for _, setName := range dirtyIPSets {
		// Create the set.
		set := &knftables.Set{
			Name:  CanonicalizeSetName(setName),
			Type:  "ipv4_addr",
			Flags: []knftables.SetFlag{knftables.IntervalFlag},
		}
		tx.Add(set)

		// TODO: Right now, we're simply flushing the set and then adding all members to the set.
		// instead, we should make incremental changes to the set for better performance.
		tx.Flush(set)

		// Add desired members to the set.
		members := s.mainSetNameToMembers[setName]
		members.Desired().Iter(func(member ipsets.IPSetMember) {
			tx.Add(&knftables.Element{
				Set: CanonicalizeSetName(setName),
				Key: []string{member.String()},
			})
		})
	}
	if err := s.nft.Run(context.TODO(), tx); err != nil {
		return fmt.Errorf("error updating nftables sets: %s", err)
	}

	log.Debugf("Updated %d IPSets in %v", len(dirtyIPSets), time.Since(start))

	// If we get here, the writes were successful, reset the IP sets delta tracking now the
	// dataplane should be in sync.
	s.ipSetsWithDirtyMembers.Clear()

	return nil
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (s *IPSets) ApplyDeletions() bool {
	numDeletions := 0
	s.setNameToProgrammedMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if numDeletions >= ipsets.MaxIPSetDeletionsPerIteration {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of %d IP sets, rate limiting further IP set deletions.", ipsets.MaxIPSetDeletionsPerIteration)
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return deltatracker.IterActionNoOpStopIteration
		}
		logCxt := s.logCxt.WithField("setName", setName)
		logCxt.Info("Deleting IP set.")
		if err := s.deleteIPSet(setName); err != nil {
			// Note: we used to set the resyncRequired flag on this path but that can lead to excessive retries if
			// the problem isn't something that we can fix (for example an external app has made a reference to
			// our IP set).  Instead, wait for the next timed resync.
			logCxt.WithError(err).Warning("Failed to delete IP set. Will retry on next resync.")
			return deltatracker.IterActionNoOp
		}
		numDeletions++
		if _, ok := s.setNameToAllMetadata[setName]; !ok {
			// IP set is not just filtered out, clean up the members cache.
			logCxt.Debug("IP set now gone from dataplane, removing from members tracker.")
			delete(s.mainSetNameToMembers, setName)
		} else {
			// We're still tracking this IP set in case it needs to be recreated.
			// Record that the dataplane is now empty.
			logCxt.Debug("IP set now gone from dataplane but still " +
				"tracking its members (it is filtered out).")
			s.mainSetNameToMembers[setName].Dataplane().DeleteAll()
		}
		return deltatracker.IterActionUpdateDataplane
	})
	// ApplyDeletions() marks the end of the two-phase "apply". Piggyback on that to
	// update the gauge that records how many IP sets we own.
	numDeletionsPending := s.setNameToProgrammedMetadata.Dataplane().Len()
	if numDeletions == 0 {
		// We had nothing to delete, or we only encountered errors, don't
		// ask to be rescheduled.
		return false
	}
	return numDeletionsPending > 0 // Reschedule if we have sets left to delete.
}

func (s *IPSets) deleteIPSet(setName string) error {
	s.logCxt.WithField("setName", setName).Info("Deleting IP set.")
	tx := s.nft.NewTransaction()
	tx.Delete(&knftables.Set{Name: CanonicalizeSetName(setName)})
	if err := s.nft.Run(context.Background(), tx); err != nil {
		return fmt.Errorf("error deleting nftables set %s: %v", setName, err)
	}
	s.logCxt.WithField("setName", setName).Info("Deleted IP set")
	return nil
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
