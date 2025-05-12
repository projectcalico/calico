// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.
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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	MaxIPSetDeletionsPerIteration = 1
)

type dataplaneMetadata struct {
	Type         IPSetType
	MaxSize      int
	RangeMin     int
	RangeMax     int
	DeleteFailed bool
}

// IPSets manages a whole "plane" of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type IPSets struct {
	IPVersionConfig *IPVersionConfig

	// setNameToAllMetadata contains an entry for each IP set that has been
	// added by a call to AddOrReplaceIPSet (and not subsequently removed).
	// It is *not* filtered by neededIPSetNames.
	setNameToAllMetadata map[string]dataplaneMetadata
	// setNameToProgrammedMetadata tracks the IP sets that we want to program and
	// those that are actually in the dataplane.  It's Desired() map is the
	// subset of setNameToAllMetadata that matches the neededIPSetNames filter.
	// Its Dataplane() map contains all IP sets matching the IPVersionConfig
	// that we think are in the dataplane.  This includes any temporary IP
	// sets and IP sets that we discovered on a resync (neither of which will
	// have entries in the Desired() map).
	setNameToProgrammedMetadata *deltatracker.DeltaTracker[string, dataplaneMetadata]
	// mainSetNameToMembers contains entries for all IP sets that are in
	// setNameToAllMetadata along with entries for "main" (non-temporary) IP
	// sets that we think are still in the dataplane.  It is not filtered by
	// neededIPSetNames.  For IP sets that are in setNameToAllMetadata, the
	// Desired() side of the tracker contains the members that we've been told
	// about.  Otherwise, Desired() is empty.  The Dataplane() side of the
	// tracker contains the members that are thought to be in the dataplane.
	mainSetNameToMembers   map[string]*deltatracker.SetDeltaTracker[IPSetMember]
	nextTempIPSetIdx       uint
	ipSetsWithDirtyMembers set.Set[string]

	resyncRequired bool

	// Factory for command objects; shimmed for UT mocking.
	newCmd cmdFactory

	// Shim for time.Sleep()
	sleep func(time.Duration)

	gaugeNumIpsets prometheus.Gauge

	logCxt *log.Entry

	// restoreInCopy holds a copy of the stdin that we send to ipset restore.  It is reset
	// after each use.
	restoreInCopy bytes.Buffer
	// stdoutCopy holds a copy of the stdout emitted by ipset restore. It is reset after
	// each use.
	stdoutCopy bytes.Buffer
	// stderrCopy holds a copy of the stderr emitted by ipset restore. It is reset after
	// each use.
	stderrCopy bytes.Buffer

	opReporter logutils.OpRecorder

	// Optional filter.  When non-nil, only these IP set IDs will be rendered into the dataplane
	// as Linux IP sets.
	neededIPSetNames set.Set[string]
}

func NewIPSets(ipVersionConfig *IPVersionConfig, recorder logutils.OpRecorder) *IPSets {
	return NewIPSetsWithShims(
		ipVersionConfig,
		recorder,
		newRealCmd,
		time.Sleep,
	)
}

// NewIPSetsWithShims is an internal test constructor.
func NewIPSetsWithShims(
	ipVersionConfig *IPVersionConfig,
	recorder logutils.OpRecorder,
	cmdFactory cmdFactory,
	sleep func(time.Duration),
) *IPSets {
	familyStr := string(ipVersionConfig.Family)
	return &IPSets{
		IPVersionConfig: ipVersionConfig,

		setNameToAllMetadata: map[string]dataplaneMetadata{},
		setNameToProgrammedMetadata: deltatracker.New[string, dataplaneMetadata](
			deltatracker.WithValuesEqualFn[string, dataplaneMetadata](func(a, b dataplaneMetadata) bool {
				return a == b
			}),
			deltatracker.WithLogCtx[string, dataplaneMetadata](log.WithFields(log.Fields{
				"ipsetFamily": ipVersionConfig.Family,
			})),
		),
		mainSetNameToMembers: map[string]*deltatracker.SetDeltaTracker[IPSetMember]{},

		ipSetsWithDirtyMembers: set.New[string](),
		resyncRequired:         true,

		newCmd: cmdFactory,
		sleep:  sleep,

		gaugeNumIpsets: gaugeVecNumCalicoIpsets.WithLabelValues(familyStr),

		logCxt: log.WithFields(log.Fields{
			"family": ipVersionConfig.Family,
		}),
		opReporter: recorder,
	}
}

// AddOrReplaceIPSet queues up the creation (or replacement) of an IP set.  After the next call
// to ApplyUpdates(), the IP sets will be replaced with the new contents and the set's metadata
// will be updated as appropriate.
func (s *IPSets) AddOrReplaceIPSet(setMetadata IPSetMetadata, members []string) {
	// We need to convert members to a canonical representation (which may be, for example,
	// an ip.Addr instead of a string) so that we can compare them with members that we read
	// back from the dataplane.  This also filters out IPs of the incorrect IP version.
	setID := setMetadata.SetID

	// Mark that we want this IP set to exist and with the correct size etc.
	// If the IP set exists, but it has the wrong metadata then the
	// DeltaTracker will catch that and mark it for recreation.
	mainIPSetName := s.IPVersionConfig.NameForMainIPSet(setID)
	dpMeta := dataplaneMetadata{
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
	desiredMembers.Iter(func(k IPSetMember) {
		if canonMembers.Contains(k) {
			canonMembers.Discard(k)
		} else {
			desiredMembers.Delete(k)
		}
	})
	canonMembers.Iter(func(m IPSetMember) error {
		desiredMembers.Add(m)
		return nil
	})
	s.updateDirtiness(mainIPSetName)
}

func (s *IPSets) getOrCreateMemberTracker(mainIPSetName string) *deltatracker.SetDeltaTracker[IPSetMember] {
	dt := s.mainSetNameToMembers[mainIPSetName]
	if dt == nil {
		dt = deltatracker.NewSetDeltaTracker[IPSetMember]()
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
	canonMembers.Iter(func(member IPSetMember) error {
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
	canonMembers.Iter(func(member IPSetMember) error {
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

func (s *IPSets) GetIPFamily() IPFamily {
	return s.IPVersionConfig.Family
}

func (s *IPSets) GetTypeOf(setID string) (IPSetType, error) {
	setName := s.nameForMainIPSet(setID)
	setMeta, ok := s.setNameToAllMetadata[setName]
	if !ok {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return setMeta.Type, nil
}

func (s *IPSets) filterAndCanonicaliseMembers(ipSetType IPSetType, members []string) set.Set[IPSetMember] {
	filtered := set.New[IPSetMember]()
	wantIPV6 := s.IPVersionConfig.Family == IPFamilyV6
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
	memberTracker.Desired().Iter(func(k IPSetMember) {
		strs.Add(k.String())
	})
	return strs, nil
}

// ApplyUpdates applies the updates to the dataplane.  Returns a set of programmed IPs in the IPSets included by the
// ipsetFilter.
func (s *IPSets) ApplyUpdates(ipsetFilter func(ipSetName string) bool) (programmedIPs set.Set[string]) {
	success := false
	retryDelay := 1 * time.Millisecond
	backOff := func() {
		s.sleep(retryDelay)
		retryDelay *= 2
	}

	programmedIPs = set.New[string]()
	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			s.logCxt.Info("Retrying after an ipsets update failure...")
		}
		if s.resyncRequired {
			// Compare our in-memory state against the dataplane and queue up
			// modifications to fix any inconsistencies.
			s.logCxt.Debug("Resyncing ipsets with dataplane.")
			s.opReporter.RecordOperation(fmt.Sprint("resync-ipsets-v", s.IPVersionConfig.Family.Version()))

			if err := s.tryResync(); err != nil {
				s.logCxt.WithError(err).Warning("Failed to resync with dataplane")
				backOff()
				continue
			}
			s.resyncRequired = false
		}

		// Opportunistically delete some temporary IP sets.  It's possible
		// that ApplyDeletions doesn't get called if there's another failure
		// and deleting some temp sets might free up some room.
		s.tryTempIPSetDeletions()

		if err := s.tryUpdates(ipsetFilter, programmedIPs); err != nil {
			// Update failures may mean that our iptables updates fail.  We need to do an immediate resync.
			s.logCxt.WithError(err).Warning("Failed to update IP sets. Marking dataplane for resync.")
			s.resyncRequired = true
			countNumIPSetErrors.Inc()
			backOff()
			continue
		}

		success = true
		break
	}
	if !success {
		s.dumpIPSetsToLog()
		s.logCxt.Panic("Failed to update IP sets after multiple retries.")
	}
	gaugeNumTotalIpsets.Set(float64(s.setNameToProgrammedMetadata.Dataplane().Len()))

	return programmedIPs
}

// tryResync attempts to bring our state into sync with the dataplane.  It scans the contents of the
// IP sets in the dataplane and queues up updates to any IP sets that are out-of-sync.
func (s *IPSets) tryResync() (err error) {
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

	// Figure out if debug logging is enabled so we can disable some expensive-to-calculate logs
	// in the tight loop below if they're not going to be emitted.  This speeds up the loop
	// by a factor of 3-4x!
	debug := log.GetLevel() >= log.DebugLevel

	// Clear the dataplane metadata view, we'll build it back up again as we
	// scan.
	s.setNameToProgrammedMetadata.Dataplane().DeleteAll()

	ipSets, err := s.CalicoIPSets()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to get the list of ipsets")
		return
	}
	if debug {
		s.logCxt.Debugf("List of ipsets: %v", ipSets)
	}

	for _, name := range ipSets {
		if debug {
			s.logCxt.Debugf("Parsing IP set %v.", name)
		}
		err = s.resyncIPSet(name)
		if err != nil {
			s.logCxt.WithError(err).Errorf("Failed to parse ipset %v", name)
			return
		}
	}

	// Mark any IP sets that we didn't see as empty.
	for name, members := range s.mainSetNameToMembers {
		if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(name); ok {
			// In the dataplane, we should have updated its members above.
			continue
		}
		if _, ok := s.setNameToAllMetadata[name]; !ok {
			// Defensive: this IP set is not in the dataplane, and it's not
			// one we are tracking, clean up its member tracker.
			log.WithField("name", name).Warn(
				"Cleaning up leaked(?) IP set member tracker.")
			delete(s.mainSetNameToMembers, name)
			continue
		}
		// We're tracking this IP set, but we didn't find it in the dataplane;
		// reset the members set to empty.
		members.Dataplane().DeleteAll()
	}

	return
}

func (s *IPSets) CalicoIPSets() ([]string, error) {
	// Start an 'ipset list -name' child process, which will emit ipset's name, one at each line:
	//
	// 	test-100
	//	test-1
	//  ...
	var ipSets []string
	// Run ipset with -name to get the name of all ipsets
	err := s.runIPSetList("-name", func(scanner *bufio.Scanner) error {
		debug := log.GetLevel() >= log.DebugLevel
		for scanner.Scan() {
			name := scanner.Text()
			// Look up to see if this is one of our IP sets.
			if !s.IPVersionConfig.OwnsIPSet(name) {
				if debug {
					s.logCxt.WithField("name", name).Debug("Skip non-Calico/wrong version IP set.")
				}
				continue
			}
			ipSets = append(ipSets, name)
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
	return ipSets, nil
}

func (s *IPSets) resyncIPSet(ipSetName string) error {
	// If ipSetName == "", it will run 'ipset list' which will return the list and details of all ipsets.
	// We should prevent this to not hit ipset protocol mismatch from non-calico ipsets.
	if ipSetName == "" {
		return fmt.Errorf("no ipset name specified")
	}
	// Start an 'ipset list [name]' child process, which will emit output of the following form:
	//
	// 	Name: test-1
	//	Type: hash:ip
	//	Revision: 4
	//	Header: family inet hashsize 1024 maxelem 65536
	//	Size in memory: 224
	//	References: 0
	//	Members:
	//	10.0.0.1
	//	10.0.0.2
	//
	// As we stream through the data, we extract the name of the IP set and its members. We
	// use the IP set's metadata to convert each member to its canonical form for comparison.
	err := s.runIPSetList(ipSetName, func(scanner *bufio.Scanner) error {
		debug := log.GetLevel() >= log.DebugLevel
		ipSetName := ""
		var ipSetType IPSetType
		for scanner.Scan() {
			line := scanner.Text()
			if debug {
				s.logCxt.Debugf("Parsing line: %q", line)
			}
			if strings.HasPrefix(line, "Name:") {
				ipSetName = strings.Split(line, " ")[1]
				if debug {
					s.logCxt.WithField("setName", ipSetName).Debug("Parsing IP set.")
				}
			}
			if strings.HasPrefix(line, "Type:") {
				ipSetType = IPSetType(strings.Split(line, " ")[1])
				if debug {
					s.logCxt.WithField("type", ipSetType).Debug("Parsed type of IP set.")
				}
			}
			if strings.HasPrefix(line, "Header:") {
				// When we hit the Header line we should know the name, and type of the IP set, which lets
				// us update the tracker.
				parts := strings.Split(line, " ")
				meta := dataplaneMetadata{
					Type: ipSetType,
				}
				for idx, p := range parts {
					if p == "maxelem" {
						if idx+1 >= len(parts) {
							return fmt.Errorf(
								"failed to parse ipset list Header line, nothing after 'maxelem'. line: '%v'", line)
						}
						maxElem, err := strconv.Atoi(parts[idx+1])
						if err != nil {
							return fmt.Errorf(
								"Failed to parse ipset list Header line. line: '%v', err: %w", line, err)
						}
						meta.MaxSize = maxElem
						break
					}
					if p == "range" {
						if idx+1 >= len(parts) {
							return fmt.Errorf(
								"Failed to parse ipset list Header line, nothing after 'range'. line: '%v'", line)
						}
						// For bitmaps, we see "range 123-456"
						rMin, rMAx, err := ParseRange(parts[idx+1])
						if err != nil {
							return fmt.Errorf(
								"Failed to parse ipset list Header line. line: '%v', err: %w", line, err)
						}
						meta.RangeMin = rMin
						meta.RangeMax = rMAx
						break
					}
				}
				s.setNameToProgrammedMetadata.Dataplane().Set(ipSetName, meta)
			}
			if strings.HasPrefix(line, "Members:") {
				// Start of a Members entry, following this, there'll be one member per
				// line then EOF or a blank line.

				// Optimisation: skip parsing temporary IP set members.
				// We only need to track their metadata to make sure they
				// are deleted.
				if s.IPVersionConfig.IsTempIPSetName(ipSetName) {
					if debug {
						s.logCxt.WithField("name", ipSetName).Debug("Skip parsing members of IP set.")
					}
					return nil
				}

				if !ipSetType.IsValid() {
					s.logCxt.WithFields(log.Fields{
						"setName": ipSetName,
						"type":    string(ipSetType),
					}).Warning("Dataplane IP set has unknown type.")
				}

				// One of our IP sets; we need to parse its members.
				logCxt := s.logCxt.WithField("setName", ipSetName)
				memberTracker := s.getOrCreateMemberTracker(ipSetName)
				numExtrasExpected := memberTracker.PendingDeletions().Len()
				err := memberTracker.Dataplane().ReplaceFromIter(func(f func(k IPSetMember)) error {
					for scanner.Scan() {
						line := scanner.Text()
						if line == "" {
							// End of members
							break
						}
						var canonMember IPSetMember
						if ipSetType.IsValid() {
							canonMember = CanonicaliseMember(ipSetType, line)
						} else {
							// Unknown type found in dataplane, record it as
							// a raw string.  Then we'll clean up the IP set
							// when we go to sync.
							canonMember = rawIPSetMember(line)
						}
						if debug {
							logCxt.WithFields(log.Fields{
								"member": line,
								"canon":  canonMember,
							}).Debug("Found member in dataplane")
						}
						f(canonMember)
					}
					return scanner.Err()
				})
				if err != nil {
					return fmt.Errorf("Failed to read members from 'ipset list'. err: %w", err)
				}

				if numMissing := memberTracker.PendingUpdates().Len(); numMissing > 0 {
					logCxt.WithField("numMissing", numMissing).Info(
						"Resync found members missing from dataplane.")
				}
				if numExtras := memberTracker.PendingDeletions().Len() - numExtrasExpected; numExtras > 0 {
					logCxt.WithField("numExtras", numExtras).Info(
						"Resync found extra members in dataplane.")
				}

				s.updateDirtiness(ipSetName)
			}
		}
		return scanner.Err()
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *IPSets) runIPSetList(arg string, parsingFunc func(*bufio.Scanner) error) error {
	cmd := s.newCmd("ipset", "list", arg)
	cmdStr := fmt.Sprintf("ipset list %v", arg)
	// Grab stdout as a pipe so we can stream through the (potentially very large) output.
	out, err := cmd.StdoutPipe()
	if err != nil {
		s.logCxt.WithError(err).Errorf("Failed to get pipe for '%v'.", cmdStr)
		return err
	}
	// Capture error output into a buffer.
	var stderr bytes.Buffer
	cmd.SetStderr(&stderr)
	execStartTime := time.Now()
	err = cmd.Start()
	if err != nil {
		s.logCxt.WithError(err).Errorf("Failed to start '%v'.", cmdStr)
		return err
	}
	summaryExecStart.Observe(float64(time.Since(execStartTime).Nanoseconds()) / 1000.0)

	// Use a scanner to chunk the input into lines.
	scanner := bufio.NewScanner(out)
	parsingErr := parsingFunc(scanner)
	if parsingErr == nil {
		// In case the parsingFunc stopped early, drain stdout fully.
		for scanner.Scan() {
		}
		parsingErr = scanner.Err()
	}
	closeErr := out.Close()
	err = cmd.Wait()
	logCxt := s.logCxt.WithField("stderr", stderr.String())
	if scanner.Err() != nil {
		err = scanner.Err()
		logCxt.WithError(err).Errorf("Failed to read '%v' output.", cmdStr)
		return err
	}
	if err != nil {
		logCxt.WithError(err).Errorf("Bad return code from '%v'.", cmdStr)
		return err
	}
	if closeErr != nil {
		logCxt.WithError(closeErr).Errorf("Failed to close stdout from '%v'.", cmdStr)
		return closeErr
	}
	if parsingErr != nil {
		logCxt.WithError(parsingErr).Errorf("Failed to process '%v' output.", cmdStr)
		return parsingErr
	}
	return nil
}

func ParseRange(s string) (min int, max int, err error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		err = fmt.Errorf("failed to parse range %q", s)
		return
	}
	if min, err = strconv.Atoi(parts[0]); err != nil {
		err = fmt.Errorf("failed to parse range %q (%w)", s, err)
		return
	}
	if max, err = strconv.Atoi(parts[1]); err != nil {
		err = fmt.Errorf("failed to parse range %q (%w)", s, err)
		return
	}
	return
}

// tryUpdates attempts to create and/or update IP sets.  It attempts to do the updates as a single
// 'ipset restore' session in order to minimise process forking overhead.  Note: unlike
// 'iptables-restore', 'ipset restore' is not atomic, updates are applied individually.
// This function updates the set of programmed IPs - that is the IPs that were added or replaced in the IPSets
// included by the ipsetFilter.
func (s *IPSets) tryUpdates(ipsetFilter func(ipSetName string) bool, programmedIPs set.Set[string]) error {
	var dirtyIPSets []string
	s.ipSetsWithDirtyMembers.Iter(func(setName string) error {
		if _, ok := s.setNameToProgrammedMetadata.Desired().Get(setName); !ok {
			// Skip deletions and IP sets that aren't needed due to the filter.
			return nil
		}
		dirtyIPSets = append(dirtyIPSets, setName)
		return nil
	})
	s.setNameToProgrammedMetadata.PendingUpdates().Iter(func(setName string, v dataplaneMetadata) deltatracker.IterAction {
		if !s.ipSetsWithDirtyMembers.Contains(setName) {
			dirtyIPSets = append(dirtyIPSets, setName)
		}
		return deltatracker.IterActionNoOp
	})
	if len(dirtyIPSets) == 0 {
		s.logCxt.Debug("No dirty IP sets.")
		return nil
	}
	s.opReporter.RecordOperation(fmt.Sprint("update-ipsets-", s.IPVersionConfig.Family.Version()))

	start := time.Now()
	// Set up an ipset restore session.
	countNumIPSetCalls.Inc()
	cmd := s.newCmd("ipset", "restore")
	// Get the pipe for stdin.
	rawStdin, err := cmd.StdinPipe()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to create pipe for ipset restore.")
		return err
	}

	// "Tee" the data that we write to stdin to a buffer so we can dump it to the log on
	// failure.
	stdin := io.MultiWriter(&s.restoreInCopy, rawStdin)
	defer s.restoreInCopy.Reset()

	// Channel stdout/err to buffers so we can include them in the log on failure.
	cmd.SetStderr(&s.stderrCopy)
	defer s.stderrCopy.Reset()
	cmd.SetStdout(&s.stdoutCopy)
	defer s.stdoutCopy.Reset()

	// Actually start the child process.
	startTime := time.Now()
	err = cmd.Start()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to start ipset restore.")
		closeErr := rawStdin.Close()
		if closeErr != nil {
			s.logCxt.WithError(closeErr).Error(
				"Error closing stdin while handling start error")
		}
		return err
	}
	summaryExecStart.Observe(float64(time.Since(startTime).Nanoseconds()) / 1000.0)

	// Ask each dirty IP set to write its updates to the stream.
	var writeErr error
	for _, setName := range dirtyIPSets {
		// Ask IP set to write its updates to the stream.
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("setName", setName).Debug("Writing updates to IP set.")
		}
		var progIPs set.Set[string]
		if ipsetFilter != nil && ipsetFilter(setName) {
			// We want to include the IPs from this set.
			progIPs = programmedIPs
		}
		writeErr = s.writeUpdates(setName, stdin, progIPs)
		if writeErr != nil {
			break
		}
	}

	// Finish off the input, then flush and close the input, or the command won't terminate.
	// We need to close and wait whether we hit a write error or not so we defer the error
	// handling.
	_, commitErr := stdin.Write([]byte("COMMIT\n"))
	flushErr := rawStdin.Flush()
	closeErr := rawStdin.Close()
	processErr := cmd.Wait()
	if err = firstNonNilErr(writeErr, commitErr, flushErr, closeErr, processErr); err != nil {
		s.logCxt.WithFields(log.Fields{
			"writeErr":   writeErr,
			"commitErr":  commitErr,
			"flushErr":   flushErr,
			"closeErr":   closeErr,
			"processErr": processErr,
			"stdout":     s.stdoutCopy.String(),
			"stderr":     s.stderrCopy.String(),
			"input":      s.restoreInCopy.String(),
		}).Warning("Failed to complete ipset restore, IP sets may be out-of-sync.")
		return fmt.Errorf("failed to write one or more IP set: %v", err)
	}
	log.Debugf("Updated %d IPSets in %v", len(dirtyIPSets), time.Since(start))

	// If we get here, the writes were successful, reset the IP sets delta tracking now the
	// dataplane should be in sync.
	s.ipSetsWithDirtyMembers.Clear()

	return nil
}

func (s *IPSets) writeUpdates(setName string, w io.Writer, programmedIPs set.Set[string]) (err error) {
	logCxt := s.logCxt.WithField("setName", setName)

	desiredMeta, desiredExists := s.setNameToProgrammedMetadata.Desired().Get(setName)
	dpMeta, dpExists := s.setNameToProgrammedMetadata.Dataplane().Get(setName)

	members, membersExists := s.mainSetNameToMembers[setName]

	if !desiredExists {
		log.WithField("setName", setName).Panic("writeUpdates called for pending deletion?")
	}
	if !membersExists {
		log.WithField("setName", setName).Panic("writeUpdates called for missing IP set?")
	}

	// If the metadata needs to change then we have to write to a temporary IP
	// set and swap it into place.
	needTempIPSet := dpExists && dpMeta != desiredMeta
	if needTempIPSet {
		log.WithFields(log.Fields{
			"desired":   desiredMeta,
			"dataplane": dpMeta,
			"setName":   setName,
		}).Info("IP set metadata change, need to use a temporary IP set.")
	}
	// If the IP set doesn't exist yet, we need to create it.
	needCreate := !dpExists

	// writeLine until an error occurs, writeLine writes a line to the output, after an error,
	// it is a no-op.
	writeLine := func(format string, a ...interface{}) {
		if err != nil {
			return
		}
		line := fmt.Sprintf(format, a...) + "\n"
		logCxt.WithField("line", line).Debug("Writing line to ipset restore")
		lineBytes := []byte(line)
		_, err = w.Write(lineBytes)
		if err != nil {
			logCxt.WithError(err).WithFields(log.Fields{
				"line": lineBytes,
			}).Error("Failed to write to ipset restore")
			return
		}
		countNumIPSetLinesExecuted.Inc()
	}

	var targetSet, tempSet string
	if needTempIPSet {
		tempSet = s.nextFreeTempIPSetName()
		targetSet = tempSet
		// Temp IP set is empty.
		members.Dataplane().DeleteAll()
	} else {
		targetSet = setName
	}
	if needCreate || needTempIPSet {
		logCxt.WithField("ipSetToCreate", targetSet).Debug("Creating IP set")

		switch desiredMeta.Type {
		case IPSetTypeBitmapPort:
			writeLine("create %s %s range %d-%d",
				targetSet, desiredMeta.Type, desiredMeta.RangeMin, desiredMeta.RangeMax)
		default:
			writeLine("create %s %s family %s maxelem %d",
				targetSet, desiredMeta.Type, s.IPVersionConfig.Family, desiredMeta.MaxSize)
		}

	}
	if err != nil {
		return
	}
	members.PendingDeletions().Iter(func(member IPSetMember) deltatracker.IterAction {
		writeLine("del %s %s --exist", targetSet, member)
		if err != nil {
			// Note, just exiting early here to save a load of no-ops.
			// If we exit with an error, the dataplane state will be resynced.
			return deltatracker.IterActionNoOpStopIteration
		}
		return deltatracker.IterActionUpdateDataplane
	})
	members.PendingUpdates().Iter(func(member IPSetMember) deltatracker.IterAction {
		memberStr := member.String()
		writeLine("add %s %s", targetSet, memberStr)
		if err != nil {
			// Note, just exiting early here to save a load of no-ops.
			// If we exit with an error, the dataplane state will be resynced.
			return deltatracker.IterActionNoOpStopIteration
		}
		if programmedIPs != nil {
			programmedIPs.Add(memberStr)
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if needTempIPSet {
		writeLine("swap %s %s", setName, targetSet)
	}
	if err != nil {
		return
	}

	if needCreate || needTempIPSet {
		if needTempIPSet {
			// After the swap, the temp IP set has the _old_ dataplane metadata.
			s.setNameToProgrammedMetadata.Dataplane().Set(tempSet, dpMeta)
		}
		// The main IP set now has the correct metadata.
		s.setNameToProgrammedMetadata.Dataplane().Set(setName, desiredMeta)
	}
	return
}

// nextFreeTempIPSetName picks a name for a temporary IP set avoiding any that
// appear to be in use already. Giving each temporary IP set a new name works
// around the fact that we sometimes see transient failures to remove
// temporary IP sets.
func (s *IPSets) nextFreeTempIPSetName() string {
	for {
		candidateName := s.IPVersionConfig.NameForTempIPSet(s.nextTempIPSetIdx)
		s.nextTempIPSetIdx++
		if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(candidateName); ok {
			log.WithField("candidate", candidateName).Warning(
				"Skipping in-use temporary IP set name (previous cleanup failure?)")
			continue
		}
		return candidateName
	}
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (s *IPSets) ApplyDeletions() bool {
	numDeletions := 0
	s.setNameToProgrammedMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if numDeletions >= MaxIPSetDeletionsPerIteration {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of %d IP sets, rate limiting further IP set deletions.", MaxIPSetDeletionsPerIteration)
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return deltatracker.IterActionNoOpStopIteration
		}
		meta, _ := s.setNameToProgrammedMetadata.Dataplane().Get(setName)
		if meta.DeleteFailed {
			// We previously failed to delete this IP set, skip it until
			// the next resync.
			return deltatracker.IterActionNoOp
		}
		logCxt := s.logCxt.WithField("setName", setName)
		logCxt.Info("Deleting IP set.")
		if err := s.deleteIPSet(setName); err != nil {
			// Note: we used to set the resyncRequired flag on this path but that can lead to excessive retries if
			// the problem isn't something that we can fix (for example an external app has made a reference to
			// our IP set).  Instead, wait for the next timed resync.
			logCxt.WithError(err).Warning("Failed to delete IP set. Will retry on next resync.")
			meta.DeleteFailed = true
			s.setNameToProgrammedMetadata.Dataplane().Set(setName, meta)
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
	s.gaugeNumIpsets.Set(float64(s.setNameToProgrammedMetadata.Dataplane().Len()))

	// Determine if we need to be rescheduled.
	numDeletionsPending := s.setNameToProgrammedMetadata.PendingDeletions().Len()
	if numDeletions == 0 {
		// We had nothing to delete, or we only encountered errors, don't
		// ask to be rescheduled.
		return false
	}
	return numDeletionsPending > 0 // Reschedule if we have sets left to delete.
}

func (s *IPSets) tryTempIPSetDeletions() {
	numDeletions := 0
	s.setNameToProgrammedMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if numDeletions >= MaxIPSetDeletionsPerIteration {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of 20 temp IP sets, rate limiting further IP set deletions.")
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return deltatracker.IterActionNoOpStopIteration
		}
		if !s.IPVersionConfig.IsTempIPSetName(setName) {
			return deltatracker.IterActionNoOp
		}
		meta, _ := s.setNameToProgrammedMetadata.Dataplane().Get(setName)
		if meta.DeleteFailed {
			return deltatracker.IterActionNoOp
		}
		logCxt := s.logCxt.WithField("setName", setName)
		logCxt.Info("Deleting IP set.")
		if err := s.deleteIPSet(setName); err != nil {
			logCxt.WithError(err).Warning("Failed to delete temp IP set. Will retry...")
			return deltatracker.IterActionNoOp
		}
		numDeletions++
		return deltatracker.IterActionUpdateDataplane
	})
}

func (s *IPSets) deleteIPSet(setName string) error {
	s.logCxt.WithField("setName", setName).Info("Deleting IP set.")
	cmd := s.newCmd("ipset", "destroy", string(setName))
	if output, err := cmd.CombinedOutput(); err != nil {
		s.logCxt.WithError(err).WithFields(log.Fields{
			"setName": setName,
			"output":  string(output),
		}).Warn("Failed to delete IP set, may be out-of-sync.")
		return err
	}
	s.logCxt.WithField("setName", setName).Info("Deleted IP set")
	return nil
}

func (s *IPSets) dumpIPSetsToLog() {
	ipSets, err := s.CalicoIPSets()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to get the list of IP sets.")
		return
	}
	s.logCxt.Infof("Current state of IP sets: %v", strings.Join(ipSets, " "))

	for _, name := range ipSets {
		s.logCxt.Infof("Dumping IP set %v.", name)

		// Start an 'ipset list [name]' child process, which will emit output of the following form:
		//
		// 	Name: test-100
		//	Type: hash:ip
		//	Revision: 4
		//	Header: family inet hashsize 1024 maxelem 65536
		//	Size in memory: 224
		//	References: 0
		//	Members:
		//	10.0.0.2
		//	10.0.0.1
		err := s.runIPSetList(name, func(scanner *bufio.Scanner) error {
			for scanner.Scan() {
				s.logCxt.Infof("%v", scanner.Text())
			}
			return scanner.Err()
		})
		if err != nil {
			s.logCxt.WithError(err).Errorf("Failed to read ipset %v", name)
			continue
		}
	}
}

func firstNonNilErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
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

// CanonicaliseMember converts the string representation of an IP set member to a canonical
// object of some kind.  The object is required to by hashable.
func CanonicaliseMember(t IPSetType, member string) IPSetMember {
	switch t {
	case IPSetTypeHashIP:
		// Convert the string into our ip.Addr type, which is backed by an array.
		ipAddr := ip.FromIPOrCIDRString(member)
		if ipAddr == nil {
			// This should be prevented by validation in libcalico-go.
			log.WithField("ip", member).Panic("Failed to parse IP")
		}
		return ipAddr
	case IPSetTypeHashIPPort:
		// The member should be of the format <IP>,(tcp|udp):<port number>
		parts := strings.Split(member, ",")
		if len(parts) != 2 {
			log.WithField("member", member).Panic("Failed to parse IP,port IP set member")
		}
		ipAddr := ip.FromString(parts[0])
		if ipAddr == nil {
			// This should be prevented by validation.
			log.WithField("member", member).Panic("Failed to parse IP part of IP,port member")
		}
		// parts[1] should contain "(tcp|udp|sctp):<port number>"
		parts = strings.Split(parts[1], ":")
		var proto labelindex.IPSetPortProtocol
		switch strings.ToLower(parts[0]) {
		case "udp":
			proto = labelindex.ProtocolUDP
		case "tcp":
			proto = labelindex.ProtocolTCP
		case "sctp":
			proto = labelindex.ProtocolSCTP
		default:
			log.WithField("member", member).Panic("Unknown protocol")
		}
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
			return V4IPPort{
				IP:       ipAddr.(ip.V4Addr),
				Port:     uint16(port),
				Protocol: proto,
			}
		} else {
			return V6IPPort{
				IP:       ipAddr.(ip.V6Addr),
				Port:     uint16(port),
				Protocol: proto,
			}
		}
	case IPSetTypeHashNet:
		// Convert the string into our ip.CIDR type, which is backed by a struct.  When
		// pretty-printing, the hash:net ipset type prints IPs with no "/32" or "/128"
		// suffix.
		return ip.MustParseCIDROrIP(member)
	case IPSetTypeBitmapPort:
		// Trim the family if it exists
		if member[0] == 'v' {
			member = member[3:]
		}
		port, err := strconv.Atoi(member)
		if err == nil && port >= 0 && port <= 0xffff {
			return Port(port)
		}
	case IPSetTypeHashNetNet:
		cidrs := strings.Split(member, ",")
		return netNet{
			cidr1: ip.MustParseCIDROrIP(cidrs[0]),
			cidr2: ip.MustParseCIDROrIP(cidrs[1]),
		}
	}
	log.WithField("type", string(t)).Panic("Unknown IPSetType")
	return nil
}
