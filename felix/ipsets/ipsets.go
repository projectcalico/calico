// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/logutils"
)

// IPSets manages a whole "plane" of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type IPSets struct {
	IPVersionConfig *IPVersionConfig

	ipSetIDToIPSet       map[string]*ipSet
	mainIPSetNameToIPSet map[string]*ipSet

	existingIPSetNames set.Set[string]
	nextTempIPSetIdx   uint

	// dirtyIPSetIDs contains IDs of IP sets that need updating.
	dirtyIPSetIDs  set.Set[string]
	resyncRequired bool

	// pendingTempIPSetDeletions contains names of temporary IP sets that need to be deleted.  We use it to
	// attempt an early deletion of temporary IP sets, if possible.
	pendingTempIPSetDeletions set.Set[string]
	// pendingIPSetDeletions contains names of IP sets that need to be deleted (including temporary ones).
	pendingIPSetDeletions set.Set[string]

	// Factory for command objects; shimmed for UT mocking.
	newCmd cmdFactory

	// Shim for time.Sleep()
	sleep func(time.Duration)

	gaugeNumIpsets prometheus.Gauge

	logCxt *log.Entry

	// restoreInCopy holds a copy of the stdin that we send to ipset restore.  It is reset
	// after each use.
	restoreInCopy bytes.Buffer
	// stdoutCopy holds a copy of the the stdout emitted by ipset restore. It is reset after
	// each use.
	stdoutCopy bytes.Buffer
	// stderrCopy holds a copy of the the stderr emitted by ipset restore. It is reset after
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

		ipSetIDToIPSet:       map[string]*ipSet{},
		mainIPSetNameToIPSet: map[string]*ipSet{},

		dirtyIPSetIDs:             set.New[string](),
		pendingTempIPSetDeletions: set.New[string](),
		pendingIPSetDeletions:     set.New[string](),
		newCmd:                    cmdFactory,
		sleep:                     sleep,
		existingIPSetNames:        set.New[string](),
		resyncRequired:            true,

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
	s.logCxt.WithFields(log.Fields{
		"setID":   setMetadata.SetID,
		"setType": setMetadata.Type,
	}).Info("Queueing IP set for creation")
	canonMembers := s.filterAndCanonicaliseMembers(setMetadata.Type, members)

	// Create the IP set struct and store it off.
	setID := setMetadata.SetID
	ipSet := &ipSet{
		IPSetMetadata:    setMetadata,
		MainIPSetName:    s.IPVersionConfig.NameForMainIPSet(setID),
		pendingReplace:   canonMembers,
		pendingAdds:      set.NewBoxed[IPSetMember](),
		pendingDeletions: set.NewBoxed[IPSetMember](),
	}
	s.ipSetIDToIPSet[setID] = ipSet
	s.mainIPSetNameToIPSet[ipSet.MainIPSetName] = ipSet

	// Mark IP set dirty so ApplyUpdates() will rewrite it.
	s.dirtyIPSetIDs.Add(setID)

	// The IP set may have been previously queued for deletion, undo that.
	s.pendingIPSetDeletions.Discard(ipSet.MainIPSetName)
}

// RemoveIPSet queues up the removal of an IP set, it need not be empty.  The IP sets will be
// removed on the next call to ApplyDeletions().
func (s *IPSets) RemoveIPSet(setID string) {
	s.logCxt.WithField("setID", setID).Info("Queueing IP set for removal")
	delete(s.ipSetIDToIPSet, setID)
	mainIPSetName := s.IPVersionConfig.NameForMainIPSet(setID)
	delete(s.mainIPSetNameToIPSet, mainIPSetName)
	s.dirtyIPSetIDs.Discard(setID)
	s.pendingIPSetDeletions.Add(mainIPSetName)
}

// AddMembers adds the given members to the IP set.  Filters out members that are of the incorrect
// IP version.
func (s *IPSets) AddMembers(setID string, newMembers []string) {
	ipSet := s.ipSetIDToIPSet[setID]
	setType := ipSet.Type
	canonMembers := s.filterAndCanonicaliseMembers(setType, newMembers)
	if canonMembers.Len() == 0 {
		return
	}
	s.logCxt.WithFields(log.Fields{
		"setID":           setID,
		"filteredMembers": canonMembers,
	}).Debug("Adding new members to IP set")
	if ipSet.pendingReplace != nil {
		canonMembers.Iter(func(m IPSetMember) error {
			ipSet.pendingReplace.Add(m)
			return nil
		})
	} else {
		// Do a delta update.
		canonMembers.Iter(func(m IPSetMember) error {
			ipSet.pendingDeletions.Discard(m)
			if ipSet.members.Contains(m) {
				// IP already in the set, this happens if the IP is removed and then
				// re-added in between updates to the dataplane.
				return nil
			}
			ipSet.pendingAdds.Add(m)
			return nil
		})
	}
	s.dirtyIPSetIDs.Add(setID)
}

// RemoveMembers queues up removal of the given members from an IP set.  Members of the wrong IP
// version are ignored.
func (s *IPSets) RemoveMembers(setID string, removedMembers []string) {
	ipSet := s.ipSetIDToIPSet[setID]
	setType := ipSet.Type
	canonMembers := s.filterAndCanonicaliseMembers(setType, removedMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to remove")
		return
	}
	s.logCxt.WithFields(log.Fields{
		"setID":           setID,
		"filteredMembers": canonMembers,
	}).Debug("Removing members from IP set")
	if ipSet.pendingReplace != nil {
		canonMembers.Iter(func(m IPSetMember) error {
			ipSet.pendingReplace.Discard(m)
			return nil
		})
	} else {
		// Do a delta update.
		canonMembers.Iter(func(m IPSetMember) error {
			ipSet.pendingAdds.Discard(m)
			if !ipSet.members.Contains(m) {
				// IP not in the dataplane, this occurs if the IP was added and
				// then removed without any calls to ApplyUpdates().
				return nil
			}
			ipSet.pendingDeletions.Add(m)
			return nil
		})
	}
	s.dirtyIPSetIDs.Add(setID)
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
	ipSet, ok := s.ipSetIDToIPSet[setID]
	if !ok {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return ipSet.Type, nil
}

func ipSetMemberSetToStringSet(ipsetMembers set.Set[IPSetMember]) set.Set[string] {
	if ipsetMembers == nil {
		return nil
	}
	stringSet := set.New[string]()
	ipsetMembers.Iter(func(member IPSetMember) error {
		stringSet.Add(member.String())
		return nil
	})
	return stringSet
}

func (s *IPSets) filterAndCanonicaliseMembers(ipSetType IPSetType, members []string) set.Set[IPSetMember] {
	filtered := set.NewBoxed[IPSetMember]()
	wantIPV6 := s.IPVersionConfig.Family == IPFamilyV6
	for _, member := range members {
		isIPV6 := ipSetType.IsMemberIPV6(member)
		if wantIPV6 != isIPV6 {
			continue
		}
		filtered.Add(ipSetType.CanonicaliseMember(member))
	}
	return filtered
}

func (s *IPSets) GetMembers(setID string) (set.Set[string], error) {
	ipSet, ok := s.ipSetIDToIPSet[setID]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found", setID)
	}

	if ipSet.pendingReplace != nil {
		return ipSetMemberSetToStringSet(ipSet.pendingReplace), nil
	}

	realMembers := ipSet.members.Copy()

	ipSet.pendingAdds.Iter(func(m IPSetMember) error {
		realMembers.Add(m)
		return nil
	})

	ipSet.pendingDeletions.Iter(func(m IPSetMember) error {
		realMembers.Discard(m)
		return nil
	})

	return ipSetMemberSetToStringSet(realMembers), nil
}

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
			s.opReporter.RecordOperation(fmt.Sprint("resync-ipsets-v", s.IPVersionConfig.Family.Version()))

			numProblems, err := s.tryResync()
			if err != nil {
				s.logCxt.WithError(err).Warning("Failed to resync with dataplane")
				backOff()
				continue
			}
			if numProblems > 0 {
				s.logCxt.WithField("numProblems", numProblems).Warn(
					"Found inconsistencies in IP sets in dataplane")
			}
			s.resyncRequired = false
		}

		numTempSets := s.pendingTempIPSetDeletions.Len()
		if numTempSets > 0 {
			log.WithField("numTempSets", numTempSets).Info(
				"There are left-over temporary IP sets, attempting cleanup")
			s.tryTempIPSetDeletions()
		}

		if err := s.tryUpdates(); err != nil {
			// While failed deletions don't cause immediate problems, update failures may mean that our iptables
			// updates fail.  We need to do an immediate resync.
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
	gaugeNumTotalIpsets.Set(float64(s.existingIPSetNames.Len()))
}

// tryResync attempts to bring our state into sync with the dataplane.  It scans the contents of the
// IP sets in the dataplane and queues up updates to any IP sets that are out-of-sync.
func (s *IPSets) tryResync() (numProblems int, err error) {
	// Log the time spent as we exit the function.
	resyncStart := time.Now()
	defer s.logCxt.WithFields(log.Fields{
		"resyncDuration":          time.Since(resyncStart),
		"numInconsistenciesFound": numProblems,
	}).Debug("Finished IPSets resync")

	// Start an 'ipset list' child process, which will emit output of the following form:
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
	//
	//	Name: test-1
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
	cmd := s.newCmd("ipset", "list")
	// Grab stdout as a pipe so we can stream through the (potentially very large) output.
	out, err := cmd.StdoutPipe()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to get pipe for 'ipset list'")
		return
	}
	// Capture error output into a buffer.
	var stderr bytes.Buffer
	cmd.SetStderr(&stderr)
	execStartTime := time.Now()
	err = cmd.Start()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to start 'ipset list'")
		return
	}
	summaryExecStart.Observe(float64(time.Since(execStartTime).Nanoseconds()) / 1000.0)
	// Clear the set of known IP sets names, we'll fill it back in as we scan.
	s.existingIPSetNames.Clear()
	// Use a scanner to chunk the input into lines.
	scanner := bufio.NewScanner(out)
	ipSetName := ""

	// Figure out if debug logging is enabled so we can disable some expensive-to-calculate logs
	// in the tight loop below if they're not going to be emitted.  This speeds up the loop
	// by a factor of 3-4x!
	debug := log.GetLevel() >= log.DebugLevel

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			ipSetName = strings.Split(line, " ")[1]
			s.existingIPSetNames.Add(ipSetName)
			s.logCxt.WithField("setName", ipSetName).Debug("Parsing IP set.")
		}
		if strings.HasPrefix(line, "Members:") {
			// Start of a Members entry, following this, there'll be one member per
			// line then EOF or a blank line.

			// Look up to see if this is one of our IP sets.
			ipSet := s.mainIPSetNameToIPSet[ipSetName]
			logCxt := s.logCxt.WithField("setName", ipSetName)
			if ipSet == nil || ipSet.members == nil {
				// Either this is not one of our IP sets, or it's one that we're
				// about to rewrite.  Either way, we don't care about its members
				// so simply scan past them.
				logCxt.Debug("Skipping IP set, either not ours or about to rewrite")
				for scanner.Scan() {
					line := scanner.Bytes()
					if len(line) == 0 {
						// End of members
						break
					}
				}
				ipSetName = ""
				continue
			}

			// One of our IP sets and we're not planning to rewrite it; we need to
			// load its members and compare them.
			logCxt = s.logCxt.WithField("setID", ipSet.SetID)
			dataplaneMembers := set.NewBoxed[IPSetMember]()
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					// End of members
					break
				}
				canonMember := ipSet.Type.CanonicaliseMember(line)
				dataplaneMembers.Add(canonMember)
				if debug {
					logCxt.WithFields(log.Fields{
						"member": line,
						"canon":  canonMember,
					}).Debug("Found member in dataplane")
				}
			}
			ipSetName = ""
			if scanner.Err() != nil {
				logCxt.WithError(err).Error("Failed to read members from 'ipset list'.")
				break
			}

			// If we get here, we've read all the members of the IP set.  Compare them
			// with what we expect and queue up any fixes.
			numMissing := 0
			ipSet.members.Iter(func(m IPSetMember) error {
				if dataplaneMembers.Contains(m) {
					// Mainline (correct) case, member is in memory and in the
					// dataplane.
					dataplaneMembers.Discard(m)
					return nil
				}

				logCxt := logCxt.WithField("member", m.String())
				numProblems++
				if ipSet.pendingDeletions.Contains(m) {
					// We were trying to delete this item anyway, record that
					// it's already gone.  We commonly hit this case when we're
					// doing a retry after a failure and we're not sure which
					// deltas got applied.
					logCxt.Debug("Resync found member missing from " +
						"dataplane. (Already queued for deletion.)")
					ipSet.pendingDeletions.Discard(m)
					return set.RemoveItem
				}

				// The item should be in the dataplane but it's not, queue up an
				// add to add it back in.
				if numMissing == 0 {
					logCxt.Warning("Resync found member missing from " +
						"dataplane. Queueing up an add to reinstate it. " +
						"Further inconsistencies will be logged at DEBUG.")
				} else {
					logCxt.Debug("Found another member missing")
				}
				numMissing++
				s.dirtyIPSetIDs.Add(ipSet.SetID)
				ipSet.pendingAdds.Add(m)
				return set.RemoveItem
			})
			if numMissing > 0 {
				logCxt.WithField("numMissing", numMissing).Warn(
					"Resync found members missing from dataplane.")
			}

			// Now look for any members which are in the dataplane but are not expected.
			// We removed the members we were expecting above so dataplaneMembers now
			// contains only unexpected members.
			numExtras := 0
			dataplaneMembers.Iter(func(m IPSetMember) error {
				logCxt := logCxt.WithField("member", m.String())

				// Record that this member really is in the dataplane.
				ipSet.members.Add(m)
				numProblems++

				if ipSet.pendingAdds.Contains(m) {
					// We were trying to add this item anyway, record that
					// it's already there.  We commonly hit this case when we're
					// doing a retry after a failure and we're not sure which
					// deltas got applied.
					logCxt.Debug("Resync found unexpected member in " +
						"dataplane. (Was about to add it anyway.)")
					ipSet.pendingAdds.Discard(m)
					return nil
				}

				// We weren't planning on adding this member, queue up a deletion.
				if numExtras == 0 {
					logCxt.Warning("Resync found unexpected member in " +
						"dataplane. Queueing it for removal.  Further " +
						"inconsistencies will be logged at DEBUG.")
				} else {
					logCxt.Debug("Found another extra member.")
				}
				numExtras++
				s.dirtyIPSetIDs.Add(ipSet.SetID)
				ipSet.pendingDeletions.Add(m)
				return nil
			})
			if numExtras > 0 {
				logCxt.WithField("numExtras", numExtras).Warn(
					"Resync found extra members in dataplane.")
			}
		}
	}
	closeErr := out.Close()
	err = cmd.Wait()
	logCxt := s.logCxt.WithField("stderr", stderr.String())
	if scanner.Err() != nil {
		logCxt.WithError(scanner.Err()).Error("Failed to read 'ipset list' output.")
		err = scanner.Err()
		return
	}
	if err != nil {
		logCxt.WithError(err).Error("Bad return code from 'ipset list'.")
		return
	}
	if closeErr != nil {
		err = closeErr
		logCxt.WithError(err).Error("Failed to close stdout from 'ipset list'.")
		return
	}

	// Scan for IP sets that need to be cleaned up.  Create a whitelist containing the IP sets
	// that we expect to be there.
	expectedIPSets := set.NewBoxed[string]()
	for _, ipSet := range s.ipSetIDToIPSet {
		if !s.ipSetNeeded(ipSet.SetID) {
			continue
		}
		expectedIPSets.Add(ipSet.MainIPSetName)
		s.logCxt.WithFields(log.Fields{
			"ID":       ipSet.SetID,
			"mainName": ipSet.MainIPSetName,
		}).Debug("Whitelisting IP sets.")
	}

	// Include any pending deletions in the whitelist; this is mainly to separate cleanup logs
	// from explicit deletion logs.
	s.pendingIPSetDeletions.Iter(func(item string) error {
		expectedIPSets.Add(item)
		return nil
	})

	// Now look for any left-over IP sets that we should delete and queue up the deletions.
	s.existingIPSetNames.Iter(func(setName string) error {
		if !s.IPVersionConfig.OwnsIPSet(setName) {
			s.logCxt.WithField("setName", setName).Debug(
				"Skipping IP set: non Calico or wrong IP version for this pass.")
			return nil
		}
		if expectedIPSets.Contains(setName) {
			s.logCxt.WithField("setName", setName).Debug("Skipping expected Calico IP set.")
			return nil
		}
		if s.IPVersionConfig.IsTempIPSetName(setName) {
			// Temporary IP sets get leaked after a failure but they should never be in use by iptables so
			// we try to delete them early in the processing to free up IP set space.
			s.logCxt.WithField("setName", setName).Info(
				"Resync found left-over temporary IP set. Queueing early deletion.")
			s.pendingTempIPSetDeletions.Add(setName)
		}
		s.logCxt.WithField("setName", setName).Info(
			"Resync found left-over Calico IP set. Queueing deletion.")
		s.pendingIPSetDeletions.Add(setName)
		return nil
	})

	return
}

// tryUpdates attempts to create and/or update IP sets.  It attempts to do the updates as a single
// 'ipset restore' session in order to minimise process forking overhead.  Note: unlike
// 'iptables-restore', 'ipset restore' is not atomic, updates are applied individually.
func (s *IPSets) tryUpdates() error {
	needUpdates := false
	if s.neededIPSetNames == nil {
		needUpdates = s.dirtyIPSetIDs.Len() > 0
	} else {
		s.dirtyIPSetIDs.Iter(func(setID string) error {
			if s.ipSetNeeded(setID) {
				needUpdates = true
				return set.StopIteration
			}
			return nil
		})
	}
	if !needUpdates {
		s.logCxt.Debug("No dirty IP sets.")
		return nil
	}

	s.opReporter.RecordOperation(fmt.Sprint("update-ipsets-", s.IPVersionConfig.Family.Version()))

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
	s.dirtyIPSetIDs.Iter(func(setID string) error {
		if !s.ipSetNeeded(setID) {
			return nil
		}
		ipSet := s.ipSetIDToIPSet[setID]
		writeErr = s.writeUpdates(ipSet, stdin)
		if writeErr != nil {
			return set.StopIteration
		}
		return nil
	})
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
		return err
	}

	// If we get here, the writes were successful, reset the IP sets delta tracking now the
	// dataplane should be in sync.  If we bail out above, then the resync logic will kick in
	// and figure out how much of our update succeeded.
	s.dirtyIPSetIDs.Iter(func(setID string) error {
		if !s.ipSetNeeded(setID) {
			return nil
		}
		ipSet := s.ipSetIDToIPSet[setID]
		if ipSet.pendingReplace != nil {
			ipSet.members = ipSet.pendingReplace
			ipSet.pendingReplace = nil

			// Doing a rewrite creates the main IP set.
			s.existingIPSetNames.Add(ipSet.MainIPSetName)
		} else {
			ipSet.pendingAdds.Iter(func(m IPSetMember) error {
				ipSet.members.Add(m)
				return set.RemoveItem
			})
			ipSet.pendingDeletions.Iter(func(m IPSetMember) error {
				ipSet.members.Discard(m)
				return set.RemoveItem
			})
		}
		return set.RemoveItem
	})

	return nil
}

func (s *IPSets) writeUpdates(ipSet *ipSet, w io.Writer) error {
	logCxt := s.logCxt.WithField("setID", ipSet.SetID)
	if ipSet.members != nil {
		logCxt = logCxt.WithField("numMembersInDataplane", ipSet.members.Len())
	}
	if ipSet.pendingReplace != nil {
		logCxt = logCxt.WithField("numMembersInPendingReplace", ipSet.pendingReplace.Len())
	} else {
		logCxt = logCxt.WithFields(log.Fields{
			"numDeltaAdds":    ipSet.pendingAdds.Len(),
			"numDeltaDeletes": ipSet.pendingDeletions.Len(),
		})
	}

	if ipSet.pendingReplace == nil {
		// In delta-writing mode:
		// - pendingReplace is nil
		// - membersInDataplane non-nil
		// - pendingAdds/Deletions hold the deltas.
		if ipSet.pendingAdds.Len() == 0 && ipSet.pendingDeletions.Len() == 0 {
			// We hit this case if an IP is added, then removed before we actually
			// write it, nothing to do.
			logCxt.Debug("Skipping delta write, IP set not dirty.")
			return nil
		}
		logCxt.Info("Calculating deltas to IP set")
		return s.writeDeltas(ipSet, w, logCxt)
	}
	// In full-rewrite mode.
	// - pendingReplace is non-nil
	// - membersInDataplane nil
	// - pendingAdds/Deletions empty.
	logCxt.Info("Doing full IP set rewrite")
	return s.writeFullRewrite(ipSet, w, logCxt)
}

// writeFullRewrite calculates the ipset restore input required to do a full, atomic, idempotent
// rewrite of the IP set and writes it to the given io.Writer.
func (s *IPSets) writeFullRewrite(ipSet *ipSet, out io.Writer, logCxt log.FieldLogger) (err error) {
	// writeLine until an error occurs, writeLine writes a line to the output, after an error,
	// it is a no-op.
	writeLine := func(format string, a ...interface{}) {
		if err != nil {
			return
		}
		line := fmt.Sprintf(format, a...) + "\n"
		logCxt.WithField("line", line).Debug("Writing line to ipset restore")
		lineBytes := []byte(line)
		_, err = out.Write(lineBytes)
		if err != nil {
			logCxt.WithError(err).WithFields(log.Fields{
				"line": lineBytes,
			}).Error("Failed to write to ipset restore")
			return
		}
		countNumIPSetLinesExecuted.Inc()
	}

	// Our general approach is to create a temporary IP set with the right contents, then
	// atomically swap it into place.
	mainSetName := ipSet.MainIPSetName
	if !s.existingIPSetNames.Contains(mainSetName) {
		// Create empty main IP set so we can share the atomic swap logic below.
		// Note: we can't use the -exist flag (which should make the create idempotent)
		// because it still fails if the IP set was previously created with different
		// parameters.
		logCxt.WithField("setID", ipSet.SetID).Debug("Pre-creating main IP set")
		writeLine("create %s %s family %s maxelem %d",
			mainSetName, ipSet.Type, s.IPVersionConfig.Family, ipSet.MaxSize)
	}
	tempSetName := s.nextFreeTempIPSetName()
	// Create the temporary IP set with the current parameters.
	writeLine("create %s %s family %s maxelem %d",
		tempSetName, ipSet.Type, s.IPVersionConfig.Family, ipSet.MaxSize)
	// Write all the members into the temporary IP set.
	ipSet.pendingReplace.Iter(func(member IPSetMember) error {
		writeLine("add %s %s", tempSetName, member)
		return nil
	})
	// Atomically swap the temporary set into place.
	writeLine("swap %s %s", mainSetName, tempSetName)
	// Then remove the temporary set (which was the old main set).
	writeLine("destroy %s", tempSetName)

	return
}

// nextFreeTempIPSetName picks a name for a temporary IP set avoiding any that appear to be in use already.
// Giving each temporary IP set a new name works around the fact that we sometimes see transient failures to
// remove temporary IP sets.
func (s *IPSets) nextFreeTempIPSetName() string {
	for {
		candidateName := s.IPVersionConfig.NameForTempIPSet(s.nextTempIPSetIdx)
		s.nextTempIPSetIdx++
		if s.existingIPSetNames.Contains(candidateName) {
			log.WithField("candidate", candidateName).Warning(
				"Skipping in-use temporary IP set name (previous cleanup failure?)")
			continue
		}
		return candidateName
	}
}

// writeDeltas calculates the ipset restore input required to apply the pending adds/deletes to the
// main IP set.
func (s *IPSets) writeDeltas(ipSet *ipSet, out io.Writer, logCxt log.FieldLogger) (err error) {
	mainSetName := ipSet.MainIPSetName
	ipSet.pendingDeletions.Iter(func(member IPSetMember) error {
		logCxt.WithField("member", member).Debug("Writing del")
		_, err = fmt.Fprintf(out, "del %s %s --exist\n", mainSetName, member)
		if err != nil {
			return set.StopIteration
		}
		countNumIPSetLinesExecuted.Inc()
		return nil
	})
	if err != nil {
		return
	}
	ipSet.pendingAdds.Iter(func(member IPSetMember) error {
		logCxt.WithField("member", member).Debug("Writing add")
		_, err = fmt.Fprintf(out, "add %s %s\n", mainSetName, member)
		if err != nil {
			return set.StopIteration
		}
		countNumIPSetLinesExecuted.Inc()
		return nil
	})
	return
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (s *IPSets) ApplyDeletions() {
	s.pendingIPSetDeletions.Iter(func(setName string) error {
		logCxt := s.logCxt.WithField("setName", setName)
		if s.existingIPSetNames.Contains(setName) {
			logCxt.Info("Deleting IP set.")
			if err := s.deleteIPSet(setName); err != nil {
				// Note: we used to set the resyncRequired flag on this path but that can lead to excessive retries if
				// the problem isn't something that we can fix (for example an external app has made a reference to
				// our IP set).  Instead, wait for the next timed resync.
				logCxt.WithError(err).Warning("Failed to delete IP set. Will retry on next resync.")
			}
		}
		// Always remove the item so we don't retry until the next timed resync.
		return set.RemoveItem
	})

	// ApplyDeletions() marks the end of the two-phase "apply".  Piggy back on that to
	// update the gauge that records how many IP sets we own.
	s.gaugeNumIpsets.Set(float64(len(s.ipSetIDToIPSet)))
}

// tryTempIPSetDeletions tries to delete any temporary IP sets found by the last resync.
func (s *IPSets) tryTempIPSetDeletions() {
	s.pendingTempIPSetDeletions.Iter(func(setName string) error {
		logCxt := s.logCxt.WithField("setName", setName)
		if s.existingIPSetNames.Contains(setName) {
			logCxt.Info("Deleting IP set.")
			if err := s.deleteIPSet(setName); err != nil {
				// Log and carry on; we'll try again in ApplyDeletions().
				logCxt.WithError(err).Warning("Failed to delete temporary IP set. Will retry...")
			} else {
				// Success! Remove from the main pending deletions set too.
				logCxt.WithField("setName", setName).Info("Successfully removed left-over temporary IP set.")
				s.pendingIPSetDeletions.Discard(setName)
			}
		}
		// Always remove the item so we don't retry until the next timed resync.
		return set.RemoveItem
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
	// Success, update the cache.
	s.logCxt.WithField("setName", setName).Info("Deleted IP set")
	s.existingIPSetNames.Discard(setName)
	if ipSet := s.mainIPSetNameToIPSet[setName]; ipSet != nil {
		// We are still tracking this IP set; it has been deleted because it's not currently
		// in the "needed" set.
		if s.ipSetNeeded(ipSet.SetID) {
			s.logCxt.Errorf("Unexpected deletion of an IP set %v that is still needed", ipSet.SetID)
		}
		// If we don't already have a pending complete IP set membership...
		if ipSet.pendingReplace == nil {
			// Reconstruct what the IP set membership should be from what was
			// programmed, plus any pending additions, minus any pending deletions.
			ipSet.pendingReplace = ipSet.members
			ipSet.members = nil
			ipSet.pendingAdds.Iter(func(m IPSetMember) error {
				ipSet.pendingReplace.Add(m)
				return set.RemoveItem
			})
			ipSet.pendingDeletions.Iter(func(m IPSetMember) error {
				ipSet.pendingReplace.Discard(m)
				return set.RemoveItem
			})
		}
	}
	return nil
}

func (s *IPSets) dumpIPSetsToLog() {
	cmd := s.newCmd("ipset", "list")
	output, err := cmd.Output()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to read IP sets")
		return
	}
	s.logCxt.WithField("output", string(output)).Info("Current state of IP sets")
}

func firstNonNilErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *IPSets) SetFilter(ipSetNames set.Set[string]) {
	s.logCxt.Debugf("Filtering to needed IP set names: %v", ipSetNames)
	markDirty := func(ipSetName string) {
		if ipSet := s.mainIPSetNameToIPSet[ipSetName]; ipSet != nil {
			s.dirtyIPSetIDs.Add(ipSet.SetID)
		}
	}
	if s.neededIPSetNames != nil {
		s.neededIPSetNames.Iter(func(item string) error {
			if ipSetNames != nil && !ipSetNames.Contains(item) {
				// Name was needed before and now isn't, so mark as dirty.
				markDirty(item)
			}
			return nil
		})
	}
	if ipSetNames != nil {
		ipSetNames.Iter(func(item string) error {
			if s.neededIPSetNames != nil && !s.neededIPSetNames.Contains(item) {
				// Name wasn't needed before and now is, so mark as dirty.
				markDirty(item)
			}
			return nil
		})
	}
	s.neededIPSetNames = ipSetNames
}

func (s *IPSets) ipSetNeeded(id string) bool {
	if s.neededIPSetNames == nil {
		// We're not filtering down to a "needed" set, so all IP sets are needed.
		return true
	}

	// We are filtering down, so compare against the needed set.
	return s.neededIPSetNames.Contains(s.IPVersionConfig.NameForMainIPSet(id))
}
