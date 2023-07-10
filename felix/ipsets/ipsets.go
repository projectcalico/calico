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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/projectcalico/calico/felix/logutils"
)

const (
	MaxIPSetParallelUpdates       = 50
	MaxIPSetDeletionsPerIteration = 20
	RestoreChunkSize              = 1000
)

// IPSets manages a whole "plane" of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type IPSets struct {
	IPVersionConfig *IPVersionConfig

	ipSetIDToIPSet       map[string]*IPSet
	mainIPSetNameToIPSet map[string]*IPSet

	// mutex protects existingIPSetNames and nextTempIPSetIdx, which are accessed by parallel
	// workers during the apply step.
	mutex              sync.Mutex
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

	bufPool sync.Pool

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

		ipSetIDToIPSet:       map[string]*IPSet{},
		mainIPSetNameToIPSet: map[string]*IPSet{},

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
		bufPool:    sync.Pool{New: func() any { return &bytes.Buffer{} }},
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

	setID := setMetadata.SetID
	var ipSet *IPSet
	if ipSet = s.ipSetIDToIPSet[setID]; ipSet != nil {
		// Doing a replace of this IP set
		// FIXME Corner case: IP set exists but is not desired, we resync, ignore it, then try to create it; will fail to check metadata
		if ipSet.IPSetMetadata != setMetadata {
			ipSet.needsFullRewrite = true
		}
		ipSet.deltaTracker.Desired().DeleteAll()
	} else {
		// Create the IP set struct and store it off.
		ipSet = &IPSet{
			IPSetMetadata: setMetadata,
			MainIPSetName: s.IPVersionConfig.NameForMainIPSet(setID),
			deltaTracker:  deltatracker.NewSetDeltaTracker[IPSetMember](),
		}
	}
	canonMembers.Iter(func(item IPSetMember) error {
		ipSet.deltaTracker.Desired().Add(item)
		return nil
	})
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
	canonMembers.Iter(func(item IPSetMember) error {
		ipSet.deltaTracker.Desired().Add(item)
		return nil
	})
	if !ipSet.deltaTracker.InSync() {
		s.dirtyIPSetIDs.Add(setID)
	} else {
		s.dirtyIPSetIDs.Discard(setID)
	}
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

	canonMembers.Iter(func(item IPSetMember) error {
		ipSet.deltaTracker.Desired().Delete(item)
		return nil
	})
	if ipSet.Dirty() {
		s.dirtyIPSetIDs.Add(setID)
	} else {
		s.dirtyIPSetIDs.Discard(setID)
	}
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
	strs := set.New[string]()
	ipSet.deltaTracker.Desired().Iter(func(k IPSetMember) {
		strs.Add(k.String())
	})
	return strs, nil
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

			if err := s.tryResync(); err != nil {
				s.logCxt.WithError(err).Warning("Failed to resync with dataplane")
				backOff()
				continue
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
func (s *IPSets) tryResync() (err error) {
	// Log the time spent as we exit the function.
	resyncStart := time.Now()
	defer func() {
		s.logCxt.WithFields(log.Fields{
			"resyncDuration": time.Since(resyncStart),
			"numDirtyIPSets": s.dirtyIPSetIDs.Len(),
		}).Debug("Finished IPSets resync")
	}()

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
		if strings.HasPrefix(line, "Header:") {
			ipSet, ok := s.mainIPSetNameToIPSet[ipSetName]
			if !ok {
				continue
			}
			parts := strings.Split(line, " ")
			for idx, p := range parts {
				if p == "maxelem" {
					maxElem, err := strconv.Atoi(parts[idx+1])
					if err != nil {
						log.WithError(err).WithField("line", line).Error(
							"Failed to parse ipset list Header line.")
						break
					}
					if ok && maxElem != ipSet.MaxSize {
						log.WithField("name", ipSetName).Info(
							"Need to recreate IP set due to change in max size")
						ipSet.needsFullRewrite = true
					}
					break
				}
			}
		}
		if strings.HasPrefix(line, "Members:") {
			// Start of a Members entry, following this, there'll be one member per
			// line then EOF or a blank line.

			// Look up to see if this is one of our IP sets.
			ipSet := s.mainIPSetNameToIPSet[ipSetName]
			logCxt := s.logCxt.WithField("setName", ipSetName)
			if ipSet == nil {
				logCxt.Debug("Skipping IP set, not one that we are tracking.")
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

			// One of our IP sets; we need to load its members and compare them.
			logCxt = s.logCxt.WithField("setID", ipSet.SetID)
			err = ipSet.deltaTracker.Dataplane().ReplaceFromIter(func(f func(k IPSetMember)) error {
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						// End of members
						break
					}
					canonMember := ipSet.Type.CanonicaliseMember(line)
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
			ipSetName = ""
			if err != nil {
				logCxt.WithError(err).Error("Failed to read members from 'ipset list'.")
				break
			}

			if numMissing := ipSet.deltaTracker.NumPendingUpdates(); numMissing > 0 {
				logCxt.WithField("numMissing", numMissing).Info(
					"Resync found members missing from dataplane.")
			}
			if numExtras := ipSet.deltaTracker.NumPendingDeletions(); numExtras > 0 {
				logCxt.WithField("numExtras", numExtras).Info(
					"Resync found extra members in dataplane.")
			}
			if ipSet.Dirty() {
				s.dirtyIPSetIDs.Add(ipSet.SetID)
			} else {
				s.dirtyIPSetIDs.Discard(ipSet.SetID)
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

	// Scan for IP sets that need to be cleaned up.  Create list containing the IP sets that we expect to be there.
	expectedIPSets := set.NewBoxed[string]()
	for _, ipSet := range s.ipSetIDToIPSet {
		if !s.ipSetNeeded(ipSet.SetID) {
			continue
		}
		expectedIPSets.Add(ipSet.MainIPSetName)
		s.logCxt.WithFields(log.Fields{
			"ID":       ipSet.SetID,
			"mainName": ipSet.MainIPSetName,
		}).Debug("Marking IP set as expected.")
	}

	// Include any pending deletions in the expected set; this is mainly to separate cleanup logs
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

// tryUpdates attempts to create and/or update IP sets.  It starts background goroutines, each
// running one "ipset restore" session.  Note: unlike 'iptables-restore', 'ipset restore' is
// not atomic, updates are applied individually.
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

	var errg errgroup.Group
	errg.SetLimit(MaxIPSetParallelUpdates)

	ipSetChunks := s.chunkUpDirtyIPSets()
	for _, setIDs := range ipSetChunks {
		setIDs := setIDs
		errg.Go(func() error {
			return s.writeIPSetChunk(setIDs)
		})
	}

	log.Debug("Waiting for background IP set updates to finish...")
	err := errg.Wait()
	log.Debug("Background IP set updates finished.")
	if err != nil {
		return fmt.Errorf("failed to write one or more IP set: %v", err)
	}

	// If we get here, the writes were successful, reset the IP sets delta tracking now the
	// dataplane should be in sync.  If we bail out above, then the resync logic will kick in
	// and figure out how much of our update succeeded.
	s.dirtyIPSetIDs.Iter(func(setID string) error {
		if !s.ipSetNeeded(setID) {
			return nil
		}
		ipSet := s.ipSetIDToIPSet[setID]
		// On success, we know the IP set must exist.
		s.existingIPSetNames.Add(ipSet.MainIPSetName)
		return set.RemoveItem
	})

	return nil
}

// chunkUpDirtyIPSets breaks up the dirtyIPSetIDs set into slices for processing in parallel.
func (s *IPSets) chunkUpDirtyIPSets() (chunks [][]string) {
	// We try to make sure that each chunk has a reasonable number of ipset input lines
	// in it.  If we simply made each ipset into its own chunk then we'd pay the overhead of
	// launching the ipset binary for every IP set, even if there was only 1 update per IP
	// set.
	var chunk []string
	var estimatedNumLinesInChunk int
	s.dirtyIPSetIDs.Iter(func(setID string) error {
		chunk = append(chunk, setID)

		ipSet := s.ipSetIDToIPSet[setID]
		estimatedNumLinesInChunk += ipSet.EstimateNumUpdateLines()
		if estimatedNumLinesInChunk >= RestoreChunkSize {
			chunks = append(chunks, chunk)
			chunk = nil
			estimatedNumLinesInChunk = 0
		}
		return nil
	})
	if chunk != nil {
		chunks = append(chunks, chunk)
	}
	return
}

func (s *IPSets) writeIPSetChunk(setIDs []string) error {
	// Set up an ipset restore session.
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithField("setIDs", setIDs).Debug("Started goroutine to update IP sets.")
	}
	countNumIPSetCalls.Inc()
	cmd := s.newCmd("ipset", "restore")
	// Get the pipe for stdin.
	rawStdin, err := cmd.StdinPipe()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to create pipe for ipset restore.")
		return err
	}

	restoreInCopy := s.bufPool.Get().(*bytes.Buffer)
	stdoutCopy := s.bufPool.Get().(*bytes.Buffer)
	stderrCopy := s.bufPool.Get().(*bytes.Buffer)

	// "Tee" the data that we write to stdin to a buffer so we can dump it to the log on
	// failure.
	stdin := io.MultiWriter(restoreInCopy, rawStdin)

	// Channel stdout/err to buffers so we can include them in the log on failure.
	cmd.SetStderr(stderrCopy)
	cmd.SetStdout(stdoutCopy)

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

	var writeErr error
	for _, setID := range setIDs {
		// Ask IP set to write its updates to the stream.
		if !s.ipSetNeeded(setID) {
			continue
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("setID", setID).Debug("Writing updates to IP set.")
		}
		ipSet := s.ipSetIDToIPSet[setID]
		writeErr = s.writeUpdates(ipSet, stdin)
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
			"stdout":     stdoutCopy.String(),
			"stderr":     stderrCopy.String(),
			"input":      restoreInCopy.String(),
		}).Warning("Failed to complete ipset restore, IP sets may be out-of-sync.")
		return err
	}

	restoreInCopy.Reset()
	s.bufPool.Put(restoreInCopy)
	stdoutCopy.Reset()
	s.bufPool.Put(stdoutCopy)
	stderrCopy.Reset()
	s.bufPool.Put(stderrCopy)

	return nil
}

func (s *IPSets) writeUpdates(ipSet *IPSet, w io.Writer) error {
	setID := ipSet.SetID
	logCxt := s.logCxt.WithField("setID", setID)
	// if ipSet.members != nil {
	// 	logCxt = logCxt.WithField("numMembersInDataplane", ipSet.members.Len())
	// }
	// if ipSet.pendingReplace != nil {
	// 	logCxt = logCxt.WithField("numMembersInPendingReplace", ipSet.pendingReplace.Len())
	// } else {
	// 	logCxt = logCxt.WithFields(log.Fields{
	// 		"numDeltaAdds":    ipSet.pendingAdds.Len(),
	// 		"numDeltaDeletes": ipSet.pendingDeletions.Len(),
	// 	})
	// }

	if !s.existingIPSetNames.Contains(ipSet.MainIPSetName) || ipSet.needsFullRewrite {
		logCxt.Info("Doing full IP set rewrite")
		return s.writeFullRewrite(ipSet, w, logCxt)
	}
	if !ipSet.Dirty() {
		logCxt.Debug("Skipping in-sync IP set.")
		return nil
	}
	logCxt.Info("Calculating deltas to IP set")
	return s.writeDeltas(ipSet, w, logCxt)
}

// writeFullRewrite calculates the ipset restore input required to do a full, atomic, idempotent
// rewrite of the IP set and writes it to the given io.Writer.
func (s *IPSets) writeFullRewrite(ipSet *IPSet, out io.Writer, logCxt log.FieldLogger) (err error) {
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

	mainSetName := ipSet.MainIPSetName
	var tempSetName string
	var targetSet string
	if !s.existingIPSetNames.Contains(mainSetName) {
		// Main IP set doesn't exist, create it and then fill it in directly.
		logCxt.WithField("setID", ipSet.SetID).Debug("Pre-creating main IP set")
		writeLine("create %s %s family %s maxelem %d",
			mainSetName, ipSet.Type, s.IPVersionConfig.Family, ipSet.MaxSize)
		targetSet = mainSetName
	} else {
		// Main IP set does exist, create a temp IP set and then do an atomic swap into place.
		// This allows us to change the IP set size, for example.
		tempSetName = s.nextFreeTempIPSetName()
		writeLine("create %s %s family %s maxelem %d",
			tempSetName, ipSet.Type, s.IPVersionConfig.Family, ipSet.MaxSize)
		targetSet = tempSetName
	}
	// Write all the members into the target IP set.
	ipSet.deltaTracker.Desired().Iter(func(member IPSetMember) {
		writeLine("add %s %s", targetSet, member)
	})
	if tempSetName != "" {
		// Atomically swap the temporary set into place.
		writeLine("swap %s %s", mainSetName, tempSetName)
		// Then remove the temporary set (which was the old main set).
		// TODO delete temp IP set lazily
		writeLine("destroy %s", tempSetName)
	}

	// Optimistically record that the dataplane is now in sync.
	ipSet.deltaTracker.IterPendingUpdates(func(k IPSetMember) deltatracker.IterAction {
		return deltatracker.IterActionUpdateDataplane
	})
	ipSet.deltaTracker.IterPendingDeletions(func(k IPSetMember) deltatracker.IterAction {
		return deltatracker.IterActionUpdateDataplane
	})
	ipSet.needsFullRewrite = false
	return
}

// nextFreeTempIPSetName picks a name for a temporary IP set avoiding any that appear to be in use already.
// Giving each temporary IP set a new name works around the fact that we sometimes see transient failures to
// remove temporary IP sets.
func (s *IPSets) nextFreeTempIPSetName() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
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
func (s *IPSets) writeDeltas(ipSet *IPSet, out io.Writer, logCxt log.FieldLogger) (err error) {
	mainSetName := ipSet.MainIPSetName
	ipSet.deltaTracker.IterPendingDeletions(func(member IPSetMember) deltatracker.IterAction {
		logCxt.WithField("member", member).Debug("Writing del")
		_, err = fmt.Fprintf(out, "del %s %s --exist\n", mainSetName, member)
		if err != nil {
			return deltatracker.IterActionNoOp // FIXME stop the iteration
		}
		countNumIPSetLinesExecuted.Inc()
		return deltatracker.IterActionUpdateDataplane
	})
	if err != nil {
		return
	}
	ipSet.deltaTracker.IterPendingUpdates(func(member IPSetMember) deltatracker.IterAction {
		logCxt.WithField("member", member).Debug("Writing add")
		_, err = fmt.Fprintf(out, "add %s %s\n", mainSetName, member)
		if err != nil {
			return deltatracker.IterActionNoOp // FIXME stop the iteration
		}
		countNumIPSetLinesExecuted.Inc()
		return deltatracker.IterActionUpdateDataplane
	})
	return
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time we do a resync.
func (s *IPSets) ApplyDeletions() bool {
	s.tryDeleteIPSets("main", s.pendingIPSetDeletions)

	// ApplyDeletions() marks the end of the two-phase "apply".  Piggy back on that to
	// update the gauge that records how many IP sets we own.
	s.gaugeNumIpsets.Set(float64(len(s.ipSetIDToIPSet)))
	return s.pendingIPSetDeletions.Len() > 0
}

// tryTempIPSetDeletions tries to delete any temporary IP sets found by the last resync.
func (s *IPSets) tryTempIPSetDeletions() {
	s.tryDeleteIPSets("temporary", s.pendingTempIPSetDeletions)
}

func (s *IPSets) tryDeleteIPSets(setType string, setNames set.Set[string]) {
	numDeletions := 0
	setNames.Iter(func(setName string) error {
		if numDeletions >= MaxIPSetDeletionsPerIteration {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of 20 %s IP sets, rate limiting further IP set deletions.", setType)
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return set.StopIteration
		}
		logCxt := s.logCxt.WithField("setName", setName)
		if s.existingIPSetNames.Contains(setName) {
			logCxt.Infof("Deleting %s IP set.", setType)
			if err := s.deleteIPSet(setName); err != nil {
				// Note: we used to set the resyncRequired flag on this path but that can lead to excessive retries if
				// the problem isn't something that we can fix (for example an external app has made a reference to
				// our IP set).  Instead, wait for the next timed resync.
				logCxt.WithError(err).Warningf("Failed to delete %s IP set. Will retry on next resync.", setType)
			}
			numDeletions++
		}
		// Remove the item, so we don't retry until the next timed resync.
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

		// Record that the dataplane is empty.
		ipSet.deltaTracker.Dataplane().DeleteAll()
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
