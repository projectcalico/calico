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
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	MaxIPSetParallelUpdates       = 50
	MaxIPSetDeletionsPerIteration = 20
	RestoreChunkSize              = 1000
)

type dataplaneMetadata struct {
	Type    IPSetType
	MaxSize int
}

// IPSets manages a whole "plane" of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type IPSets struct {
	IPVersionConfig *IPVersionConfig

	// mutex protects setNameToDPMetadata, nextTempIPSetIdx, and dirtyIPSetNames,
	// which are updated from the apply worker goroutines.
	mutex               sync.Mutex
	setNameToDPMetadata *deltatracker.DeltaTracker[string, dataplaneMetadata]
	setNameToMembers    map[string]*deltatracker.SetDeltaTracker[IPSetMember]
	nextTempIPSetIdx    uint
	dirtyIPSetNames     set.Set[string]

	resyncRequired bool

	// Factory for command objects; shimmed for UT mocking.
	newCmd cmdFactory

	// Shim for time.Sleep()
	sleep func(time.Duration)

	gaugeNumIpsets prometheus.Gauge

	logCxt *log.Entry

	bufPool sync.Pool

	opReporter logutils.OpRecorder
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

		setNameToDPMetadata: deltatracker.New[string, dataplaneMetadata](
			deltatracker.WithValuesEqualFn[string, dataplaneMetadata](func(a, b dataplaneMetadata) bool {
				return a == b
			}),
			deltatracker.WithLogCtx[string, dataplaneMetadata](log.WithFields(log.Fields{
				"ipsetFamily": ipVersionConfig.Family,
			})),
		),
		setNameToMembers: map[string]*deltatracker.SetDeltaTracker[IPSetMember]{},

		dirtyIPSetNames: set.New[string](),
		resyncRequired:  true,

		newCmd: cmdFactory,
		sleep:  sleep,

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
	setID := setMetadata.SetID
	s.logCxt.WithFields(log.Fields{
		"setID":   setID,
		"setType": setMetadata.Type,
	}).Info("Queueing IP set for creation")

	// Mark that we want this IP set to exist and with the correct size etc.
	// If the IP set exists, but it has the wrong metadata then the
	// DeltaTracker will catch that and mark it for recreation.
	mainIPSetName := s.IPVersionConfig.NameForMainIPSet(setID)
	dpMeta := dataplaneMetadata{
		Type:    setMetadata.Type,
		MaxSize: setMetadata.MaxSize,
	}
	s.setNameToDPMetadata.Desired().Set(mainIPSetName, dpMeta)

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

	s.dirtyIPSetNames.Add(mainIPSetName)
}

func (s *IPSets) getOrCreateMemberTracker(mainIPSetName string) *deltatracker.SetDeltaTracker[IPSetMember] {
	dt := s.setNameToMembers[mainIPSetName]
	if dt == nil {
		dt = deltatracker.NewSetDeltaTracker[IPSetMember]()
		s.setNameToMembers[mainIPSetName] = dt
	}
	return dt
}

// RemoveIPSet queues up the removal of an IP set, it need not be empty.  The IP sets will be
// removed on the next call to ApplyDeletions().
func (s *IPSets) RemoveIPSet(setID string) {
	s.logCxt.WithField("setID", setID).Info("Queueing IP set for removal")
	// Mark that we no longer need this IP set.  The DeltaTracker will keep track of the metadata
	// until we actually delete the IP set.  We clean up setNameToMembers only when we actually
	// delete it.
	setName := s.nameForMainIPSet(setID)
	s.setNameToDPMetadata.Desired().Delete(setName)
}

func (s *IPSets) nameForMainIPSet(setID string) string {
	return s.IPVersionConfig.NameForMainIPSet(setID)
}

// AddMembers adds the given members to the IP set.  Filters out members that are of the incorrect
// IP version.
func (s *IPSets) AddMembers(setID string, newMembers []string) {
	setName := s.nameForMainIPSet(setID)
	setMeta, ok := s.setNameToDPMetadata.Desired().Get(setName)
	if !ok {
		log.WithField("setName", setName).Panic("AddMembers called for non-existent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, newMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to add")
		return
	}
	membersTracker := s.setNameToMembers[setName]
	desiredMembers := membersTracker.Desired()
	canonMembers.Iter(func(member IPSetMember) error {
		desiredMembers.Add(member)
		return nil
	})
	if !membersTracker.InSync() {
		s.dirtyIPSetNames.Add(setName)
	}
}

// RemoveMembers queues up removal of the given members from an IP set.  Members of the wrong IP
// version are ignored.
func (s *IPSets) RemoveMembers(setID string, removedMembers []string) {
	setName := s.nameForMainIPSet(setID)
	setMeta, ok := s.setNameToDPMetadata.Desired().Get(setName)
	if !ok {
		log.WithField("setName", setName).Panic("AddMembers called for non-existent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, removedMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to remove")
		return
	}
	membersTracker := s.setNameToMembers[setName]
	desiredMembers := membersTracker.Desired()
	canonMembers.Iter(func(member IPSetMember) error {
		desiredMembers.Delete(member)
		return nil
	})
	if !membersTracker.InSync() {
		s.dirtyIPSetNames.Add(setName)
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
	setName := s.nameForMainIPSet(setID)
	setMeta, ok := s.setNameToDPMetadata.Desired().Get(setName)
	if !ok {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return setMeta.Type, nil
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

func (s *IPSets) GetDesiredMembers(setID string) (set.Set[string], error) {
	setName := s.nameForMainIPSet(setID)

	_, ok := s.setNameToDPMetadata.Desired().Get(setName)
	if !ok {
		return nil, fmt.Errorf("ipset %s not found", setID)
	}

	memberTracker, ok := s.setNameToMembers[setName]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found in members tracker", setID)
	}
	strs := set.New[string]()
	memberTracker.Desired().Iter(func(k IPSetMember) {
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

		// FIXME we used to try to delete temporary IP sets here because they're never referenced by iptables
		// so should always be safe to delete (and if ApplyDeletions never gets called then we'd leak them)...
		// numTempSets := s.pendingTempIPSetDeletions.Len()
		// if numTempSets > 0 {
		//	log.WithField("numTempSets", numTempSets).Info(
		//			"There are left-over temporary IP sets, attempting cleanup")
		//		s.tryTempIPSetDeletions()
		//	}

		if err := s.tryUpdates(); err != nil {
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
	gaugeNumTotalIpsets.Set(float64(s.setNameToDPMetadata.Dataplane().Len()))
}

// tryResync attempts to bring our state into sync with the dataplane.  It scans the contents of the
// IP sets in the dataplane and queues up updates to any IP sets that are out-of-sync.
func (s *IPSets) tryResync() (err error) {
	// Log the time spent as we exit the function.
	resyncStart := time.Now()
	defer func() {
		s.logCxt.WithFields(log.Fields{
			"resyncDuration": time.Since(resyncStart),
			"numDirtyIPSets": s.dirtyIPSetNames.Len(),
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

	// Use a scanner to chunk the input into lines.
	scanner := bufio.NewScanner(out)

	// Values of the last-seen header fields.
	ipSetName := ""
	var ipSetType IPSetType

	// Figure out if debug logging is enabled so we can disable some expensive-to-calculate logs
	// in the tight loop below if they're not going to be emitted.  This speeds up the loop
	// by a factor of 3-4x!
	debug := log.GetLevel() >= log.DebugLevel

	for scanner.Scan() {
		line := scanner.Text()
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
			if !s.IPVersionConfig.OwnsIPSet(ipSetName) {
				s.logCxt.WithField("name", ipSetName).Debug("Skip non-Calico IP set.")
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
					meta := dataplaneMetadata{
						Type:    ipSetType,
						MaxSize: maxElem,
					}
					s.setNameToDPMetadata.Dataplane().Set(ipSetName, meta)
					break
				}
			}
		}
		if strings.HasPrefix(line, "Members:") {
			// Start of a Members entry, following this, there'll be one member per
			// line then EOF or a blank line.

			// Look up to see if this is one of our IP sets.
			if !s.IPVersionConfig.OwnsIPSet(ipSetName) || s.IPVersionConfig.IsTempIPSetName(ipSetName) {
				if debug {
					s.logCxt.WithField("name", ipSetName).Debug("Skip parsing members of IP set.")
				}
				for scanner.Scan() {
					line := scanner.Bytes()
					if len(line) == 0 {
						// End of members
						break
					}
				}
				ipSetName = ""
				ipSetType = ""
				continue
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
			err = memberTracker.Dataplane().ReplaceFromIter(func(f func(k IPSetMember)) error {
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						// End of members
						break
					}
					var canonMember IPSetMember
					if ipSetType.IsValid() {
						canonMember = ipSetType.CanonicaliseMember(line)
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
				logCxt.WithError(err).Error("Failed to read members from 'ipset list'.")
				break
			}

			if numMissing := memberTracker.PendingUpdates().Len(); numMissing > 0 {
				logCxt.WithField("numMissing", numMissing).Info(
					"Resync found members missing from dataplane.")
			}
			if numExtras := memberTracker.PendingDeletions().Len(); numExtras > 0 {
				logCxt.WithField("numExtras", numExtras).Info(
					"Resync found extra members in dataplane.")
			}
			if !memberTracker.InSync() {
				s.dirtyIPSetNames.Add(ipSetName)
			} else {
				s.dirtyIPSetNames.Discard(ipSetName)
			}

			ipSetName = ""
			ipSetType = ""
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

	return
}

// tryUpdates attempts to create and/or update IP sets.  It starts background goroutines, each
// running one "ipset restore" session.  Note: unlike 'iptables-restore', 'ipset restore' is
// not atomic, updates are applied individually.
func (s *IPSets) tryUpdates() error {
	if s.setNameToDPMetadata.PendingUpdates().Len() == 0 && s.dirtyIPSetNames.Len() == 0 {
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
	// dataplane should be in sync.
	s.dirtyIPSetNames.Clear()

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
	s.dirtyIPSetNames.Iter(func(setName string) error {
		chunk = append(chunk, setName)
		estimatedNumLinesInChunk += s.estimateUpdateSize(setName)
		if estimatedNumLinesInChunk >= RestoreChunkSize {
			chunks = append(chunks, chunk)
			chunk = nil
			estimatedNumLinesInChunk = 0
		}
		return nil
	})
	s.setNameToDPMetadata.PendingUpdates().Iter(func(setName string, v dataplaneMetadata) deltatracker.IterAction {
		if !s.dirtyIPSetNames.Contains(setName) {
			chunk = append(chunk, setName)
			estimatedNumLinesInChunk += s.estimateUpdateSize(setName)
			if estimatedNumLinesInChunk >= RestoreChunkSize {
				chunks = append(chunks, chunk)
				chunk = nil
				estimatedNumLinesInChunk = 0
			}
		}
		return deltatracker.IterActionNoOp
	})
	if chunk != nil {
		chunks = append(chunks, chunk)
	}
	return
}

func (s *IPSets) writeIPSetChunk(setNames []string) error {
	// Set up an ipset restore session.
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithField("setNames", setNames).Debug("Started goroutine to update IP sets.")
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
	for _, setName := range setNames {
		// Ask IP set to write its updates to the stream.
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("setName", setName).Debug("Writing updates to IP set.")
		}
		writeErr = s.writeUpdates(setName, stdin)
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

func (s *IPSets) writeUpdates(setName string, w io.Writer) (err error) {
	logCxt := s.logCxt.WithField("setName", setName)

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

	s.mutex.Lock()
	desiredMeta, desExists := s.setNameToDPMetadata.PendingUpdates().Get(setName)
	dpMeta, dpExists := s.setNameToDPMetadata.Dataplane().Get(setName)

	// Note: we'll update members below without the lock.  This is safe because we only update
	// it from one worker.
	members, _ := s.setNameToMembers[setName]

	s.mutex.Unlock()

	if !desExists {
		// IP set is going to be deleted, nothing for us to do.
		return nil
	}

	// If the metadata needs to change then we have to write to a temporary IP
	// set and swap it into place.
	needTempIPSet := dpExists && dpMeta != desiredMeta
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
		writeLine("create %s %s family %s maxelem %d",
			targetSet, desiredMeta.Type, s.IPVersionConfig.Family, desiredMeta.MaxSize)
	}
	if err != nil {
		return err
	}
	members.PendingDeletions().Iter(func(member IPSetMember) deltatracker.IterAction {
		writeLine("del %s %s --exist", targetSet, member)
		return deltatracker.IterActionUpdateDataplane
	})
	if err != nil {
		return err
	}
	members.PendingUpdates().Iter(func(member IPSetMember) deltatracker.IterAction {
		writeLine("add %s %s", targetSet, member)
		return deltatracker.IterActionUpdateDataplane
	})
	if needTempIPSet {
		writeLine("swap %s %s", setName, targetSet)
	}
	if err != nil {
		return err
	}

	s.mutex.Lock()
	if needCreate || needTempIPSet {
		if needTempIPSet {
			// After the swap, the temp IP set has the _old_ dataplane metadata.
			s.setNameToDPMetadata.Dataplane().Set(tempSet, dpMeta)
		}
		// The main IP set now has the correct metadata.
		s.setNameToDPMetadata.Dataplane().Set(setName, desiredMeta)
	}
	s.dirtyIPSetNames.Discard(setName)
	s.mutex.Unlock()
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
		if _, ok := s.setNameToDPMetadata.Dataplane().Get(candidateName); ok {
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
	s.setNameToDPMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if numDeletions >= MaxIPSetDeletionsPerIteration {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of 20 IP sets, rate limiting further IP set deletions.")
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
		return deltatracker.IterActionNoOp // deleteIPSet() already deletes the entry.
	})
	// ApplyDeletions() marks the end of the two-phase "apply".  Piggy back on that to
	// update the gauge that records how many IP sets we own.
	numDeletionsPending := s.setNameToDPMetadata.Dataplane().Len()
	s.gaugeNumIpsets.Set(float64(numDeletionsPending))
	return numDeletionsPending > 0
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
	s.setNameToDPMetadata.Dataplane().Delete(setName)
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

func (s *IPSets) estimateUpdateSize(name string) int {
	desiredMeta, desExists := s.setNameToDPMetadata.PendingUpdates().Get(name)
	dpMeta, dpExists := s.setNameToDPMetadata.Dataplane().Get(name)
	if !desExists {
		return 0 // Deletions are handled elsewhere.
	}
	memberTracker := s.setNameToMembers[name]
	if dpExists {
		if desiredMeta != dpMeta {
			// Full rewrite needed to change metadata.
			return 1 /*create*/ + memberTracker.Desired().LenUpperBound() + 1 /*swap*/
		} else {
			// Metadata up to date, just need to apply updates.
			return memberTracker.PendingUpdates().Len() + memberTracker.PendingDeletions().Len()
		}
	} else {
		// Full rewrite needed to create IPs set
		return 1 /*create*/ + memberTracker.Desired().LenUpperBound()
	}
}
