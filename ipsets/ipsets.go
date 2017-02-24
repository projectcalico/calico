// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"os/exec"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"

	"time"

	"github.com/projectcalico/felix/set"
)

// IPSets manages a whole "plane" of IP sets, i.e. all the IPv4 or IPv6 IP sets.
type IPSets struct {
	IPVersionConfig *IPVersionConfig

	ipSetIDToIPSet       map[string]*ipSet
	mainIPSetNameToIPSet map[string]*ipSet

	existingIPSetNames set.Set

	// dirtyIPSetIDs contains IDs of IP sets that need updating.
	dirtyIPSetIDs  set.Set
	resyncRequired bool

	// pendingIPSetDeletions contains names of IP sets that need to be deleted.
	pendingIPSetDeletions set.Set

	// Factory for command objects; shimmed for UT mocking.
	newCmd cmdFactory

	gaugeNumIpsets prometheus.Gauge

	logCxt *log.Entry
}

func NewIPSets(ipVersionConfig *IPVersionConfig) *IPSets {
	return NewIPSetsWithShims(
		ipVersionConfig,
		newRealCmd,
	)
}

// NewIPSetsWithShims is an internal test constructor.
func NewIPSetsWithShims(
	ipVersionConfig *IPVersionConfig,
	cmdFactory cmdFactory,
) *IPSets {
	familyStr := string(ipVersionConfig.Family)
	return &IPSets{
		IPVersionConfig: ipVersionConfig,

		ipSetIDToIPSet:       map[string]*ipSet{},
		mainIPSetNameToIPSet: map[string]*ipSet{},

		dirtyIPSetIDs:         set.New(),
		pendingIPSetDeletions: set.New(),
		newCmd:                cmdFactory,
		existingIPSetNames:    set.New(),
		resyncRequired:        true,

		gaugeNumIpsets: gaugeVecNumCalicoIpsets.WithLabelValues(familyStr),

		logCxt: log.WithFields(log.Fields{
			"family": ipVersionConfig.Family,
		}),
	}
}

func (s *IPSets) AddOrReplaceIPSet(setMetadata IPSetMetadata, members []string) {
	canonMembers := s.filterAndCanonicaliseMembers(setMetadata.Type, members)
	setID := setMetadata.SetID
	ipSet := &ipSet{
		IPSetMetadata:    setMetadata,
		MainIPSetName:    s.IPVersionConfig.NameForMainIPSet(setID),
		TempIPSetName:    s.IPVersionConfig.NameForTempIPSet(setID),
		pendingReplace:   canonMembers,
		pendingAdds:      set.New(),
		pendingDeletions: set.New(),
	}
	s.ipSetIDToIPSet[setID] = ipSet
	s.mainIPSetNameToIPSet[s.IPVersionConfig.NameForMainIPSet(setID)] = ipSet
	s.dirtyIPSetIDs.Add(setID)
	s.pendingIPSetDeletions.Discard(ipSet.MainIPSetName)
	s.pendingIPSetDeletions.Discard(ipSet.TempIPSetName)
}

func (s *IPSets) RemoveIPSet(setID string) {
	s.logCxt.WithField("setID", setID).Info("Removing IP set")
	delete(s.ipSetIDToIPSet, setID)
	mainIPSetName := s.IPVersionConfig.NameForMainIPSet(setID)
	tempIPSetName := s.IPVersionConfig.NameForTempIPSet(setID)
	delete(s.mainIPSetNameToIPSet, mainIPSetName)
	s.dirtyIPSetIDs.Discard(setID)
	s.pendingIPSetDeletions.Add(mainIPSetName)
	s.pendingIPSetDeletions.Add(tempIPSetName)
}

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
		canonMembers.Iter(func(m interface{}) error {
			ipSet.pendingReplace.Add(m)
			return nil
		})
	} else {
		// Do a delta update.
		canonMembers.Iter(func(m interface{}) error {
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

func (s *IPSets) QueueResync() {
	s.logCxt.Info("Forcing a resync with the dataplane on next update.")
	s.resyncRequired = true
}

func (s *IPSets) RemoveMembers(setID string, removedMembers []string) {
	ipSet := s.ipSetIDToIPSet[setID]
	setType := ipSet.Type
	canonMembers := s.filterAndCanonicaliseMembers(setType, removedMembers)
	if canonMembers.Len() == 0 {
		return
	}
	s.logCxt.WithFields(log.Fields{
		"setID":           setID,
		"filteredMembers": canonMembers,
	}).Debug("Removing members from IP set")
	if ipSet.pendingReplace != nil {
		canonMembers.Iter(func(m interface{}) error {
			ipSet.pendingReplace.Discard(m)
			return nil
		})
	} else {
		// Do a delta update.
		canonMembers.Iter(func(m interface{}) error {
			ipSet.pendingAdds.Discard(m)
			if !ipSet.members.Contains(m) {
				// IP already in the set, this happens if the IP is removed and then
				// re-added in between updates to the dataplane.
				return nil
			}
			ipSet.pendingDeletions.Add(m)
			return nil
		})
	}
	s.dirtyIPSetIDs.Add(setID)
}

func (s *IPSets) filterAndCanonicaliseMembers(ipSetType IPSetType, members []string) set.Set {
	filtered := set.New()
	wantIPV6 := s.IPVersionConfig.Family == IPFamilyV6
	for _, member := range members {
		isIPV6 := strings.Index(member, ":") >= 0
		if wantIPV6 != isIPV6 {
			continue
		}
		filtered.Add(ipSetType.CanonicaliseMember(member))
	}
	return filtered
}

func (s *IPSets) ApplyUpdates() {
	success := false
	lastNumProblems := -1
	for attempts := 0; attempts < 3; attempts++ {
		if s.resyncRequired {
			// Compare our in-memory state against the dataplane and queue up
			// modifications to fix any inconsistencies.
			s.logCxt.Info("Resyncing ipsets with dataplane.")
			numProblems, err := s.tryResync()
			if err != nil {
				s.logCxt.WithError(err).Error("Failed to resync with dataplane")
				continue
			}
			if lastNumProblems >= 0 && numProblems < lastNumProblems {
				// Number of problems is going down, allow more retries.
				s.logCxt.WithField("numInconsistencies", numProblems).Info(
					"IP sets converging, allowing more retries.")
				attempts--
			}
			lastNumProblems = numProblems
			s.resyncRequired = false
		}

		if err := s.tryUpdates(); err != nil {
			s.logCxt.WithError(err).Error("Failed to update IP sets.")
			s.resyncRequired = true
			countNumIPSetErrors.Inc()
			continue
		}

		success = true
	}
	if !success {
		s.dumpIPSetsToLog()
		s.logCxt.Panic("Failed to update IP sets after mutliple retries.")
	}
	gaugeNumTotalIpsets.Set(float64(s.existingIPSetNames.Len()))
}

func (s *IPSets) tryResync() (numProblems int, err error) {
	resyncStart := time.Now()
	defer func() {
		log.WithFields(log.Fields{
			"resyncDuration":          time.Since(resyncStart),
			"numInconsistenciesFound": numProblems,
		}).Info("Finished resync")
	}()

	cmd := exec.Command("ipset", "list")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	startTime := time.Now()
	cmd.Start()
	summaryExecStart.Observe(float64(time.Since(startTime).Nanoseconds()) / 1000.0)
	s.existingIPSetNames.Clear()
	scanner := bufio.NewScanner(out)
	ipSetName := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			ipSetName = strings.Split(line, " ")[1]
			s.existingIPSetNames.Add(ipSetName)
		}
		if strings.HasPrefix(line, "Members:") {
			ipSet := s.mainIPSetNameToIPSet[ipSetName]
			logCxt := log.WithField("setName", ipSetName)
			if ipSet != nil {
				logCxt = log.WithField("setID", ipSet.SetID)
			}
			dpMembers := set.New()
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					// End of members
					ipSetName = ""
					break
				}
				if ipSet != nil && ipSet.members != nil {
					// IP set is in delta-update mode; collect the members we
					// see in the dataplane.
					canonMember := ipSet.Type.CanonicaliseMember(line)
					dpMembers.Add(canonMember)
					logCxt.WithFields(log.Fields{
						"member": line,
						"canon":  canonMember,
					}).Debug("Found member in dataplane")
				}
			}
			if scanner.Err() != nil {
				err = scanner.Err()
				return
			}
			if ipSet == nil || ipSet.members == nil {
				// Either the ipSet is unknown, or we're about to rewrite it anyway.
				continue
			}

			// If we get here, we've read all the members of the IP set.  Compare them
			// with what we expect and queue up any fixes.
			numMissing := 0
			ipSet.members.Iter(func(item interface{}) error {
				m := item.(ipSetMember)
				if dpMembers.Contains(m) {
					// Mainline case, member is in memory and in the dataplane.
					dpMembers.Discard(m)
					return nil
				}

				logCxt := logCxt.WithFields(log.Fields{
					"member": m.String(),
				})

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
				numProblems++
				s.dirtyIPSetIDs.Add(ipSet.SetID)
				ipSet.pendingAdds.Add(m)
				return set.RemoveItem
			})
			if numMissing > 0 {
				logCxt.WithField("numMissing", numMissing).Warn(
					"Resync found members missing from dataplane.	")
			}
			// We removed the members we were expecting above so dpMembers now contains
			// only unexpected members.
			numExtras := 0
			dpMembers.Iter(func(item interface{}) error {
				m := item.(ipSetMember)
				logCxt := logCxt.WithFields(log.Fields{
					"member": m.String(),
				})

				// Record that this member really is in the dataplane.
				ipSet.members.Add(m)

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
				numProblems++
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
	out.Close()
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

	// Scan for IP sets that need to be cleaned up.  Create a whitelist containing the IP sets
	// that we expect to be there.
	expectedIPSets := set.New()
	for _, ipSet := range s.ipSetIDToIPSet {
		expectedIPSets.Add(ipSet.MainIPSetName)
		expectedIPSets.Add(ipSet.TempIPSetName)
		s.logCxt.WithFields(log.Fields{
			"ID":       ipSet.SetID,
			"mainName": ipSet.MainIPSetName,
			"tempName": ipSet.TempIPSetName,
		}).Debug("Whitelisting IP sets.")
	}

	// Include any pending deletions in the whitelist; this is mainly to separate cleanup logs
	// from explicit deletion logs.
	s.pendingIPSetDeletions.Iter(func(item interface{}) error {
		expectedIPSets.Add(item)
		return nil
	})

	// Now look for any left-over IP sets that we should delete and queue up the deletions.
	s.existingIPSetNames.Iter(func(item interface{}) error {
		setName := item.(string)
		if !s.IPVersionConfig.OwnsIPSet(setName) {
			s.logCxt.WithField("setName", setName).Debug(
				"Skipping IP set: non Calico or wrong IP version for this pass.")
			return nil
		}
		if expectedIPSets.Contains(setName) {
			s.logCxt.WithField("setName", setName).Debug("Skipping expected Calico IP set.")
			return nil
		}
		s.logCxt.WithField("setName", setName).Info(
			"Resync found left-over Calico IP set. Queueing deletion.")
		s.pendingIPSetDeletions.Add(setName)
		return nil
	})

	return
}

func (s *IPSets) tryUpdates() error {
	if s.dirtyIPSetIDs.Len() == 0 {
		s.logCxt.Debug("No dirty IP sets.")
		return nil
	}

	// Set up an ipset restore session.
	countNumIPSetCalls.Inc()
	cmd := exec.Command("ipset", "restore")
	rawStdin, err := cmd.StdinPipe()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to create pipe for ipset restore.")
		return err
	}
	stdin := bufio.NewWriterSize(rawStdin, 65536)
	var stdout, stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	// TODO(smc) Do something with the output.
	startTime := time.Now()
	cmd.Start()
	summaryExecStart.Observe(float64(time.Since(startTime).Nanoseconds()) / 1000.0)

	// Ask each dirty IP set to write its updates to the stream.
	s.dirtyIPSetIDs.Iter(func(item interface{}) error {
		ipSet := s.ipSetIDToIPSet[item.(string)]
		err = s.writeUpdates(ipSet, stdin)
		if err != nil {
			return set.StopIteration
		}
		return nil
	})
	if err == nil {
		// No error so far, finish off the input.
		_, err = stdin.Write([]byte("COMMIT\n"))
	}

	// Close the pipe, or the command will wait for more input.
	if err == nil {
		err = stdin.Flush()
	}
	closeErr := rawStdin.Close()
	if err == nil {
		err = closeErr
	}

	rcErr := cmd.Wait()
	logCxt := s.logCxt.WithFields(log.Fields{
		"stdout": stdout.String(),
		"stderr": stderr.String(),
		"rc":     rcErr,
	})

	if err != nil {
		logCxt.WithError(err).Error("Failed to write to ipset restore")
		return err
	}
	if rcErr != nil {
		logCxt.Error("Bad ipset restore return code")
		return rcErr
	}

	// If we get here, the writes were successful, reset the IP sets delta tracking now the
	// dataplane should be in sync.
	s.dirtyIPSetIDs.Iter(func(item interface{}) error {
		ipSet := s.ipSetIDToIPSet[item.(string)]
		if ipSet.pendingReplace != nil {
			ipSet.members = ipSet.pendingReplace
			ipSet.pendingReplace = nil

			// Doing a rewrite creates the main IP set and deletes the temp IP set.
			s.existingIPSetNames.Add(ipSet.MainIPSetName)
			s.existingIPSetNames.Discard(ipSet.TempIPSetName)
		} else {
			ipSet.pendingAdds.Iter(func(m interface{}) error {
				ipSet.members.Add(m)
				return set.RemoveItem
			})
			ipSet.pendingDeletions.Iter(func(m interface{}) error {
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
		return s.writeDeltas(ipSet, w)
	} else {
		// In full-rewrite mode.
		// - pendingReplace is non-nil
		// - membersInDataplane nil
		// - pendingAdds/Deletions empty.
		logCxt.Info("Doing full IP set rewrite")
		return s.writeFullRewrite(ipSet, w)
	}

	return nil
}

// writeFullRewrite calculates the ipset restore input required to do a full, atomic, idempotent
// rewrite of the IP set and writes it to the given io.Writer.
func (s *IPSets) writeFullRewrite(ipSet *ipSet, out io.Writer) (err error) {
	// writeLine until an error occurs, writeLine writes a line to the output, after an error,
	// it is a no-op.
	var inputCopy bytes.Buffer
	writeLine := func(format string, a ...interface{}) {
		if err != nil {
			return
		}
		line := fmt.Sprintf(format, a...) + "\n"
		s.logCxt.WithField("line", line).Debug("Writing line to ipset restore")
		lineBytes := []byte(line)
		inputCopy.Write(lineBytes)
		_, err = out.Write(lineBytes)
		if err != nil {
			s.logCxt.WithError(err).WithFields(log.Fields{
				"line":  lineBytes,
				"input": inputCopy.String(),
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
		s.logCxt.WithField("setID", ipSet.SetID).Debug("Pre-creating main IP set")
		writeLine("create %s %s family %s maxelem %d",
			mainSetName, ipSet.Type, s.IPVersionConfig.Family, ipSet.MaxSize)
	}
	tempSetName := ipSet.TempIPSetName
	if s.existingIPSetNames.Contains(tempSetName) {
		// Explicitly delete the temporary IP set so that we can recreate it with new
		// parameters.
		s.logCxt.WithField("setID", ipSet.SetID).Debug("Temp IP set exists, deleting it before rewrite")
		writeLine("destroy %s", tempSetName)
	}
	// Create the temporary IP set with the current parameters.
	writeLine("create %s %s family %s maxelem %d",
		tempSetName, ipSet.Type, s.IPVersionConfig.Family, ipSet.MaxSize)
	// Write all the members into the temporary IP set.
	ipSet.pendingReplace.Iter(func(item interface{}) error {
		member := item.(ipSetMember)
		writeLine("add %s %s", tempSetName, member)
		return nil
	})
	// Atomically swap the temporary set into place.
	writeLine("swap %s %s", mainSetName, tempSetName)
	// Then remove the temporary set (which was the old main set).
	writeLine("destroy %s", tempSetName)

	return
}

// writeDeltas calculates the ipset restore input required to apply the pending adds/deletes to the
// main IP set.
func (s *IPSets) writeDeltas(ipSet *ipSet, out io.Writer) (err error) {
	mainSetName := ipSet.MainIPSetName
	ipSet.pendingDeletions.Iter(func(item interface{}) error {
		member := item.(ipSetMember)
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
	ipSet.pendingAdds.Iter(func(item interface{}) error {
		member := item.(ipSetMember)
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
// Failures are ignored, deletions will be retried the next time AttemptCleanup() is called.
func (s *IPSets) ApplyDeletions() {
	s.pendingIPSetDeletions.Iter(func(item interface{}) error {
		setName := item.(string)
		logCxt := s.logCxt.WithField("setName", setName)
		logCxt.Info("Deleting IP set (if it exists)")
		if s.existingIPSetNames.Contains(setName) {
			if err := s.deleteIPSet(setName); err != nil {
				logCxt.WithError(err).Warning("Failed to delete IP set.")
			}
		}
		return set.RemoveItem
	})

	s.gaugeNumIpsets.Set(float64(len(s.ipSetIDToIPSet)))
}

func (s *IPSets) deleteIPSet(setName string) error {
	s.logCxt.WithField("setName", setName).Info("Deleting IP set.")
	cmd := s.newCmd("ipset", "destroy", string(setName))
	if output, err := cmd.CombinedOutput(); err != nil {
		s.logCxt.WithError(err).WithFields(log.Fields{
			"setName": setName,
			"output":  string(output),
		}).Warn("Failed to delete IP set, may be out-of-sync.")
		s.resyncRequired = true
		return err
	}
	// Success, update the cache.
	s.logCxt.WithField("setName", setName).Info("Deleted IP set")
	s.existingIPSetNames.Discard(setName)
	return nil
}

func (s *IPSets) dumpIPSetsToLog() {
	cmd := exec.Command("ipset", "save")
	output, err := cmd.Output()
	if err != nil {
		s.logCxt.WithError(err).Panic("Failed to read IP sets")
	}
	s.logCxt.WithField("output", string(output)).Debug("Current state of IP sets")
}
