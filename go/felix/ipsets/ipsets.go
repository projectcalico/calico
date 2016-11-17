// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"bytes"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/set"
	"os/exec"
	"strings"
	"time"
)

type IPSets struct {
	ipFamily IPFamily

	// desiredIPSets.
	activeIPSets          map[string]*IPSet
	dirtyIPSets           set.Set
	pendingIPSetDeletions set.Set

	existenceCache existenceCache
}

func NewIPSets(ipFamily IPFamily) *IPSets {
	return NewIPSetsWithOverrides(ipFamily, NewExistenceCache())
}

func NewIPSetsWithOverrides(ipFamily IPFamily, existenceCache existenceCache) *IPSets {
	return &IPSets{
		ipFamily:              ipFamily,
		activeIPSets:          map[string]*IPSet{},
		dirtyIPSets:           set.New(),
		pendingIPSetDeletions: set.New(),
		existenceCache:        existenceCache,
	}
}

func (s *IPSets) CreateOrReplaceIPSet(setMetadata IPSetMetadata, members []string) {
	members = s.filterMembersByIPVersion(members)
	ipSet := NewIPSet(setMetadata, s.existenceCache)
	ipSet.ReplaceMembers(members)
	s.activeIPSets[ipSet.SetID] = ipSet
	s.dirtyIPSets.Add(ipSet.SetID)
	s.pendingIPSetDeletions.Discard(ipSet.SetID)
}

func (s *IPSets) AddIPsToIPSet(setID string, newMembers []string) {
	newMembers = s.filterMembersByIPVersion(newMembers)
	s.activeIPSets[setID].AddMembers(newMembers)
	s.dirtyIPSets.Add(setID)
}

func (s *IPSets) RemoveIPsFromIPSet(setID string, removedMembers []string) {
	removedMembers = s.filterMembersByIPVersion(removedMembers)
	s.activeIPSets[setID].RemoveMembers(removedMembers)
	s.dirtyIPSets.Add(setID)
}

func (s *IPSets) filterMembersByIPVersion(members []string) []string {
	var filtered []string
	wantIPV6 := s.ipFamily == IPFamilyV6
	for _, member := range members {
		isIPV6 := strings.Index(member, ":") >= 0
		if wantIPV6 != isIPV6 {
			continue
		}
		filtered = append(filtered, member)
	}
	return filtered
}

func (s *IPSets) RemoveIPSet(setID string) {
	delete(s.activeIPSets, setID)
	s.dirtyIPSets.Discard(setID)
	s.pendingIPSetDeletions.Add(setID)
}

// ApplyUpdates flushes any updates (or creations) to the dataplane.
// Separate from ApplyDeletions to allow for proper sequencing with updates to iptables chains.
func (s *IPSets) ApplyUpdates() {
	s.dirtyIPSets.Iter(func(item interface{}) error {
		s.activeIPSets[item.(string)].Apply()
		return set.RemoveItem
	})
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time AttemptCleanup() is called.
func (s *IPSets) ApplyDeletions() {
	reloadCache := false
	s.pendingIPSetDeletions.Iter(func(item interface{}) error {
		setID := item.(string)
		log.WithField("setID", setID).Info("Deleting IP set (if it exists)")
		for _, setName := range []string{
			s.ipFamily.NameForMainIPSet(setID),
			s.ipFamily.NameForTempIPSet(setID),
		} {
			if s.existenceCache.Exists(setName) {
				cmd := exec.Command("ipset", "destroy", setName)
				if output, err := cmd.CombinedOutput(); err != nil {
					log.WithError(err).WithFields(log.Fields{
						"setID":   setID,
						"setName": setName,
						"output":  string(output),
					}).Warn("Failed to delete IP set, may be out-of-sync.")
					reloadCache = true
				} else {
					// Success, update the cache.
					log.WithField("setName", setName).Info("Deleted IP set")
					s.existenceCache.SetExists(setID, false)
				}
			}
		}
		return set.RemoveItem
	})
	if reloadCache {
		s.existenceCache.Reload()
	}
}

// AttemptCleanup() attempts to delete any left-over IP sets, either from a previous run of
// Felix, or from a failed deletion.
func (s *IPSets) AttemptCleanup() {
	// TODO(smc) Reload the existence cache.
	// TODO(smc) Resolve against desired IP sets.
	// TODO(smc) Attempt to delete any left-overs.
}

type IPSetType string

const (
	IPSetTypeHashIP IPSetType = "hash:ip"
)

type IPFamily string

func (f IPFamily) NameForTempIPSet(setID string) string {
	switch f {
	case IPFamilyV4:
		return combineAndTrunc("felix-4t", setID, 31)
	case IPFamilyV6:
		return combineAndTrunc("felix-6t", setID, 31)
	}
	log.WithField("family", f).Panic("Unknown family")
	return ""
}

func (f IPFamily) NameForMainIPSet(setID string) string {
	switch f {
	case IPFamilyV4:
		return combineAndTrunc("felix-4-", setID, 31)
	case IPFamilyV6:
		return combineAndTrunc("felix-6-", setID, 31)
	}
	log.WithField("family", f).Panic("Unknown family")
	return ""
}

const (
	IPFamilyV4 = "inet"
	IPFamilyV6 = "inet6"
)

type IPSetMetadata struct {
	SetID    string
	Type     IPSetType
	IPFamily IPFamily
	MaxSize  int
}

type IPSet struct {
	IPSetMetadata

	desiredMembers set.Set

	pendingAdds      set.Set
	pendingDeletions set.Set

	rewritePending bool

	existenceCache existenceCache
}

func NewIPSet(metadata IPSetMetadata, existenceCache existenceCache) *IPSet {
	return &IPSet{
		IPSetMetadata:    metadata,
		desiredMembers:   set.New(),
		pendingAdds:      set.New(),
		pendingDeletions: set.New(),
		rewritePending:   true,
		existenceCache:   existenceCache,
	}
}

func (s *IPSet) ReplaceMembers(newMembers []string) {
	s.desiredMembers = set.New()
	for _, m := range newMembers {
		s.desiredMembers.Add(m)
	}
	s.rewritePending = true
	s.pendingAdds = set.New()
	s.pendingDeletions = set.New()
}

func (s *IPSet) AddMembers(newMembers []string) {
	for _, m := range newMembers {
		s.desiredMembers.Add(m)
		if !s.rewritePending {
			s.pendingAdds.Add(m)
			s.pendingDeletions.Discard(m)
		}
	}
}

func (s *IPSet) RemoveMembers(removedMembers []string) {
	for _, m := range removedMembers {
		s.desiredMembers.Discard(m)
		if !s.rewritePending {
			s.pendingAdds.Discard(m)
			s.pendingDeletions.Add(m)
		}
	}
}

func (s *IPSet) Apply() {
	retries := 3
	for {
		if s.rewritePending {
			// We've been asked to rewrite the IP set from scratch.  We need to do this:
			// - at start of day
			// - after a failure
			// - whenever we change the parameters of the ipset.
			err := s.rewriteIPSet()
			if err != nil {
				if retries <= 0 {
					log.WithError(err).Fatal("Failed to rewrite ipset after retries, giving up")
				}
				log.WithError(err).Warn("Sleeping before retrying ipset rewrite")
				time.Sleep(100 * time.Millisecond)
				// Reload the existence cache in case we're out of sync.
				s.existenceCache.Reload()
				retries--
				continue
			}
			break
		} else {
			// IP set should already exist, just write deltas.
			err := s.flushDeltas()
			if err != nil {
				log.WithError(err).Warn("Failed to update IP set, attempting to rewrite it")
				continue
			}
			break
		}
	}
}

func (s *IPSet) flushDeltas() error {
	return errors.New("Not implemented") // Will force a full rewrite
}

// rewriteIPSet does a full, atomic, idempotent rewrite of the IP set.
func (s *IPSet) rewriteIPSet() error {
	logCxt := log.WithFields(log.Fields{
		"setID":      s.SetID,
		"numMembers": s.desiredMembers.Len()},
	)
	logCxt.Info("Rewriting IP Set")

	// Pre-calculate the commands to issue in a buffer.
	// TODO(smc) We could write the input directly to a pipe instead to save a bit of occupancy.
	var buf bytes.Buffer
	s.writeFullRewrite(&buf)
	if log.GetLevel() >= log.DebugLevel {
		logCxt.WithField("input", buf.String()).Debug("About to rewrite IP set")
	}

	// Execute the commands via the bulk "restore" sub-command.
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = &buf
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(output)).Warn("Failed to execute ipset restore")
		return err
	}

	// Success, we know the main set exists and the temp set has been deleted.
	logCxt.Info("Rewrote IP set")
	s.existenceCache.SetExists(s.MainIPSetName(), true)
	s.existenceCache.SetExists(s.TempIPSetName(), false)

	return nil
}

type stringWriter interface {
	WriteString(s string) (n int, err error)
}

// writeFullRewrite calculates the ipset restore input required to do a full, atomic, idempotent
// rewrite of the IP set and writes it to the given io.Writer.
func (s *IPSet) writeFullRewrite(buf stringWriter) {
	// Our general approach is to create a temporary IP set with the right contents, then
	// atomically swap it into place.
	mainSetName := s.MainIPSetName()
	if !s.existenceCache.Exists(mainSetName) {
		// Create empty main IP set so we can share the atomic swap logic below.
		// Note: we can't use the -exist flag (which should make the create idempotent)
		// because it still fails if the IP set was previously created with different
		// parameters.
		log.WithField("setID", s.SetID).Debug("Pre-creating main IP set")
		buf.WriteString(fmt.Sprintf("create %s %s family %s maxelem %d\n",
			mainSetName, s.Type, s.IPFamily, s.MaxSize))
	}
	tempSetName := s.TempIPSetName()
	if s.existenceCache.Exists(tempSetName) {
		// Explicitly delete the temporary IP set so that we can recreate it with new
		// parameters.
		log.WithField("setID", s.SetID).Debug("Temp IP set exists, deleting it before rewrite")
		buf.WriteString(fmt.Sprintf("destroy %s\n", tempSetName))
	}
	// Create the temporary IP set with the current parameters.
	buf.WriteString(fmt.Sprintf("create %s %s family %s maxelem %d\n", tempSetName, s.Type, s.IPFamily, s.MaxSize))
	// Write all the members into the temporary IP set.
	s.desiredMembers.Iter(func(item interface{}) error {
		member := item.(string)
		buf.WriteString(fmt.Sprintf("add %s %s\n", tempSetName, member))
		return nil
	})
	// Atomically swap the temporary set into place.
	buf.WriteString(fmt.Sprintf("swap %s %s\n", mainSetName, tempSetName))
	// Then remove the temporary set (which was the old main set).
	buf.WriteString(fmt.Sprintf("destroy %s\n", tempSetName))
	// ipset restore input ends with "COMMIT" (but only the swap instruction is guaranteed to be
	// atomic).
	buf.WriteString("COMMIT\n")
}

func (s *IPSet) DeleteTempIPSet() {
	cmd := exec.Command("ipset", "destroy", s.TempIPSetName())
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", output).Info(
			"Failed to delete temporary IP set, assuming it is not present")
	}
}

func (s *IPSet) TempIPSetName() string {
	return s.IPFamily.NameForTempIPSet(s.SetID)
}

func (s *IPSet) MainIPSetName() string {
	return s.IPFamily.NameForMainIPSet(s.SetID)
}

func combineAndTrunc(prefix, suffix string, maxLength int) string {
	combined := prefix + suffix
	if len(combined) > maxLength {
		return combined[0:maxLength]
	} else {
		return combined
	}
}

type existenceCache interface {
	Exists(setName string) bool
	SetExists(setName string, exists bool)
	Reload() error
}

type ExistenceCache struct {
	existingIPSetNames set.Set
}

func NewExistenceCache() *ExistenceCache {
	cache := &ExistenceCache{
		existingIPSetNames: set.New(),
	}
	cache.Reload()
	return cache
}

func (c *ExistenceCache) Reload() error {
	log.Info("Reloading IP set existence cache.")
	cmd := exec.Command("ipset", "list", "-n")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	setNames := set.New()
	buf := bytes.NewBuffer(output)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			break
		}
		setName := strings.Trim(line, "\n")
		log.WithField("setName", setName).Debug("Found IP set")
		setNames.Add(setName)
	}
	c.existingIPSetNames = setNames
	return nil
}

func (c *ExistenceCache) SetExists(setName string, exists bool) {
	if exists {
		c.existingIPSetNames.Add(setName)
	} else {
		c.existingIPSetNames.Discard(setName)
	}
}

func (c *ExistenceCache) Exists(setName string) bool {
	return c.existingIPSetNames.Contains(setName)
}
