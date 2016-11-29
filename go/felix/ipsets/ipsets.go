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
	"regexp"
	"strings"
	"time"
)

type IPSets struct {
	IPVersionConfig *IPVersionConfig

	// activeIPSets maps from IP set ID to the IPSet object managing that IP set.
	activeIPSets map[string]*IPSet
	// dirtyIPSets contains IDs of IP sets that need updating.
	dirtyIPSets set.Set
	// pendingIPSetDeletions contains IDs of IP sets that need to be deleted.
	pendingIPSetDeletions set.Set

	// existenceCache is a shared cache of the names (not IDs) of IP sets that currently exist.
	existenceCache existenceCache
}

func NewIPSets(ipVersionConfig *IPVersionConfig) *IPSets {
	return NewIPSetsWithOverrides(ipVersionConfig, NewExistenceCache())
}

func NewIPSetsWithOverrides(ipVersionConfig *IPVersionConfig, existenceCache existenceCache) *IPSets {
	return &IPSets{
		IPVersionConfig:       ipVersionConfig,
		activeIPSets:          map[string]*IPSet{},
		dirtyIPSets:           set.New(),
		pendingIPSetDeletions: set.New(),
		existenceCache:        existenceCache,
	}
}

func (s *IPSets) CreateOrReplaceIPSet(setMetadata IPSetMetadata, members []string) {
	members = s.filterMembersByIPVersion(members)
	ipSet := NewIPSet(s.IPVersionConfig, setMetadata, s.existenceCache)
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
	wantIPV6 := s.IPVersionConfig.Family == IPFamilyV6
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
			s.IPVersionConfig.NameForMainIPSet(setID),
			s.IPVersionConfig.NameForTempIPSet(setID),
		} {
			if s.existenceCache.Exists(setName) {
				if err := s.deleteIPSet(setName); err != nil {
					reloadCache = true
				}
			}
		}
		return set.RemoveItem
	})
	if reloadCache {
		log.Warn("An IP set delete operation failed, reloading existence cache.")
		s.existenceCache.Reload()
	}
}

func (s *IPSets) deleteIPSet(setName string) error {
	log.WithField("setName", setName).Info("Deleting IP set.")
	cmd := exec.Command("ipset", "destroy", string(setName))
	if output, err := cmd.CombinedOutput(); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"setName": setName,
			"output":  string(output),
		}).Warn("Failed to delete IP set, may be out-of-sync.")
		return err
	} else {
		// Success, update the cache.
		log.WithField("setName", setName).Info("Deleted IP set")
		s.existenceCache.SetExists(setName, false)
	}
	return nil
}

// AttemptCleanup() attempts to delete any left-over IP sets, either from a previous run of
// Felix, or from a failed deletion.
func (s *IPSets) AttemptCleanup() {
	// Find the names of all the IP sets that we expect to be there.
	expectedIPSets := set.New()
	for setID := range s.activeIPSets {
		mainName := s.IPVersionConfig.NameForMainIPSet(setID)
		expectedIPSets.Add(mainName)
		tempName := s.IPVersionConfig.NameForTempIPSet(setID)
		expectedIPSets.Add(tempName)
		log.WithFields(log.Fields{
			"ID":       setID,
			"mainName": mainName,
			"tempName": tempName,
		}).Debug("Whitelisting IP sets.")
	}
	// Include any pending deletions in the whitelist; this is mainly to separate cleanup logs
	// from explicit deletion logs.
	s.pendingIPSetDeletions.Iter(func(item interface{}) error {
		setID := item.(string)
		expectedIPSets.Add(s.IPVersionConfig.NameForMainIPSet(setID))
		expectedIPSets.Add(s.IPVersionConfig.NameForTempIPSet(setID))
		return nil
	})

	// Re-load the cache of IP sets that are present.
	if err := s.existenceCache.Reload(); err != nil {
		log.WithError(err).Error("Failed to load ipsets from dataplane, unable to do cleanup.")
		return
	}

	// Scan for IP sets that need to be cleaned up.
	s.existenceCache.Iter(func(setName string) {
		if !s.IPVersionConfig.OwnsIPSet(setName) {
			log.WithField("setName", setName).Debug(
				"Skipping IP set: non Calico or wrong IP version for this pass.")
			return
		}
		if expectedIPSets.Contains(setName) {
			log.WithField("setName", setName).Debug("Skipping expected Calico IP set.")
			return
		}
		log.WithField("setName", setName).Info("Removing left-over Calico IP set.")
		if err := s.deleteIPSet(setName); err != nil {
			log.WithError(err).Warn("Failed to delete IP set during cleanup. Is it still referenced?")
		}
	})
}

type IPSetType string

const (
	IPSetTypeHashIP IPSetType = "hash:ip"
)

type IPVersionConfig struct {
	Family                IPFamily
	setNamePrefix         string
	tempSetNamePrefix     string
	mainSetNamePrefix     string
	ourNamePrefixesRegexp *regexp.Regexp
}

func NewIPSetConfig(
	family IPFamily,
	namePrefix string,
	allHistoricPrefixes []string,
	extraUnversionedIPSets []string,
) *IPVersionConfig {
	var version string
	switch family {
	case IPFamilyV4:
		version = "4"
	case IPFamilyV6:
		version = "6"
	}
	versionedPrefix := namePrefix + version
	var versionedPrefixes []string
	for _, prefix := range allHistoricPrefixes {
		versionedPrefixes = append(versionedPrefixes, prefix+version)
	}
	versionedPrefixes = append(versionedPrefixes, extraUnversionedIPSets...)
	ourNamesPattern := "^(" + strings.Join(versionedPrefixes, "|") + ")"
	log.WithField("regexp", ourNamesPattern).Debug("Calculated IP set name regexp.")
	ourNamesRegexp := regexp.MustCompile(ourNamesPattern)

	return &IPVersionConfig{
		Family:                family,
		setNamePrefix:         versionedPrefix,
		tempSetNamePrefix:     versionedPrefix + "t", // Replace "-" so we maintain the same length.
		mainSetNamePrefix:     versionedPrefix + "-",
		ourNamePrefixesRegexp: ourNamesRegexp,
	}
}

func (c IPVersionConfig) NameForTempIPSet(setID string) string {
	// Replace main set's dash with a "t" so that we maintain the same length.
	return combineAndTrunc(c.tempSetNamePrefix, setID, 31)
}

func (c IPVersionConfig) NameForMainIPSet(setID string) string {
	return combineAndTrunc(c.mainSetNamePrefix, setID, 31)
}

func (c IPVersionConfig) OwnsIPSet(setName string) bool {
	return c.ourNamePrefixesRegexp.MatchString(setName)
}

type IPFamily string

const (
	IPFamilyV4 = IPFamily("inet")
	IPFamilyV6 = IPFamily("inet6")
)

type IPSetMetadata struct {
	SetID   string
	Type    IPSetType
	MaxSize int
}

type IPSet struct {
	IPSetMetadata

	IPVersionConfig *IPVersionConfig

	desiredMembers set.Set

	pendingAdds      set.Set
	pendingDeletions set.Set

	rewritePending bool

	existenceCache existenceCache
}

func NewIPSet(
	versionConfig *IPVersionConfig,
	metadata IPSetMetadata,
	existenceCache existenceCache,
) *IPSet {
	return &IPSet{
		IPVersionConfig:  versionConfig,
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
			mainSetName, s.Type, s.IPVersionConfig.Family, s.MaxSize))
	}
	tempSetName := s.TempIPSetName()
	if s.existenceCache.Exists(tempSetName) {
		// Explicitly delete the temporary IP set so that we can recreate it with new
		// parameters.
		log.WithField("setID", s.SetID).Debug("Temp IP set exists, deleting it before rewrite")
		buf.WriteString(fmt.Sprintf("destroy %s\n", tempSetName))
	}
	// Create the temporary IP set with the current parameters.
	buf.WriteString(fmt.Sprintf("create %s %s family %s maxelem %d\n",
		tempSetName, s.Type, s.IPVersionConfig.Family, s.MaxSize))
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
	cmd := exec.Command("ipset", "destroy", string(s.TempIPSetName()))
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", output).Info(
			"Failed to delete temporary IP set, assuming it is not present")
	}
}

func (s *IPSet) TempIPSetName() string {
	return s.IPVersionConfig.NameForTempIPSet(s.SetID)
}

func (s *IPSet) MainIPSetName() string {
	return s.IPVersionConfig.NameForMainIPSet(s.SetID)
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
	Iter(func(setName string))
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

func (c *ExistenceCache) Iter(f func(setName string)) {
	c.existingIPSetNames.Iter(func(item interface{}) error {
		f(item.(string))
		return nil
	})
}
