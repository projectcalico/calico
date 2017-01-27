// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/set"
	"regexp"
	"strings"
)

// A Registry manages the life-cycles of the IP sets for a particular IP version.  All IPSet
// objects should be created through a Registry so that the Registry is aware of the IPSet.
//
// We need the Registry in order to manage clean-up. The IPSets created through it are white-listed
// when cleaning up old IP sets.
type Registry struct {
	IPVersionConfig *IPVersionConfig

	// ipSetIDToActiveIPSet maps from IP set ID to the IPSet object managing that IP set.
	ipSetIDToActiveIPSet map[string]*IPSet
	// dirtyIPSetIDs contains IDs of IP sets that need updating.
	dirtyIPSetIDs set.Set
	// pendingIPSetDeletions contains IDs of IP sets that need to be deleted.
	pendingIPSetDeletions set.Set

	// existenceCache is a shared cache of the names (not IDs) of IP sets that currently exist.
	existenceCache existenceCache

	// Factory for command objects; shimmed for UT mocking.
	newCmd cmdFactory
}

func NewRegistry(ipVersionConfig *IPVersionConfig) *Registry {
	return NewRegistryWithShims(
		ipVersionConfig,
		NewExistenceCache(newRealCmd),
		newRealCmd,
	)
}

// newRegistryWithOverrides is an internal test constructor.
func NewRegistryWithShims(
	ipVersionConfig *IPVersionConfig,
	existenceCache existenceCache,
	cmdFactory cmdFactory,
) *Registry {
	return &Registry{
		IPVersionConfig:       ipVersionConfig,
		ipSetIDToActiveIPSet:  map[string]*IPSet{},
		dirtyIPSetIDs:         set.New(),
		pendingIPSetDeletions: set.New(),
		existenceCache:        existenceCache,
		newCmd:                cmdFactory,
	}
}

func (s *Registry) AddOrReplaceIPSet(setMetadata IPSetMetadata, members []string) {
	members = s.filterMembersByIPVersion(members)
	ipSet := NewIPSet(s.IPVersionConfig, setMetadata, s.existenceCache, s.newCmd)
	ipSet.ReplaceMembers(members)
	s.ipSetIDToActiveIPSet[ipSet.SetID] = ipSet
	s.dirtyIPSetIDs.Add(ipSet.SetID)
	s.pendingIPSetDeletions.Discard(ipSet.SetID)
}

func (s *Registry) AddMembers(setID string, newMembers []string) {
	newMembers = s.filterMembersByIPVersion(newMembers)
	s.ipSetIDToActiveIPSet[setID].AddMembers(newMembers)
	s.dirtyIPSetIDs.Add(setID)
}

func (s *Registry) RemoveMembers(setID string, removedMembers []string) {
	removedMembers = s.filterMembersByIPVersion(removedMembers)
	s.ipSetIDToActiveIPSet[setID].RemoveMembers(removedMembers)
	s.dirtyIPSetIDs.Add(setID)
}

func (s *Registry) filterMembersByIPVersion(members []string) []string {
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

func (s *Registry) RemoveIPSet(setID string) {
	delete(s.ipSetIDToActiveIPSet, setID)
	s.dirtyIPSetIDs.Discard(setID)
	s.pendingIPSetDeletions.Add(setID)
}

// ApplyUpdates flushes any updates (or creations) to the dataplane.
// Separate from ApplyDeletions to allow for proper sequencing with updates to iptables chains.
func (s *Registry) ApplyUpdates() {
	s.dirtyIPSetIDs.Iter(func(item interface{}) error {
		s.ipSetIDToActiveIPSet[item.(string)].Apply()
		return set.RemoveItem
	})
}

// ApplyDeletions tries to delete any IP sets that are no longer needed.
// Failures are ignored, deletions will be retried the next time AttemptCleanup() is called.
func (s *Registry) ApplyDeletions() {
	reloadCache := false
	s.pendingIPSetDeletions.Iter(func(item interface{}) error {
		setID := item.(string)
		log.WithField("setID", setID).Info("Deleting IP set (if it exists)")
		for _, setName := range []string{
			s.IPVersionConfig.NameForMainIPSet(setID),
			s.IPVersionConfig.NameForTempIPSet(setID),
		} {
			if s.existenceCache.IPSetExists(setName) {
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

func (s *Registry) deleteIPSet(setName string) error {
	log.WithField("setName", setName).Info("Deleting IP set.")
	cmd := s.newCmd("ipset", "destroy", string(setName))
	if output, err := cmd.CombinedOutput(); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"setName": setName,
			"output":  string(output),
		}).Warn("Failed to delete IP set, may be out-of-sync.")
		return err
	} else {
		// Success, update the cache.
		log.WithField("setName", setName).Info("Deleted IP set")
		s.existenceCache.SetIPSetExists(setName, false)
	}
	return nil
}

// AttemptCleanup() attempts to delete any left-over IP sets, either from a previous run of
// Felix, or from a failed deletion.
func (s *Registry) AttemptCleanup() {
	// Find the names of all the IP sets that we expect to be there.
	expectedIPSets := set.New()
	for setID := range s.ipSetIDToActiveIPSet {
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

// IPVersionConfig wraps up the metadata for a particular IP version.  It can be used by other
// this and other components to calculate IP set names from IP set IDs, for example.
type IPVersionConfig struct {
	Family                IPFamily
	setNamePrefix         string
	tempSetNamePrefix     string
	mainSetNamePrefix     string
	ourNamePrefixesRegexp *regexp.Regexp
}

func NewIPVersionConfig(
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
	versionedPrefixes = append(versionedPrefixes, namePrefix+version)
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

// NameForTempIPSet converts the given IP set ID (example: "qMt7iLlGDhvLnCjM0l9nzxbabcd"), to
// a name for use in the dataplane.  The return value will have the configured prefix and is
// guaranteed to be short enough to use as an ipset name (example:
// "cali6ts:qMt7iLlGDhvLnCjM0l9nzxb").
func (c IPVersionConfig) NameForTempIPSet(setID string) string {
	// Since IP set IDs are chosen with a secure hash already, we can simply truncate them
	/// to length to get maximum entropy.
	return combineAndTrunc(c.tempSetNamePrefix, setID, MaxIPSetNameLength)
}

// NameForMainIPSet converts the given IP set ID (example: "qMt7iLlGDhvLnCjM0l9nzxbabcd"), to
// a name for use in the dataplane.  The return value will have the configured prefix and is
// guaranteed to be short enough to use as an ipset name (example:
// "cali6ts:qMt7iLlGDhvLnCjM0l9nzxb").
func (c IPVersionConfig) NameForMainIPSet(setID string) string {
	// Since IP set IDs are chosen with a secure hash already, we can simply truncate them
	/// to length to get maximum entropy.
	return combineAndTrunc(c.mainSetNamePrefix, setID, MaxIPSetNameLength)
}

// OwnsIPSet returns true if the given IP set name appears to belong to Felix.  i.e. whether it
// starts with an expected prefix.
func (c IPVersionConfig) OwnsIPSet(setName string) bool {
	return c.ourNamePrefixesRegexp.MatchString(setName)
}

// combineAndTrunc concatenates the given prefix and suffix and truncates the result to maxLength.
func combineAndTrunc(prefix, suffix string, maxLength int) string {
	combined := prefix + suffix
	if len(combined) > maxLength {
		return combined[0:maxLength]
	} else {
		return combined
	}
}

// existenceCache is an interface for the ExistenceCache, used to allow the latter to be mocked.
type existenceCache interface {
	IPSetExists(setName string) bool
	SetIPSetExists(setName string, exists bool)
	Iter(func(setName string))
	Reload() error
}
