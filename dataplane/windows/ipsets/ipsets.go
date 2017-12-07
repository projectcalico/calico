//+build windows

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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/set"
)

// IPSets manages a whole plane of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type IPSets struct {
	IPVersionConfig *IPVersionConfig
	ipSetIDToIPSet  map[string]*ipSet
	logCxt          *log.Entry
}

func NewIPSets(ipVersionConfig *IPVersionConfig) *IPSets {
	return &IPSets{
		IPVersionConfig: ipVersionConfig,
		ipSetIDToIPSet:  map[string]*ipSet{},
		logCxt: log.WithFields(log.Fields{
			"family": ipVersionConfig.Family,
		}),
	}
}

// AddOrReplaceIPSet is responsible for the creation (or replacement) of an IP set in the store
func (s *IPSets) AddOrReplaceIPSet(setMetadata IPSetMetadata, members []string) {
	s.logCxt.WithFields(log.Fields{
		"setID":   setMetadata.SetID,
		"setType": setMetadata.Type,
	}).Info("Creating IP set")
	filteredMembers := s.filterMembers(members)

	// Create the IP set struct and stores it by id
	setID := setMetadata.SetID
	ipSet := &ipSet{
		IPSetMetadata: setMetadata,
		Members:       filteredMembers,
	}
	s.ipSetIDToIPSet[setID] = ipSet
}

// RemoveIPSet is responsible for the removal of an IP set from the store
func (s *IPSets) RemoveIPSet(setID string) {
	s.logCxt.WithField("setID", setID).Info("Removing IP set")
	delete(s.ipSetIDToIPSet, setID)
}

// AddMembers adds a range of new members to an existing IP set in the store
func (s *IPSets) AddMembers(setID string, newMembers []string) {
	if len(newMembers) == 0 {
		return
	}

	ipSet := s.ipSetIDToIPSet[setID]
	filteredMembers := s.filterMembers(newMembers)
	if filteredMembers.Len() == 0 {
		return
	}
	s.logCxt.WithFields(log.Fields{
		"setID":           setID,
		"filteredMembers": filteredMembers,
	}).Info("Adding new members to IP set")
	filteredMembers.Iter(func(m interface{}) error {
		ipSet.Members.Add(m)
		return nil
	})
}

// RemoveMembers removes a range of members from an existing IP set in the store
func (s *IPSets) RemoveMembers(setID string, removedMembers []string) {
	if len(removedMembers) == 0 {
		return
	}

	ipSet := s.ipSetIDToIPSet[setID]
	filteredMembers := s.filterMembers(removedMembers)
	if filteredMembers.Len() == 0 {
		return
	}
	s.logCxt.WithFields(log.Fields{
		"setID":           setID,
		"filteredMembers": filteredMembers,
	}).Info("Removing members from IP set")

	filteredMembers.Iter(func(m interface{}) error {
		ipSet.Members.Discard(m)
		return nil
	})
}

// GetIPSetMembers returns all of the members for a given IP set
func (s *IPSets) GetIPSetMembers(setID string) []string {
	var retVal []string

	ipSet := s.ipSetIDToIPSet[setID]
	if ipSet == nil {
		return nil
	}

	ipSet.Members.Iter(func(item interface{}) error {
		member := item.(string)
		retVal = append(retVal, member)
		return nil
	})

	return retVal
}

// filterMembers filters out any members which are not of the correct
// ip family for the IPSet
func (s *IPSets) filterMembers(members []string) set.Set {
	filtered := set.New()
	wantIPV6 := s.IPVersionConfig.Family == IPFamilyV6
	for _, member := range members {
		isIPV6 := strings.Index(member, ":") >= 0
		if wantIPV6 != isIPV6 {
			continue
		}
		filtered.Add(member)
	}
	return filtered
}
