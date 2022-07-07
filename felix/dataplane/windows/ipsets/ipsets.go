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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type CallBackFunc func(ipSetId string)

// IPSets manages a whole plane of IP sets, i.e. all the IPv4 sets, or all the IPv6 IP sets.
type IPSets struct {
	IPVersionConfig  *IPVersionConfig
	ipSetIDToIPSet   map[string]*ipSet
	logCxt           *log.Entry
	callbackOnUpdate CallBackFunc
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

func (s *IPSets) SetCallback(callback CallBackFunc) {
	s.callbackOnUpdate = callback
}

// AddOrReplaceIPSet is responsible for the creation (or replacement) of an IP set in the store
func (s *IPSets) AddOrReplaceIPSet(setMetadata IPSetMetadata, members []string) {
	log.WithFields(log.Fields{
		"metadata":   setMetadata,
		"numMembers": len(members),
	}).Info("Adding IP set to cache")
	s.logCxt.WithFields(log.Fields{
		"setID":   setMetadata.SetID,
		"setType": setMetadata.Type,
	}).Info("Creating IP set")
	filteredMembers := s.filterMembers(members, setMetadata.Type)

	// Create the IP set struct and stores it by id
	setID := setMetadata.SetID
	ipSet := &ipSet{
		IPSetMetadata: setMetadata,
		Members:       filteredMembers,
	}
	s.ipSetIDToIPSet[setID] = ipSet
	s.callbackOnUpdate(setID)
}

// RemoveIPSet is responsible for the removal of an IP set from the store
func (s *IPSets) RemoveIPSet(setID string) {
	s.logCxt.WithField("setID", setID).Info("Removing IP set")
	delete(s.ipSetIDToIPSet, setID)
	s.callbackOnUpdate(setID)
}

// AddMembers adds a range of new members to an existing IP set in the store
func (s *IPSets) AddMembers(setID string, newMembers []string) {
	if len(newMembers) == 0 {
		return
	}

	ipSet := s.ipSetIDToIPSet[setID]
	filteredMembers := s.filterMembers(newMembers, ipSet.Type)
	if filteredMembers.Len() == 0 {
		return
	}
	s.logCxt.WithFields(log.Fields{
		"setID":           setID,
		"filteredMembers": filteredMembers,
	}).Debug("Adding new members to IP set")
	filteredMembers.Iter(func(m string) error {
		ipSet.Members.Add(m)
		return nil
	})
	s.callbackOnUpdate(setID)
}

// RemoveMembers removes a range of members from an existing IP set in the store
func (s *IPSets) RemoveMembers(setID string, removedMembers []string) {
	if len(removedMembers) == 0 {
		return
	}

	ipSet := s.ipSetIDToIPSet[setID]
	filteredMembers := s.filterMembers(removedMembers, ipSet.Type)
	if filteredMembers.Len() == 0 {
		return
	}
	s.logCxt.WithFields(log.Fields{
		"setID":           setID,
		"filteredMembers": filteredMembers,
	}).Debug("Removing members from IP set")

	filteredMembers.Iter(func(m string) error {
		ipSet.Members.Discard(m)
		return nil
	})
	s.callbackOnUpdate(setID)
}

// GetIPSetMembers returns all of the members for a given IP set
func (s *IPSets) GetIPSetMembers(setID string) []string {
	var retVal []string

	ipSet := s.ipSetIDToIPSet[setID]
	if ipSet == nil {
		return nil
	}

	ipSet.Members.Iter(func(member string) error {
		retVal = append(retVal, member)
		return nil
	})

	// Note: It is very important that nil is returned if there is no ip in an ipset
	// so that policy rules related to this ipset won't be populated.
	return retVal
}

// filterMembers filters out any members which are not of the correct
// ip family for the IPSet
func (s *IPSets) filterMembers(members []string, setType IPSetType) set.Set[string] {
	filtered := set.New[string]()
	wantIPV6 := s.IPVersionConfig.Family == IPFamilyV6

	// IPSet members can come in two forms: IP, or IP and port.
	// To determine the address family for an IP set member, we must first
	// determine which type of IP set this is.
	memberIsIPv6 := func(m string) bool {
		addr := m
		if setType == IPSetTypeHashIPPort {
			// IP+port - we need to split the address out to determine its family.
			// Split out address. Member format is addr,proto:port
			splits := strings.Split(m, ",")
			addr = splits[0]
		}
		return strings.Contains(addr, ":")
	}

	for _, member := range members {
		if wantIPV6 != memberIsIPv6(member) {
			continue
		}
		filtered.Add(member)
	}
	return filtered
}

func (s *IPSets) GetIPFamily() IPFamily {
	return s.IPVersionConfig.Family
}

// The following functions are no-ops on Windows.
func (s *IPSets) QueueResync() {
}

func (m *IPSets) GetTypeOf(setID string) (IPSetType, error) {
	panic("Not implemented")
}

func (m *IPSets) GetMembers(setID string) (set.Set[string], error) {
	// GetMembers is only called from XDPState, and XDPState does not coexist with
	// config.BPFEnabled.
	panic("Not implemented")
}

func (m *IPSets) ApplyUpdates() {
}

func (m *IPSets) ApplyDeletions() {
}

func (s *IPSets) SetFilter(ipSetNames set.Set[string]) {
	// Not needed for Windows.
}
