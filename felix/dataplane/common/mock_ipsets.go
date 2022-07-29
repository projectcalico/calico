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

package common

import (
	"net"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type MockIPSets struct {
	Members            map[string]set.Set[string]
	Metadata           map[string]ipsets.IPSetMetadata
	AddOrReplaceCalled bool
}

func NewMockIPSets() *MockIPSets {
	return &MockIPSets{
		Members:  map[string]set.Set[string]{},
		Metadata: map[string]ipsets.IPSetMetadata{},
	}
}

func (s *MockIPSets) AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, newMembers []string) {
	s.Metadata[setMetadata.SetID] = setMetadata
	members := set.New[string]()
	for _, member := range newMembers {
		if setMetadata.Type == ipsets.IPSetTypeHashIP {
			Expect(net.ParseIP(member)).ToNot(BeNil())
		}
		members.Add(member)
	}
	s.Members[setMetadata.SetID] = members
	s.AddOrReplaceCalled = true
}
func (s *MockIPSets) AddMembers(setID string, newMembers []string) {
	members := s.Members[setID]
	for _, member := range newMembers {
		if s.Metadata[setID].Type == ipsets.IPSetTypeHashIP {
			Expect(net.ParseIP(member)).ToNot(BeNil())
		}
		Expect(members.Contains(member)).To(BeFalse())
		members.Add(member)
	}
}

func (s *MockIPSets) RemoveMembers(setID string, removedMembers []string) {
	members := s.Members[setID]
	for _, member := range removedMembers {
		if s.Metadata[setID].Type == ipsets.IPSetTypeHashIP {
			Expect(net.ParseIP(member)).ToNot(BeNil())
		}
		Expect(members.Contains(member)).To(BeTrue())
		members.Discard(member)
	}
}

func (s *MockIPSets) RemoveIPSet(setID string) {
	delete(s.Members, setID)
	delete(s.Metadata, setID)
}

func (s *MockIPSets) GetIPFamily() ipsets.IPFamily {
	return ipsets.IPFamilyV4
}

func (s *MockIPSets) GetMembers(setID string) (set.Set[string], error) {
	return s.Members[setID], nil
}

func (s *MockIPSets) GetTypeOf(setID string) (ipsets.IPSetType, error) {
	return s.Metadata[setID].Type, nil
}

func (s *MockIPSets) QueueResync() {
	// Not implemented for UT.
}

func (s *MockIPSets) ApplyUpdates() {
	// Not implemented for UT.
}

func (s *MockIPSets) ApplyDeletions() {
	// Not implemented for UT.
}

func (s *MockIPSets) SetFilter(ipSetNames set.Set[string]) {
	// Not implemented for UT.
}
