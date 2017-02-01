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

package intdataplane

import (
	"net"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/set"
)

type mockIPSets struct {
	Members            map[string]set.Set
	Metadata           map[string]ipsets.IPSetMetadata
	AddOrReplaceCalled bool
}

func newMockIPSets() *mockIPSets {
	return &mockIPSets{
		Members:  map[string]set.Set{},
		Metadata: map[string]ipsets.IPSetMetadata{},
	}
}

func (s *mockIPSets) AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, newMembers []string) {
	s.Metadata[setMetadata.SetID] = setMetadata
	members := set.New()
	for _, member := range newMembers {
		if setMetadata.Type == ipsets.IPSetTypeHashIP {
			Expect(net.ParseIP(member)).ToNot(BeNil())
		}
		members.Add(member)
	}
	s.Members[setMetadata.SetID] = members
	s.AddOrReplaceCalled = true
}
func (s *mockIPSets) AddMembers(setID string, newMembers []string) {
	members := s.Members[setID]
	for _, member := range newMembers {
		if s.Metadata[setID].Type == ipsets.IPSetTypeHashIP {
			Expect(net.ParseIP(member)).ToNot(BeNil())
		}
		Expect(members.Contains(member)).To(BeFalse())
		members.Add(member)
	}
}

func (s *mockIPSets) RemoveMembers(setID string, removedMembers []string) {
	members := s.Members[setID]
	for _, member := range removedMembers {
		if s.Metadata[setID].Type == ipsets.IPSetTypeHashIP {
			Expect(net.ParseIP(member)).ToNot(BeNil())
		}
		Expect(members.Contains(member)).To(BeTrue())
		members.Discard(member)
	}
}

func (s *mockIPSets) RemoveIPSet(setID string) {
	delete(s.Members, setID)
	delete(s.Metadata, setID)
}
