// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package mock

import (
	"fmt"
	"reflect"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type MockDataplane struct {
	sync.Mutex

	ipSets                         map[string]set.Set
	activePolicies                 set.Set
	activeUntrackedPolicies        set.Set
	activePreDNATPolicies          set.Set
	activeProfiles                 set.Set
	endpointToPolicyOrder          map[string][]TierInfo
	endpointToUntrackedPolicyOrder map[string][]TierInfo
	endpointToPreDNATPolicyOrder   map[string][]TierInfo
	config                         map[string]string
}

func (d *MockDataplane) IPSets() map[string]set.Set {
	d.Lock()
	defer d.Unlock()

	copy := map[string]set.Set{}
	for k, v := range d.ipSets {
		copy[k] = v.Copy()
	}
	return copy
}

func (d *MockDataplane) ActivePolicies() set.Set {
	d.Lock()
	defer d.Unlock()

	return d.activePolicies.Copy()
}
func (d *MockDataplane) ActiveUntrackedPolicies() set.Set {
	d.Lock()
	defer d.Unlock()

	return d.activeUntrackedPolicies.Copy()
}
func (d *MockDataplane) ActivePreDNATPolicies() set.Set {
	d.Lock()
	defer d.Unlock()

	return d.activePreDNATPolicies.Copy()
}
func (d *MockDataplane) ActiveProfiles() set.Set {
	d.Lock()
	defer d.Unlock()

	return d.activeProfiles.Copy()
}
func (d *MockDataplane) EndpointToPolicyOrder() map[string][]TierInfo {
	d.Lock()
	defer d.Unlock()

	return copyPolOrder(d.endpointToPolicyOrder)
}
func (d *MockDataplane) EndpointToUntrackedPolicyOrder() map[string][]TierInfo {
	d.Lock()
	defer d.Unlock()

	return copyPolOrder(d.endpointToUntrackedPolicyOrder)
}
func (d *MockDataplane) EndpointToPreDNATPolicyOrder() map[string][]TierInfo {
	d.Lock()
	defer d.Unlock()

	return copyPolOrder(d.endpointToPreDNATPolicyOrder)
}

func copyPolOrder(in map[string][]TierInfo) map[string][]TierInfo {
	copy := map[string][]TierInfo{}
	for k, v := range in {
		if v == nil {
			copy[k] = nil
		}
		vCopy := make([]TierInfo, len(v))
		for i := range v {
			vCopy[i] = v[i]
		}
		copy[k] = vCopy
	}
	return copy
}

func (d *MockDataplane) Config() map[string]string {
	d.Lock()
	defer d.Unlock()

	if d.config == nil {
		return nil
	}
	copy := map[string]string{}
	for k, v := range d.config {
		copy[k] = v
	}
	return copy
}

func NewMockDataplane() *MockDataplane {
	s := &MockDataplane{
		ipSets:                         make(map[string]set.Set),
		activePolicies:                 set.New(),
		activeProfiles:                 set.New(),
		activeUntrackedPolicies:        set.New(),
		activePreDNATPolicies:          set.New(),
		endpointToPolicyOrder:          make(map[string][]TierInfo),
		endpointToUntrackedPolicyOrder: make(map[string][]TierInfo),
		endpointToPreDNATPolicyOrder:   make(map[string][]TierInfo),
	}
	return s
}

func (s *MockDataplane) OnEvent(event interface{}) {
	s.Lock()
	defer s.Unlock()

	evType := reflect.TypeOf(event).String()
	fmt.Fprintf(GinkgoWriter, "       <- Event: %v %v\n", evType, event)
	Expect(event).NotTo(BeNil())
	Expect(reflect.TypeOf(event).Kind()).To(Equal(reflect.Ptr))
	switch event := event.(type) {
	case *proto.IPSetUpdate:
		newMembers := set.New()
		for _, ip := range event.Members {
			newMembers.Add(ip)
		}
		s.ipSets[event.Id] = newMembers
	case *proto.IPSetDeltaUpdate:
		members, ok := s.ipSets[event.Id]
		if !ok {
			Fail(fmt.Sprintf("IP set delta to missing ipset %v", event.Id))
			return
		}

		for _, ip := range event.AddedMembers {
			Expect(members.Contains(ip)).To(BeFalse(),
				fmt.Sprintf("IP Set %v already contained added IP %v",
					event.Id, ip))
			members.Add(ip)
		}
		for _, ip := range event.RemovedMembers {
			Expect(members.Contains(ip)).To(BeTrue(),
				fmt.Sprintf("IP Set %v did not contain removed IP %v",
					event.Id, ip))
			members.Discard(ip)
		}
	case *proto.IPSetRemove:
		_, ok := s.ipSets[event.Id]
		if !ok {
			Fail(fmt.Sprintf("IP set remove for unknown ipset %v", event.Id))
			return
		}
		delete(s.ipSets, event.Id)
	case *proto.ActivePolicyUpdate:
		// TODO: check rules against expected rules
		policyID := *event.Id
		s.activePolicies.Add(policyID)
		if event.Policy.Untracked {
			s.activeUntrackedPolicies.Add(policyID)
		} else {
			s.activeUntrackedPolicies.Discard(policyID)
		}
		if event.Policy.PreDnat {
			s.activePreDNATPolicies.Add(policyID)
		} else {
			s.activePreDNATPolicies.Discard(policyID)
		}
	case *proto.ActivePolicyRemove:
		policyID := *event.Id
		s.activePolicies.Discard(policyID)
		s.activeUntrackedPolicies.Discard(policyID)
		s.activePreDNATPolicies.Discard(policyID)
	case *proto.ActiveProfileUpdate:
		// TODO: check rules against expected rules
		s.activeProfiles.Add(*event.Id)
	case *proto.ActiveProfileRemove:
		s.activeProfiles.Discard(*event.Id)
	case *proto.WorkloadEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]TierInfo, len(tiers))
		for i, tier := range event.Endpoint.Tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].IngressPolicyNames = tier.IngressPolicies
			tierInfos[i].EgressPolicyNames = tier.EgressPolicies
		}
		id := workloadId(*event.Id)
		s.endpointToPolicyOrder[id.String()] = tierInfos
		s.endpointToUntrackedPolicyOrder[id.String()] = []TierInfo{}
		s.endpointToPreDNATPolicyOrder[id.String()] = []TierInfo{}
	case *proto.WorkloadEndpointRemove:
		id := workloadId(*event.Id)
		delete(s.endpointToPolicyOrder, id.String())
		delete(s.endpointToUntrackedPolicyOrder, id.String())
		delete(s.endpointToPreDNATPolicyOrder, id.String())
	case *proto.HostEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]TierInfo, len(tiers))
		for i, tier := range tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].IngressPolicyNames = tier.IngressPolicies
			tierInfos[i].EgressPolicyNames = tier.EgressPolicies
		}
		id := hostEpId(*event.Id)
		s.endpointToPolicyOrder[id.String()] = tierInfos

		uTiers := event.Endpoint.UntrackedTiers
		uTierInfos := make([]TierInfo, len(uTiers))
		for i, tier := range uTiers {
			uTierInfos[i].Name = tier.Name
			uTierInfos[i].IngressPolicyNames = tier.IngressPolicies
			uTierInfos[i].EgressPolicyNames = tier.EgressPolicies
		}
		s.endpointToUntrackedPolicyOrder[id.String()] = uTierInfos

		pTiers := event.Endpoint.PreDnatTiers
		pTierInfos := make([]TierInfo, len(pTiers))
		for i, tier := range pTiers {
			pTierInfos[i].Name = tier.Name
			pTierInfos[i].IngressPolicyNames = tier.IngressPolicies
			pTierInfos[i].EgressPolicyNames = tier.EgressPolicies
		}
		s.endpointToPreDNATPolicyOrder[id.String()] = pTierInfos
	case *proto.HostEndpointRemove:
		id := hostEpId(*event.Id)
		delete(s.endpointToPolicyOrder, id.String())
		delete(s.endpointToUntrackedPolicyOrder, id.String())
		delete(s.endpointToPreDNATPolicyOrder, id.String())
	}
}

func (s *MockDataplane) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return
}

func (s *MockDataplane) RawValues() map[string]string {
	return s.Config()
}

type TierInfo struct {
	Name               string
	IngressPolicyNames []string
	EgressPolicyNames  []string
}

type workloadId proto.WorkloadEndpointID

func (w *workloadId) String() string {
	return fmt.Sprintf("%v/%v/%v",
		w.OrchestratorId, w.WorkloadId, w.EndpointId)
}

type hostEpId proto.HostEndpointID

func (i *hostEpId) String() string {
	return i.EndpointId
}
