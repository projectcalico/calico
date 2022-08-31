// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	extdataplane "github.com/projectcalico/calico/felix/dataplane/external"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type MockDataplane struct {
	sync.Mutex

	inSync                         bool
	ipSets                         map[string]set.Set[string]
	activePolicies                 map[proto.PolicyID]*proto.Policy
	activeUntrackedPolicies        set.Set[proto.PolicyID]
	activePreDNATPolicies          set.Set[proto.PolicyID]
	activeProfiles                 set.Set[proto.ProfileID]
	activeVTEPs                    map[string]proto.VXLANTunnelEndpointUpdate
	activeWireguardEndpoints       map[string]proto.WireguardEndpointUpdate
	activeWireguardV6Endpoints     map[string]proto.WireguardEndpointV6Update
	activeRoutes                   set.Set[proto.RouteUpdate]
	endpointToPolicyOrder          map[string][]TierInfo
	endpointToUntrackedPolicyOrder map[string][]TierInfo
	endpointToPreDNATPolicyOrder   map[string][]TierInfo
	endpointToAllPolicyIDs         map[string][]proto.PolicyID
	endpointToProfiles             map[string][]string
	serviceAccounts                map[proto.ServiceAccountID]*proto.ServiceAccountUpdate
	namespaces                     map[proto.NamespaceID]*proto.NamespaceUpdate
	config                         map[string]string
	numEvents                      int
	encapsulation                  proto.Encapsulation
}

func (d *MockDataplane) InSync() bool {
	d.Lock()
	defer d.Unlock()

	return d.inSync
}

func (d *MockDataplane) IPSets() map[string]set.Set[string] {
	d.Lock()
	defer d.Unlock()

	copy := map[string]set.Set[string]{}
	for k, v := range d.ipSets {
		copy[k] = v.Copy()
	}
	return copy
}

func (d *MockDataplane) ActivePolicies() set.Set[proto.PolicyID] {
	d.Lock()
	defer d.Unlock()

	policyIDs := set.New[proto.PolicyID]()
	for k := range d.activePolicies {
		policyIDs.Add(k)
	}

	return policyIDs
}

func (d *MockDataplane) ActivePolicy(k proto.PolicyID) *proto.Policy {
	d.Lock()
	defer d.Unlock()

	return d.activePolicies[k]
}

func (d *MockDataplane) ActiveUntrackedPolicies() set.Set[proto.PolicyID] {
	d.Lock()
	defer d.Unlock()

	return d.activeUntrackedPolicies.Copy()
}
func (d *MockDataplane) ActivePreDNATPolicies() set.Set[proto.PolicyID] {
	d.Lock()
	defer d.Unlock()

	return d.activePreDNATPolicies.Copy()
}
func (d *MockDataplane) ActiveProfiles() set.Set[proto.ProfileID] {
	d.Lock()
	defer d.Unlock()

	return d.activeProfiles.Copy()
}
func (d *MockDataplane) ActiveVTEPs() set.Set[proto.VXLANTunnelEndpointUpdate] {
	d.Lock()
	defer d.Unlock()

	cp := set.New[proto.VXLANTunnelEndpointUpdate]()
	for _, v := range d.activeVTEPs {
		cp.Add(v)
	}

	return cp
}
func (d *MockDataplane) ActiveWireguardEndpoints() set.Set[proto.WireguardEndpointUpdate] {
	d.Lock()
	defer d.Unlock()

	cp := set.New[proto.WireguardEndpointUpdate]()
	for _, v := range d.activeWireguardEndpoints {
		cp.Add(v)
	}

	return cp
}
func (d *MockDataplane) ActiveWireguardV6Endpoints() set.Set[proto.WireguardEndpointV6Update] {
	d.Lock()
	defer d.Unlock()

	cp := set.New[proto.WireguardEndpointV6Update]()
	for _, v := range d.activeWireguardV6Endpoints {
		cp.Add(v)
	}

	return cp
}
func (d *MockDataplane) ActiveRoutes() set.Set[proto.RouteUpdate] {
	d.Lock()
	defer d.Unlock()

	return d.activeRoutes.Copy()
}
func (d *MockDataplane) EndpointToProfiles() map[string][]string {
	d.Lock()
	defer d.Unlock()

	epToProfCopy := map[string][]string{}
	for k, v := range d.endpointToProfiles {
		profCopy := append([]string{}, v...)
		epToProfCopy[k] = profCopy
	}

	return epToProfCopy
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

func (d *MockDataplane) ServiceAccounts() map[proto.ServiceAccountID]*proto.ServiceAccountUpdate {
	d.Lock()
	defer d.Unlock()

	cpy := make(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate)
	for k, v := range d.serviceAccounts {
		cpy[k] = v
	}
	return cpy
}

func (d *MockDataplane) Namespaces() map[proto.NamespaceID]*proto.NamespaceUpdate {
	d.Lock()
	defer d.Unlock()

	cpy := make(map[proto.NamespaceID]*proto.NamespaceUpdate)
	for k, v := range d.namespaces {
		cpy[k] = v
	}
	return cpy
}

func (d *MockDataplane) NumEventsRecorded() int {
	d.Lock()
	defer d.Unlock()

	return d.numEvents
}

func (d *MockDataplane) Encapsulation() proto.Encapsulation {
	d.Lock()
	defer d.Unlock()

	return d.encapsulation
}

func copyPolOrder(in map[string][]TierInfo) map[string][]TierInfo {
	localCopy := map[string][]TierInfo{}
	for k, v := range in {
		if v == nil {
			localCopy[k] = nil
		}
		vCopy := make([]TierInfo, len(v))
		copy(vCopy, v)
		localCopy[k] = vCopy
	}
	return localCopy
}

func (d *MockDataplane) Config() map[string]string {
	d.Lock()
	defer d.Unlock()

	if d.config == nil {
		return nil
	}
	localCopy := map[string]string{}
	for k, v := range d.config {
		localCopy[k] = v
	}
	return localCopy
}

func NewMockDataplane() *MockDataplane {
	s := &MockDataplane{
		ipSets:                         make(map[string]set.Set[string]),
		activePolicies:                 map[proto.PolicyID]*proto.Policy{},
		activeProfiles:                 set.New[proto.ProfileID](),
		activeUntrackedPolicies:        set.New[proto.PolicyID](),
		activePreDNATPolicies:          set.New[proto.PolicyID](),
		activeRoutes:                   set.New[proto.RouteUpdate](),
		activeVTEPs:                    make(map[string]proto.VXLANTunnelEndpointUpdate),
		activeWireguardEndpoints:       make(map[string]proto.WireguardEndpointUpdate),
		activeWireguardV6Endpoints:     make(map[string]proto.WireguardEndpointV6Update),
		endpointToPolicyOrder:          make(map[string][]TierInfo),
		endpointToUntrackedPolicyOrder: make(map[string][]TierInfo),
		endpointToPreDNATPolicyOrder:   make(map[string][]TierInfo),
		endpointToProfiles:             make(map[string][]string),
		endpointToAllPolicyIDs:         make(map[string][]proto.PolicyID),
		serviceAccounts:                make(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate),
		namespaces:                     make(map[proto.NamespaceID]*proto.NamespaceUpdate),
	}
	return s
}

func (d *MockDataplane) OnEvent(event interface{}) {
	d.Lock()
	defer d.Unlock()

	d.numEvents++

	evType := reflect.TypeOf(event).String()
	fmt.Fprintf(GinkgoWriter, "       <- Event: %v %v\n", evType, event)
	Expect(event).NotTo(BeNil())
	Expect(reflect.TypeOf(event).Kind()).To(Equal(reflect.Ptr))

	// Test wrapping the message for the external dataplane
	switch event := event.(type) {
	case *calc.DatastoreNotReady:
	default:
		_, err := extdataplane.WrapPayloadWithEnvelope(event, 0)
		Expect(err).To(BeNil())
	}

	switch event := event.(type) {
	case *proto.InSync:
		d.inSync = true
	case *proto.IPSetUpdate:
		newMembers := set.New[string]()
		for _, ip := range event.Members {
			newMembers.Add(ip)
		}
		d.ipSets[event.Id] = newMembers
	case *proto.IPSetDeltaUpdate:
		members, ok := d.ipSets[event.Id]
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
		_, ok := d.ipSets[event.Id]
		if !ok {
			Fail(fmt.Sprintf("IP set remove for unknown ipset %v", event.Id))
			return
		}
		delete(d.ipSets, event.Id)
	case *proto.ActivePolicyUpdate:
		// TODO: check rules against expected rules
		policyID := *event.Id
		d.activePolicies[policyID] = event.Policy
		if event.Policy.Untracked {
			d.activeUntrackedPolicies.Add(policyID)
		} else {
			d.activeUntrackedPolicies.Discard(policyID)
		}
		if event.Policy.PreDnat {
			d.activePreDNATPolicies.Add(policyID)
		} else {
			d.activePreDNATPolicies.Discard(policyID)
		}
	case *proto.ActivePolicyRemove:
		policyID := *event.Id
		for ep, allPols := range d.endpointToAllPolicyIDs {
			Expect(allPols).NotTo(ContainElement(policyID),
				fmt.Sprintf("Policy %s removed while still in use by endpoint %s", policyID, ep))
		}
		delete(d.activePolicies, policyID)
		d.activeUntrackedPolicies.Discard(policyID)
		d.activePreDNATPolicies.Discard(policyID)
	case *proto.ActiveProfileUpdate:
		// TODO: check rules against expected rules
		d.activeProfiles.Add(*event.Id)
	case *proto.ActiveProfileRemove:
		for ep, profs := range d.endpointToProfiles {
			for _, p := range profs {
				if p == event.Id.Name {
					Fail(fmt.Sprintf("Profile %s removed while still in use by endpoint %s", p, ep))
				}
			}
		}
		d.activeProfiles.Discard(*event.Id)
	case *proto.WorkloadEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]TierInfo, len(tiers))
		var allPolsIDs []proto.PolicyID
		for i, tier := range event.Endpoint.Tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].IngressPolicyNames = tier.IngressPolicies
			tierInfos[i].EgressPolicyNames = tier.EgressPolicies

			// Check that all the policies referenced by the endpoint are already present, which
			// is one of the guarantees provided by the EventSequencer.
			var combinedPolNames []string
			combinedPolNames = append(combinedPolNames, tier.IngressPolicies...)
			combinedPolNames = append(combinedPolNames, tier.EgressPolicies...)
			for _, polName := range combinedPolNames {
				polID := proto.PolicyID{Tier: tier.Name, Name: polName}
				allPolsIDs = append(allPolsIDs, polID)
				Expect(d.activePolicies).To(HaveKey(polID),
					fmt.Sprintf("Expected policy %v referenced by workload endpoint "+
						"update %v to be active", polID, event))
			}
		}
		id := workloadId(*event.Id)
		d.endpointToPolicyOrder[id.String()] = tierInfos
		d.endpointToUntrackedPolicyOrder[id.String()] = []TierInfo{}
		d.endpointToPreDNATPolicyOrder[id.String()] = []TierInfo{}
		d.endpointToAllPolicyIDs[id.String()] = allPolsIDs

		// Check that all the profiles referenced by the endpoint are already present, which
		// is one of the guarantees provided by the EventSequencer.
		for _, profName := range event.Endpoint.ProfileIds {
			profID := proto.ProfileID{Name: profName}
			Expect(d.activeProfiles.Contains(profID)).To(BeTrue(),
				fmt.Sprintf("Expected profile %v referenced by workload endpoint "+
					"update %v to be active", profID, event))
		}
		d.endpointToProfiles[id.String()] = event.Endpoint.ProfileIds
	case *proto.WorkloadEndpointRemove:
		id := workloadId(*event.Id)
		delete(d.endpointToPolicyOrder, id.String())
		delete(d.endpointToUntrackedPolicyOrder, id.String())
		delete(d.endpointToPreDNATPolicyOrder, id.String())
		delete(d.endpointToProfiles, id.String())
		delete(d.endpointToAllPolicyIDs, id.String())
	case *proto.HostEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]TierInfo, len(tiers))
		for i, tier := range tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].IngressPolicyNames = tier.IngressPolicies
			tierInfos[i].EgressPolicyNames = tier.EgressPolicies
		}
		id := hostEpId(*event.Id)
		d.endpointToPolicyOrder[id.String()] = tierInfos

		uTiers := event.Endpoint.UntrackedTiers
		uTierInfos := make([]TierInfo, len(uTiers))
		for i, tier := range uTiers {
			uTierInfos[i].Name = tier.Name
			uTierInfos[i].IngressPolicyNames = tier.IngressPolicies
			uTierInfos[i].EgressPolicyNames = tier.EgressPolicies
		}
		d.endpointToUntrackedPolicyOrder[id.String()] = uTierInfos

		pTiers := event.Endpoint.PreDnatTiers
		pTierInfos := make([]TierInfo, len(pTiers))
		for i, tier := range pTiers {
			pTierInfos[i].Name = tier.Name
			pTierInfos[i].IngressPolicyNames = tier.IngressPolicies
			pTierInfos[i].EgressPolicyNames = tier.EgressPolicies
		}
		d.endpointToPreDNATPolicyOrder[id.String()] = pTierInfos
	case *proto.HostEndpointRemove:
		id := hostEpId(*event.Id)
		delete(d.endpointToPolicyOrder, id.String())
		delete(d.endpointToUntrackedPolicyOrder, id.String())
		delete(d.endpointToPreDNATPolicyOrder, id.String())
	case *proto.ServiceAccountUpdate:
		d.serviceAccounts[*event.Id] = event
	case *proto.ServiceAccountRemove:
		id := *event.Id
		Expect(d.serviceAccounts).To(HaveKey(id))
		delete(d.serviceAccounts, id)
	case *proto.NamespaceUpdate:
		d.namespaces[*event.Id] = event
	case *proto.NamespaceRemove:
		id := *event.Id
		Expect(d.namespaces).To(HaveKey(id))
		delete(d.namespaces, id)
	case *proto.RouteUpdate:
		d.activeRoutes.Iter(func(r proto.RouteUpdate) error {
			if event.Dst == r.Dst {
				return set.RemoveItem
			}
			return nil
		})
		d.activeRoutes.Add(*event)
	case *proto.RouteRemove:
		d.activeRoutes.Iter(func(r proto.RouteUpdate) error {
			if event.Dst == r.Dst {
				return set.RemoveItem
			}
			return nil
		})
	case *proto.VXLANTunnelEndpointUpdate:
		d.activeVTEPs[event.Node] = *event
	case *proto.VXLANTunnelEndpointRemove:
		Expect(d.activeVTEPs).To(HaveKey(event.Node), "delete for unknown VTEP")
		delete(d.activeVTEPs, event.Node)
	case *proto.WireguardEndpointUpdate:
		d.activeWireguardEndpoints[event.Hostname] = *event
	case *proto.WireguardEndpointRemove:
		Expect(d.activeWireguardEndpoints).To(HaveKey(event.Hostname), "delete for unknown IPv4 Wireguard Endpoint")
		delete(d.activeWireguardEndpoints, event.Hostname)
	case *proto.WireguardEndpointV6Update:
		d.activeWireguardV6Endpoints[event.Hostname] = *event
	case *proto.WireguardEndpointV6Remove:
		Expect(d.activeWireguardV6Endpoints).To(HaveKey(event.Hostname), "delete for unknown IPv6 Wireguard Endpoint")
		delete(d.activeWireguardV6Endpoints, event.Hostname)
	case *proto.Encapsulation:
		d.encapsulation = *event
	}
}

func (d *MockDataplane) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return
}

func (d *MockDataplane) RawValues() map[string]string {
	return d.Config()
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
