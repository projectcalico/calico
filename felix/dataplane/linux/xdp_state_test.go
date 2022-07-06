// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"fmt"
	"reflect"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type mockIPSetValue struct {
	members   set.Set[string]
	ipsetType ipsets.IPSetType
}

type mockIPSetsSource struct {
	ipsetsMap map[string]mockIPSetValue
}

func (s *mockIPSetsSource) GetIPSetType(setID string) (ipsets.IPSetType, error) {
	return s.ipsetsMap[setID].ipsetType, nil
}

func (s *mockIPSetsSource) GetIPSetMembers(setID string) (set.Set[string], error) {
	return s.ipsetsMap[setID].members, nil
}

type mockEndpointsSource struct {
	rawHep map[proto.HostEndpointID]*proto.HostEndpoint
}

func (s *mockEndpointsSource) GetRawHostEndpoints() map[proto.HostEndpointID]*proto.HostEndpoint {
	return s.rawHep
}

func stateToBPFDataplane(state map[string]map[string]uint32, family bpf.IPFamily) bpf.BPFDataplane {
	lib := bpf.NewMockBPFLib("../../bpf-apache/bin")
	_, err := lib.NewFailsafeMap()
	Expect(err).NotTo(HaveOccurred())
	for iface, cidrMap := range state {
		mode := bpf.XDPDriver
		if strings.HasSuffix(iface, "_xdpgeneric") {
			mode = bpf.XDPGeneric
			iface = strings.TrimSuffix(iface, "_xdpgeneric")
		}
		_, err = lib.NewCIDRMap(iface, family)
		Expect(err).NotTo(HaveOccurred())
		err = lib.LoadXDPAuto(iface, mode)
		Expect(err).NotTo(HaveOccurred())
		for member, refCount := range cidrMap {
			ip, mask, err := bpf.MemberToIPMask(member)
			Expect(err).NotTo(HaveOccurred())

			err = lib.UpdateCIDRMap(iface, family, *ip, mask, refCount)
			Expect(err).NotTo(HaveOccurred())
		}
	}

	return lib
}

// knownProtoRuleFields lists the fields in the proto.Rule struct.
// If you add a new field, please check if isValidRuleForXDP() needs to be updated
var knownProtoRuleFields = set.From(
	"RuleId",
	"Protocol",
	"NotProtocol",
	"Icmp",
	"NotIcmp",
	"Action",
	"IpVersion",
	"DstNet",
	"DstPorts",
	"DstNamedPortIpSetIds",
	"DstIpSetIds",
	"NotDstNet",
	"NotDstPorts",
	"NotSrcIpSetIds",
	"NotDstIpSetIds",
	"NotSrcNamedPortIpSetIds",
	"NotDstNamedPortIpSetIds",
	"OriginalSrcSelector",
	"OriginalDstSelector",
	"OriginalSrcNamespaceSelector",
	"OriginalDstNamespaceSelector",
	"OriginalNotSrcSelector",
	"OriginalNotDstSelector",
	"OriginalSrcService",
	"OriginalSrcServiceNamespace",
	"OriginalDstService",
	"OriginalDstServiceNamespace",
	"DstServiceAccountMatch",
	"SrcNet",
	"SrcPorts",
	"SrcNamedPortIpSetIds",
	"NotSrcNet",
	"NotSrcPorts",
	"SrcIpSetIds",
	"SrcServiceAccountMatch",
	"HttpMatch",
	"Metadata",
	"DstIpPortSetIds",
)

func testAllProtoRuleFieldsAreKnown() {
	t := reflect.TypeOf(proto.Rule{})
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		Expect(knownProtoRuleFields.Contains(name)).To(BeTrue(), "It looks like that the field %s is a new addition to the proto.Rule struct. Please check if it affects XDP optimizations in any way, update the isValidRuleForXDP function and the \"invalid policies\" unit test if needed, and then add the name to the knownProtoRuleFields slice above. Please DO NOT blindly add the field to the slice without checking its influence on the XDP optimization.", name)
	}
}

type testCBEvent interface {
	Do(ipState *xdpIPState)
}

type updatePolicyType struct {
	policyID string
	inRules  []*proto.Rule
}

func (up *updatePolicyType) Do(ipState *xdpIPState) {
	policyID := proto.PolicyID{Tier: "default", Name: up.policyID}
	policy := &proto.Policy{InboundRules: up.inRules}
	ipState.updatePolicy(policyID, policy)
}

type removePolicyType struct {
	policyID string
}

func (rp *removePolicyType) Do(ipState *xdpIPState) {
	policyID := proto.PolicyID{Tier: "default", Name: rp.policyID}
	ipState.removePolicy(policyID)
}

type addMembersIPSetType struct {
	setID   string
	members set.Set[string]
}

func (am *addMembersIPSetType) Do(ipState *xdpIPState) {
	ipState.addMembersIPSet(am.setID, am.members)
}

type removeMembersIPSetType struct {
	setID   string
	members set.Set[string]
}

func (rm *removeMembersIPSetType) Do(ipState *xdpIPState) {
	ipState.removeMembersIPSet(rm.setID, rm.members)
}

type replaceIPSetType struct {
	setID   string
	members set.Set[string]
}

func (r *replaceIPSetType) Do(ipState *xdpIPState) {
	ipState.replaceIPSet(r.setID, r.members)
}

type removeIPSetType struct {
	setID string
}

func (r *removeIPSetType) Do(ipState *xdpIPState) {
	ipState.removeIPSet(r.setID)
}

type addInterfaceType struct {
	ifaceName  string
	endpointID string
}

func (ai *addInterfaceType) Do(ipState *xdpIPState) {
	ipState.addInterface(ai.ifaceName, proto.HostEndpointID{EndpointId: ai.endpointID})
}

type removeInterfaceType struct {
	ifaceName string
}

func (ri *removeInterfaceType) Do(ipState *xdpIPState) {
	ipState.removeInterface(ri.ifaceName)
}

type updateInterfaceType struct {
	ifaceName  string
	endpointID string
}

func (ui *updateInterfaceType) Do(ipState *xdpIPState) {
	ipState.updateInterface(ui.ifaceName, proto.HostEndpointID{EndpointId: ui.endpointID})
}

type updateHostEndpointType struct {
	endpointID string
}

func (uh *updateHostEndpointType) Do(ipState *xdpIPState) {
	ipState.updateHostEndpoint(proto.HostEndpointID{EndpointId: uh.endpointID})
}

type removeHostEndpointType struct {
	endpointID string
}

func (rh *removeHostEndpointType) Do(ipState *xdpIPState) {
	ipState.removeHostEndpoint(proto.HostEndpointID{EndpointId: rh.endpointID})
}

var _ testCBEvent = &updatePolicyType{}

func denyRule(setIDs ...string) *proto.Rule {
	return customRule(nil, "deny", 4, setIDs...)
}

func allowRule(setIDs ...string) *proto.Rule {
	return customRule(nil, "allow", 4, setIDs...)
}

func customRule(protocol *string, action string, ipVersion int, setIDs ...string) *proto.Rule {
	ipVersion32 := int32(ipVersion)
	if _, ok := proto.IPVersion_name[ipVersion32]; !ok {
		versions := make([]int32, 0, len(proto.IPVersion_name))
		for version := range proto.IPVersion_name {
			versions = append(versions, version)
		}
		panic(fmt.Sprintf("The ip version needs to be one of %v, fix your test please", versions))
	}
	var protoProtocol *proto.Protocol = nil
	if protocol != nil {
		protoProtocol = &proto.Protocol{
			NumberOrName: &proto.Protocol_Name{
				Name: *protocol,
			},
		}
	}
	return &proto.Rule{
		Action:      action,
		Protocol:    protoProtocol,
		IpVersion:   proto.IPVersion(ipVersion32),
		SrcIpSetIds: setIDs,
	}
}

func stringPtr(str string) *string {
	return &str
}

func updatePolicy(policyID string, rules ...*proto.Rule) testCBEvent {
	return &updatePolicyType{
		policyID: policyID,
		inRules:  rules,
	}
}

var _ testCBEvent = &removePolicyType{}

func removePolicy(policyID string) testCBEvent {
	return &removePolicyType{
		policyID: policyID,
	}
}

var _ testCBEvent = &addMembersIPSetType{}

func addMembersIPSet(setID string, members ...string) testCBEvent {
	return &addMembersIPSetType{
		setID:   setID,
		members: set.FromArray(members),
	}
}

var _ testCBEvent = &removeMembersIPSetType{}

func removeMembersIPSet(setID string, members ...string) testCBEvent {
	return &removeMembersIPSetType{
		setID:   setID,
		members: set.FromArray(members),
	}
}

var _ testCBEvent = &replaceIPSetType{}

func replaceIPSet(setID string, members ...string) testCBEvent {
	return &replaceIPSetType{
		setID:   setID,
		members: set.FromArray(members),
	}
}

var _ testCBEvent = &removeIPSetType{}

func removeIPSet(setID string) testCBEvent {
	return &removeIPSetType{
		setID: setID,
	}
}

var _ testCBEvent = &addInterfaceType{}

func addInterface(ifaceName, endpointID string) testCBEvent {
	return &addInterfaceType{
		ifaceName:  ifaceName,
		endpointID: endpointID,
	}
}

var _ testCBEvent = &removeInterfaceType{}

func removeInterface(ifaceName string) testCBEvent {
	return &removeInterfaceType{
		ifaceName: ifaceName,
	}
}

var _ testCBEvent = &updateInterfaceType{}

func updateInterface(ifaceName, endpointID string) testCBEvent {
	return &updateInterfaceType{
		ifaceName:  ifaceName,
		endpointID: endpointID,
	}
}

var _ testCBEvent = &updateHostEndpointType{}

func updateHostEndpoint(endpointID string) testCBEvent {
	return &updateHostEndpointType{
		endpointID: endpointID,
	}
}

var _ testCBEvent = &removeHostEndpointType{}

func removeHostEndpoint(endpointID string) testCBEvent {
	return &removeHostEndpointType{
		endpointID: endpointID,
	}
}

type testIfaceData struct {
	epID           string
	policiesToSets map[string][]string
}

func testStateToRealState(testIfaces map[string]testIfaceData, testEligiblePolicies map[string][][]string, realState *xdpSystemState) {
	for ifaceName, ifaceData := range testIfaces {
		policiesToSetIDs := make(map[proto.PolicyID]set.Set[string], len(ifaceData.policiesToSets))
		for policyID, setIDs := range ifaceData.policiesToSets {
			protoID := proto.PolicyID{Tier: "default", Name: policyID}
			setIDsSet := set.FromArray(setIDs)
			policiesToSetIDs[protoID] = setIDsSet
		}
		realState.IfaceNameToData[ifaceName] = xdpIfaceData{
			EpID:             proto.HostEndpointID{EndpointId: ifaceData.epID},
			PoliciesToSetIDs: policiesToSetIDs,
		}
	}
	for policyID, testRules := range testEligiblePolicies {
		protoID := proto.PolicyID{Tier: "default", Name: policyID}
		rules := make([]xdpRule, 0, len(testRules))
		for _, setIDs := range testRules {
			rules = append(rules, xdpRule{
				SetIDs: setIDs,
			})
		}
		realState.XDPEligiblePolicies[protoID] = xdpRules{
			Rules: rules,
		}
	}
}

func bpfDataplaneDump(st bpf.BPFDataplane, family bpf.IPFamily) map[string]map[string]uint32 {
	ifaces, err := st.GetXDPIfaces()
	Expect(err).NotTo(HaveOccurred())

	actual := make(map[string]map[string]uint32)
	for _, ifName := range ifaces {
		rawCidrMap, err := st.DumpCIDRMap(ifName, family)
		Expect(err).NotTo(HaveOccurred())
		cidrMap := make(map[string]uint32)
		for k, v := range rawCidrMap {
			cidrMap[k.ToIPNet().String()] = v
		}

		actual[ifName] = cidrMap
	}
	return actual
}

var _ = Describe("XDP state", func() {
	It("should take into account all relevant fields of proto.Rule", func() {
		testAllProtoRuleFieldsAreKnown()
	})

	Context("XDP state logic", func() {
		Context("processPendingDiffState", func() {
			type bpfActions struct {
				createMap     set.Set[string]
				removeMap     set.Set[string]
				addToMap      map[string]map[string]uint32
				removeFromMap map[string]map[string]uint32
				installXDP    set.Set[string]
				uninstallXDP  set.Set[string]
			}

			type testStruct struct {
				currentState        map[string]testIfaceData
				eligiblePolicies    map[string][][]string
				endpoints           map[string][]string
				events              []testCBEvent
				actions             *bpfActions
				newCurrentState     map[string]testIfaceData
				newEligiblePolicies map[string][][]string
			}

			DescribeTable("",
				func(s testStruct) {
					state := NewXDPStateWithBPFLibrary(bpf.NewMockBPFLib("../../bpf-apache/bin"), true)
					ipState := state.ipV4State
					cs := ipState.currentState
					expectedNcs := newXDPSystemState()
					testStateToRealState(s.currentState, s.eligiblePolicies, cs)
					testStateToRealState(s.newCurrentState, s.newEligiblePolicies, expectedNcs)
					rawHep := make(map[proto.HostEndpointID]*proto.HostEndpoint, len(s.endpoints))
					for epID, policyIDs := range s.endpoints {
						protoEpID := proto.HostEndpointID{
							EndpointId: epID,
						}
						protoEndpoint := &proto.HostEndpoint{
							Name: "default." + epID,
							UntrackedTiers: []*proto.TierInfo{
								{
									Name:            "default",
									IngressPolicies: policyIDs,
								},
							},
						}
						rawHep[protoEpID] = protoEndpoint
					}
					epSrc := &mockEndpointsSource{rawHep: rawHep}
					for _, event := range s.events {
						event.Do(ipState)
					}
					ipState.processPendingDiffState(epSrc)
					if s.actions == nil {
						s.actions = &bpfActions{}
					}
					if s.actions.createMap == nil {
						s.actions.createMap = set.New[string]()
					}
					if s.actions.removeMap == nil {
						s.actions.removeMap = set.New[string]()
					}
					if s.actions.addToMap == nil {
						s.actions.addToMap = make(map[string]map[string]uint32)
					}
					if s.actions.removeFromMap == nil {
						s.actions.removeFromMap = make(map[string]map[string]uint32)
					}
					if s.actions.installXDP == nil {
						s.actions.installXDP = set.New[string]()
					}
					if s.actions.uninstallXDP == nil {
						s.actions.uninstallXDP = set.New[string]()
					}
					ba := ipState.bpfActions
					ncs := ipState.newCurrentState
					Expect(ba.CreateMap).To(Equal(s.actions.createMap))
					Expect(ba.RemoveMap).To(Equal(s.actions.removeMap))
					Expect(ba.AddToMap).To(Equal(s.actions.addToMap))
					Expect(ba.RemoveFromMap).To(Equal(s.actions.removeFromMap))
					Expect(ba.InstallXDP).To(Equal(s.actions.installXDP))
					Expect(ba.UninstallXDP).To(Equal(s.actions.uninstallXDP))
					Expect(ba.MembersToDrop).To(Equal(make(map[string]map[string]uint32)))
					Expect(ba.MembersToAdd).To(Equal(make(map[string]map[string]uint32)))
					Expect(ncs).To(Equal(expectedNcs))
				},
				Entry("XDP program gets installed on an interface", testStruct{
					// nothing in current state
					// no eligible policies
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updatePolicy("policy", denyRule("ipset")),
						addInterface("iface", "ep"),
					},
					actions: &bpfActions{
						createMap: set.From("iface"),
						addToMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
						installXDP: set.From("iface"),
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("nothing gets installed on an interface if policy is not optimizable", testStruct{
					// nothing in current state
					// no eligible policies
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updatePolicy("policy", allowRule("ipset")),
						addInterface("iface", "ep"),
					},
					// no actions
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							// no policies
						},
					},
					// no new eligible policies
				}),
				Entry("XDP stuff gets dropped from interface when policy becomes invalid", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updatePolicy("policy", denyRule()),
					},
					actions: &bpfActions{
						removeMap:    set.From("iface"),
						uninstallXDP: set.From("iface"),
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							// no policies
						},
					},
					// no new eligible policies
				}),
				Entry("XDP stuff gets dropped from interface when last policy is dropped", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {},
					},
					events: []testCBEvent{
						updateHostEndpoint("ep"),
						removePolicy("policy"),
					},
					actions: &bpfActions{
						removeMap:    set.From("iface"),
						uninstallXDP: set.From("iface"),
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							// no policies
						},
					},
					// no new eligible policies
				}),
				Entry("XDP stuff gets dropped from interface when active interface disappears", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {},
					},
					events: []testCBEvent{
						removeInterface("iface"),
					},
					actions: &bpfActions{
						removeMap:    set.From("iface"),
						uninstallXDP: set.From("iface"),
					},
					// nothing in current state
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("XDP program gets installed on an interface when policy becomes optimizable again", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							// no policies
						},
					},
					// no eligible policies
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updatePolicy("policy", denyRule("ipset")),
					},
					actions: &bpfActions{
						createMap: set.From("iface"),
						addToMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
						installXDP: set.From("iface"),
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("XDP program gets installed on an interface when it changes to use host endpoint with optimizable policy", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							// no policies
						},
					},
					// no eligible policies
					endpoints: map[string][]string{
						"ep":  {"policy"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						updatePolicy("policy2", denyRule("ipset2")),
						updateInterface("iface", "ep2"),
					},
					actions: &bpfActions{
						createMap: set.From("iface"),
						addToMap: map[string]map[string]uint32{
							"iface": {"ipset2": 1},
						},
						installXDP: set.From("iface"),
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("XDP program gets uninstalled on an interface when it changes to use host endpoint with unoptimizable policy", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy2": {{"ipset2"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						updatePolicy("policy2", denyRule("ipset2")),
						updateInterface("iface", "ep"),
					},
					actions: &bpfActions{
						removeMap:    set.From("iface"),
						uninstallXDP: set.From("iface"),
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							// no policies
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("contents of the BPF map changes if the interface changes the host endpoint", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						updateInterface("iface", "ep2"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							"iface": {"ipset2": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("contents of the BPF map changes if the host endpoint of the interface changes", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy2"},
					},
					events: []testCBEvent{
						updateHostEndpoint("ep"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							"iface": {"ipset2": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("contents of the BPF map changes if the policy changes, but is still optimizable", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updatePolicy("policy", denyRule("ipset2")),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							"iface": {"ipset2": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset2"}},
					},
				}),
				Entry("interface is processed once (host endpoint update on processed interface is ignored)", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						// this is to have ep2 in the current state,
						// so update of the host endpoint ep2 is
						// not ignored in callbacks
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						updateInterface("iface", "ep2"),
						updateHostEndpoint("ep2"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							// were the interface processed twice, ref count would be 2
							"iface": {"ipset2": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("interface is processed once (policy update on processed interface is ignored)", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy2"},
					},
					events: []testCBEvent{
						updatePolicy("policy2", denyRule("ipset2")),
						updateHostEndpoint("ep"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							// were the interface processed twice, ref count would be 2
							"iface": {"ipset2": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("unrelated interfaces are unchanged on host endpoint update", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
						"policy3": {{"ipset3"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy3"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						updateHostEndpoint("ep"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							"iface": {"ipset3": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface": {"ipset": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy3": {"ipset3"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
						"policy3": {{"ipset3"}},
					},
				}),
				Entry("all related interfaces are processed on host endpoint update", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
						"iface3": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
						"policy3": {{"ipset3"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy3"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						updateHostEndpoint("ep"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							"iface":  {"ipset3": 1},
							"iface3": {"ipset3": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface":  {"ipset": 1},
							"iface3": {"ipset": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy3": {"ipset3"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
						"iface3": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy3": {"ipset3"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
						"policy3": {{"ipset3"}},
					},
				}),
				Entry("nothing changes in the BPF stuff if nothing actually changes in the policy", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updatePolicy("policy", denyRule("ipset")),
					},
					// no actions
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("nothing changes in the BPF stuff if nothing actually changes in the host endpoint", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updateHostEndpoint("ep"),
					},
					// no actions
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("nothing changes in the BPF stuff if nothing actually changes in the network interface", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updateInterface("iface", "ep"),
					},
					// no actions
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("nothing changes in the BPF stuff we get unrelated policy change", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						updatePolicy("policy2", allowRule("ipset2")),
					},
					// no actions
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("nothing changes in the BPF stuff we get unrelated host endpoint", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						updateHostEndpoint("ep2"),
					},
					// no actions
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset"}},
					},
				}),
				Entry("nothing changes in the BPF stuff we get ipset member changes", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy"},
						"ep2": {"policy2"},
					},
					events: []testCBEvent{
						addMembersIPSet("ipset", "member1"),
						removeMembersIPSet("ipset", "member2"),
						replaceIPSet("ipset2", "member21"),
						// this is quite artificial, because removing
						// an ipset would be acompanied with events
						// about policy being updated or dropped,
						// so there would be no mentions of the removed
						// ipset anywhere
						removeIPSet("ipset2"),
					},
					// no actions
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("host endpoint update and deletion are handled properly", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
					endpoints: map[string][]string{
						"ep": {"policy"},
					},
					events: []testCBEvent{
						removeHostEndpoint("ep"),
						updateHostEndpoint("ep"),
						updateHostEndpoint("ep2"),
						updateInterface("iface2", "ep"),
						removeHostEndpoint("ep2"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							"iface2": {"ipset": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface2": {"ipset2": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"iface2": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
				}),
				Entry("policy update and deletion are handled properly", testStruct{
					currentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy2": {"ipset2"},
							},
						},
					},
					eligiblePolicies: map[string][][]string{
						"policy":  {{"ipset"}},
						"policy2": {{"ipset2"}},
					},
					endpoints: map[string][]string{
						"ep":  {"policy"},
						"ep2": {"policy"},
					},
					events: []testCBEvent{
						removePolicy("policy"),
						updatePolicy("policy", denyRule("ipset3")),
						updatePolicy("policy2", denyRule("ipset4")),
						updateHostEndpoint("ep2"),
						removePolicy("policy2"),
					},
					actions: &bpfActions{
						addToMap: map[string]map[string]uint32{
							"iface":  {"ipset3": 1},
							"iface2": {"ipset3": 1},
						},
						removeFromMap: map[string]map[string]uint32{
							"iface":  {"ipset": 1},
							"iface2": {"ipset2": 1},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset3"},
							},
						},
						"iface2": {
							epID: "ep2",
							policiesToSets: map[string][]string{
								"policy": {"ipset3"},
							},
						},
					},
					newEligiblePolicies: map[string][][]string{
						"policy": {{"ipset3"}},
					},
				}),
				// TODO: That's not really possible - we support only one policy in host endpoint
				// Entry("ipset gets dropped from bpf map when policy becomes unoptimizable", testStruct{
				//	currentState: map[string]testIfaceData{
				//		"iface": testIfaceData{
				//			epID: "ep",
				//			policiesToSets: map[string][]string{
				//				"policy":  []string{"ipset"},
				//				"policy2": []string{"ipset2"},
				//			},
				//		},
				//	},
				//	eligiblePolicies: map[string][][]string{
				//		"policy":  [][]string{[]string{"ipset"}},
				//		"policy2": [][]string{[]string{"ipset2"}},
				//	},
				//	endpoints: map[string][]string{
				//		"ep": []string{"policy", "policy2"},
				//	},
				//	events: []testCBEvent{
				//		updatePolicy("policy2", allowRule("ipset2")),
				//	},
				//	actions: &bpfActions{
				//		removeFromMap: map[string]map[string]uint32{
				//			"iface": map[string]uint32{"ipset2": 1},
				//		},
				//	},
				//	newCurrentState: map[string]testIfaceData{
				//		"iface": testIfaceData{
				//			epID: "ep",
				//			policiesToSets: map[string][]string{
				//				"policy": []string{"ipset"},
				//			},
				//		},
				//	},
				//	newEligiblePolicies: map[string][][]string{
				//		"policy": [][]string{[]string{"ipset"}},
				//	},
				// }),
				// TODO: uncomment it when we support optimization of more than one policy in the host endpoint
				// Entry("ipset gets added to bpf map when policy becomes optimizable", testStruct{
				//	currentState: map[string]testIfaceData{
				//		"iface": testIfaceData{
				//			epID: "ep",
				//			policiesToSets: map[string][]string{
				//				"policy": []string{"ipset"},
				//			},
				//		},
				//	},
				//	eligiblePolicies: map[string][][]string{
				//		"policy": [][]string{[]string{"ipset"}},
				//	},
				//	endpoints: map[string][]string{
				//		"ep": []string{"policy", "policy2"},
				//	},
				//	events: []testCBEvent{
				//		updatePolicy("policy2", denyRule("ipset2")),
				//	},
				//	actions: &bpfActions{
				//		addToMap: map[string]map[string]uint32{
				//			"iface": map[string]uint32{"ipset2": 1},
				//		},
				//	},
				//	newCurrentState: map[string]testIfaceData{
				//		"iface": testIfaceData{
				//			epID: "ep",
				//			policiesToSets: map[string][]string{
				//				"policy":  []string{"ipset"},
				//				"policy2": []string{"ipset2"},
				//			},
				//		},
				//	},
				//	newEligiblePolicies: map[string][][]string{
				//		"policy":  [][]string{[]string{"ipset"}},
				//		"policy2": [][]string{[]string{"ipset2"}},
				//	},
				// }),
				Entry("invalid policies", func() testStruct {
					modifiedRule := func(field string, value interface{}) *proto.Rule {
						rule := denyRule("ipset")
						rulePtrValue := reflect.ValueOf(rule)
						ruleValue := rulePtrValue.Elem()
						fieldValue := ruleValue.FieldByName(field)
						fieldType := fieldValue.Type()
						valueValue := reflect.ValueOf(value)
						valueType := valueValue.Type()
						if !valueType.AssignableTo(fieldType) {
							panic(fmt.Sprintf("modifying proto.Rule field %s of type %s with a value %v of type %s, fix your test please", field, fieldType.Name(), value, valueType.Name()))
						}
						if !fieldValue.CanSet() {
							panic(fmt.Sprintf("modifying proto.Rule field %s of type %s is not possible, fix your test please", field, fieldType.Name()))
						}
						fieldValue.Set(valueValue)
						return rule
					}
					type policyInfo struct {
						name string
						rule *proto.Rule
					}
					policyInfos := []policyInfo{
						{
							name: "badAction",
							rule: allowRule("ipset"),
						},
						{
							name: "badIPVersion",
							rule: customRule(nil, "deny", 6, "ipset"),
						},
						{
							name: "withProtocol",
							rule: customRule(stringPtr("tcp"), "deny", 4, "ipset"),
						},
						{
							name: "noIPSets",
							rule: denyRule(),
						},
						{
							name: "tooManyIPSets",
							rule: denyRule("ipset", "ipset2"),
						},
						{
							name: "icmpDefined",
							rule: modifiedRule("Icmp", &proto.Rule_IcmpType{}),
						},
						{
							name: "notIcmpDefined",
							rule: modifiedRule("NotIcmp", &proto.Rule_NotIcmpType{}),
						},
						{
							name: "srcNetDefined",
							rule: modifiedRule("SrcNet", []string{"net"}),
						},
						{
							name: "notSrcNetDefined",
							rule: modifiedRule("NotSrcNet", []string{"net"}),
						},
						{
							name: "srcPortsDefined",
							rule: modifiedRule("SrcPorts", []*proto.PortRange{
								{
									First: 1,
									Last:  42,
								},
							}),
						},
						{
							name: "notSrcPortsDefined",
							rule: modifiedRule("NotSrcPorts", []*proto.PortRange{
								{
									First: 1,
									Last:  42,
								},
							}),
						},
						{
							name: "srcNamedPortIpSetIdsDefined",
							rule: modifiedRule("SrcNamedPortIpSetIds", []string{"namedPort"}),
						},
						{
							name: "notSrcNamedPortIpSetIdsDefined",
							rule: modifiedRule("NotSrcNamedPortIpSetIds", []string{"namedPort"}),
						},
						{
							name: "notProtocolDefined",
							rule: modifiedRule("NotProtocol", &proto.Protocol{
								NumberOrName: &proto.Protocol_Name{
									Name: "tcp",
								},
							}),
						},
						{
							name: "notSrcIpSetIdsDefined",
							rule: modifiedRule("NotSrcIpSetIds", []string{"ipset"}),
						},
						{
							name: "dstNetDefined",
							rule: modifiedRule("DstNet", []string{"net"}),
						},
						{
							name: "dstPortsDefined",
							rule: modifiedRule("DstPorts", []*proto.PortRange{
								{
									First: 1,
									Last:  42,
								},
							}),
						},
						{
							name: "dstNamedPortIpSetIdsDefined",
							rule: modifiedRule("DstNamedPortIpSetIds", []string{"namedPort"}),
						},
						{
							name: "dstIpSetIdsDefined",
							rule: modifiedRule("DstIpSetIds", []string{"ipset"}),
						},
						{
							name: "notDstNetDefined",
							rule: modifiedRule("NotDstNet", []string{"net"}),
						},
						{
							name: "notDstPortsDefined",
							rule: modifiedRule("NotDstPorts", []*proto.PortRange{
								{
									First: 1,
									Last:  42,
								},
							}),
						},
						{
							name: "notDstIpSetIdsDefined",
							rule: modifiedRule("NotDstIpSetIds", []string{"ipset"}),
						},
						{
							name: "notDstNamedPortIpSetIdsDefined",
							rule: modifiedRule("NotDstNamedPortIpSetIds", []string{"namedPort"}),
						},
						{
							name: "httpMatchDefined",
							rule: modifiedRule("HttpMatch", &proto.HTTPMatch{}),
						},
						{
							name: "srcServiceAccountMatchDefined",
							rule: modifiedRule("SrcServiceAccountMatch", &proto.ServiceAccountMatch{}),
						},
						{
							name: "dstServiceAccountMatchDefined",
							rule: modifiedRule("DstServiceAccountMatch", &proto.ServiceAccountMatch{}),
						},
					}
					ts := testStruct{
						currentState: make(map[string]testIfaceData, len(policyInfos)),
						endpoints:    make(map[string][]string, len(policyInfos)),
						events:       make([]testCBEvent, 0, len(policyInfos)),
						// no actions expected
						newCurrentState: make(map[string]testIfaceData, len(policyInfos)),
					}
					for idx, info := range policyInfos {
						iface := fmt.Sprintf("if%d", idx)
						ep := fmt.Sprintf("ep%d", idx)
						ifaceData := testIfaceData{
							epID: ep,
						}
						ts.currentState[iface] = ifaceData
						ts.endpoints[ep] = []string{info.name}
						ts.events = append(ts.events, updatePolicy(info.name, info.rule))
						ts.newCurrentState[iface] = ifaceData
					}
					return ts
				}()),
			)
		})

		Describe("resync", func() {
			type bpfIfaceData struct {
				hasXDP      bool
				hasBogusXDP bool
				hasBadMode  bool
				mapExists   bool
				mapBogus    bool
				mapMismatch bool
				mapContents map[bpf.IPv4Mask]uint32
			}

			bpfStateToBpfLib := func(bpfState map[string]bpfIfaceData) (bpf.BPFDataplane, string) {
				id := 0
				getNextID := func() int {
					id++
					return id
				}
				lib := bpf.NewMockBPFLib("../../bpf-apache/bin")
				failsafeID := getNextID()
				lib.FailsafeMap = bpf.NewMockFailsafeMap(failsafeID)
				expectedProgramBytes := []byte{42}
				bogusProgramBytes := []byte{13}
				for iface, bpfData := range bpfState {
					mapID := getNextID()
					if bpfData.mapExists {
						family := bpf.IPFamilyV4
						m := bpf.NewMockCIDRMap(mapID)
						if bpfData.mapBogus {
							m.Info.Type = "i'm a map, yes"
							m.Info.KeySize++
							m.Info.ValueSize++
						} else if bpfData.mapContents != nil {
							m.M = bpfData.mapContents
						}
						key := bpf.CIDRMapsKey{
							IfName: iface,
							Family: family,
						}
						lib.CIDRMaps[key] = m
					}
					if bpfData.hasXDP {
						prog := bpf.XDPInfo{
							Id:    getNextID(),
							Maps:  []int{failsafeID, mapID},
							Bytes: expectedProgramBytes,
							Mode:  bpf.XDPOffload,
						}
						if bpfData.hasBogusXDP {
							prog.Bytes = bogusProgramBytes
						}
						if bpfData.hasBadMode {
							// generic mode is forbidden in this test
							prog.Mode = bpf.XDPGeneric
						}
						if bpfData.mapMismatch {
							prog.Maps[1] = getNextID()
						}
						lib.XDPProgs[iface] = prog
					}
				}
				return lib, bpf.GetMockXDPTag(expectedProgramBytes)
			}

			type testStruct struct {
				bpfState        map[string]bpfIfaceData
				newCurrentState map[string]testIfaceData
				ipsetsSrc       ipsetsSource
				actions         *xdpBPFActions
			}

			DescribeTable("resync",
				func(s testStruct) {
					lib, programTag := bpfStateToBpfLib(s.bpfState)
					state := NewXDPStateWithBPFLibrary(lib, false)
					state.common.programTag = programTag
					ipState := state.ipV4State
					ipState.newCurrentState = newXDPSystemState()
					testStateToRealState(s.newCurrentState, nil, ipState.newCurrentState)

					ipsetsSrc := s.ipsetsSrc
					if ipsetsSrc == nil {
						ipsetsSrc = &nilIPSetsSource{}
					}
					err := ipState.tryResync(&state.common, newConvertingIPSetsSource(ipsetsSrc))
					Expect(err).NotTo(HaveOccurred())

					if s.actions == nil {
						s.actions = newXDPBPFActions()
					}
					if s.actions.CreateMap == nil {
						s.actions.CreateMap = set.New[string]()
					}
					if s.actions.RemoveMap == nil {
						s.actions.RemoveMap = set.New[string]()
					}
					if s.actions.AddToMap == nil {
						s.actions.AddToMap = make(map[string]map[string]uint32)
					}
					if s.actions.RemoveFromMap == nil {
						s.actions.RemoveFromMap = make(map[string]map[string]uint32)
					}
					if s.actions.InstallXDP == nil {
						s.actions.InstallXDP = set.New[string]()
					}
					if s.actions.UninstallXDP == nil {
						s.actions.UninstallXDP = set.New[string]()
					}
					if s.actions.MembersToDrop == nil {
						s.actions.MembersToDrop = make(map[string]map[string]uint32)
					}
					if s.actions.MembersToAdd == nil {
						s.actions.MembersToAdd = make(map[string]map[string]uint32)
					}
					Expect(ipState.bpfActions).To(Equal(s.actions))
				},
				Entry("nothing in BPF, nothing in current state, nothing to do", testStruct{
					// nothing in bpf state
					// nothing in new current state
					// nil ipsets source
					// no actions
				}),
				Entry("something in BPF, no need for BPF, remove BPF stuff", testStruct{
					bpfState: map[string]bpfIfaceData{
						"ifMap": {
							// no xdp
							mapExists: true,
						},
						"ifProg": {
							hasXDP: true,
							// no map
						},
						"ifProgMap": {
							hasXDP:    true,
							mapExists: true,
						},
					},
					// nothing in current state
					// nil ipsets source
					actions: &xdpBPFActions{
						RemoveMap:    set.From("ifMap", "ifProgMap"),
						UninstallXDP: set.From("ifProg", "ifProgMap"),
					},
				}),
				Entry("no XDP, but should have it", testStruct{
					bpfState: map[string]bpfIfaceData{
						"ifNoMap": {
							// no xdp
							// no map
						},
						"ifBogusMap": {
							// no xdp
							mapExists: true,
							mapBogus:  true,
						},
						"ifOkMap": {
							// no xdp
							mapExists: true,
						},
					},
					newCurrentState: map[string]testIfaceData{
						"ifNoMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifBogusMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifOkMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					// nil ipsets source
					actions: &xdpBPFActions{
						InstallXDP: set.From("ifNoMap", "ifBogusMap", "ifOkMap"),
						CreateMap:  set.From("ifNoMap", "ifBogusMap"),
						RemoveMap:  set.From("ifBogusMap"),
						AddToMap: map[string]map[string]uint32{
							"ifNoMap": {
								"ipset": 1,
							},
							"ifBogusMap": {
								"ipset": 1,
							},
							// no ifOkMap here, because it is synced memberwise,
							// but ipset has no members, no it does not appear anywhere
						},
					},
				}),
				Entry("has XDP, but with some map problems", testStruct{
					bpfState: map[string]bpfIfaceData{
						"ifNoMap": {
							hasXDP: true,
							// no map
						},
						"ifBogusMap": {
							hasXDP:    true,
							mapExists: true,
							mapBogus:  true,
						},
						"ifMismatchedMap": {
							hasXDP:      true,
							mapExists:   true,
							mapMismatch: true,
						},
						"ifOkMap": {
							hasXDP:    true,
							mapExists: true,
						},
					},
					newCurrentState: map[string]testIfaceData{
						"ifNoMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifBogusMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifMismatchedMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifOkMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					// nil ipsets source
					actions: &xdpBPFActions{
						InstallXDP:   set.From("ifNoMap", "ifBogusMap", "ifMismatchedMap"),
						UninstallXDP: set.From("ifNoMap", "ifBogusMap", "ifMismatchedMap"),
						CreateMap:    set.From("ifNoMap", "ifBogusMap"),
						RemoveMap:    set.From("ifBogusMap"),
						AddToMap: map[string]map[string]uint32{
							"ifNoMap": {
								"ipset": 1,
							},
							"ifBogusMap": {
								"ipset": 1,
							},
							// no ifOkMap and ifMismatchedMap here, because they are synced memberwise,
							// but ipset has no members, so they do not appear anywhere
						},
					},
				}),
				Entry("has bogus XDP and some map problems", testStruct{
					bpfState: map[string]bpfIfaceData{
						"ifNoMap": {
							hasXDP:      true,
							hasBogusXDP: true,
							// no map
						},
						"ifBogusMap": {
							hasXDP:      true,
							hasBogusXDP: true,
							mapExists:   true,
							mapBogus:    true,
						},
						"ifMismatchedMap": {
							hasXDP:      true,
							hasBogusXDP: true,
							mapExists:   true,
							mapMismatch: true,
						},
						"ifOkMap": {
							hasXDP:      true,
							hasBogusXDP: true,
							mapExists:   true,
						},
					},
					newCurrentState: map[string]testIfaceData{
						"ifNoMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifBogusMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifMismatchedMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifOkMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					// nil ipsets source
					actions: &xdpBPFActions{
						InstallXDP:   set.From("ifNoMap", "ifBogusMap", "ifMismatchedMap", "ifOkMap"),
						UninstallXDP: set.From("ifNoMap", "ifBogusMap", "ifMismatchedMap", "ifOkMap"),
						CreateMap:    set.From("ifNoMap", "ifBogusMap"),
						RemoveMap:    set.From("ifBogusMap"),
						AddToMap: map[string]map[string]uint32{
							"ifNoMap": {
								"ipset": 1,
							},
							"ifBogusMap": {
								"ipset": 1,
							},
							// no ifOkMap and ifMismatchedMap here, because they are synced memberwise,
							// but ipset has no members, so they do not appear anywhere
						},
					},
				}),
				Entry("has invalid XDP mode and some map problems", testStruct{
					bpfState: map[string]bpfIfaceData{
						"ifNoMap": {
							hasXDP:     true,
							hasBadMode: true,
							// no map
						},
						"ifBogusMap": {
							hasXDP:     true,
							hasBadMode: true,
							mapExists:  true,
							mapBogus:   true,
						},
						"ifMismatchedMap": {
							hasXDP:      true,
							hasBadMode:  true,
							mapExists:   true,
							mapMismatch: true,
						},
						"ifOkMap": {
							hasXDP:     true,
							hasBadMode: true,
							mapExists:  true,
						},
					},
					newCurrentState: map[string]testIfaceData{
						"ifNoMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifBogusMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifMismatchedMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifOkMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					// nil ipsets source
					actions: &xdpBPFActions{
						InstallXDP:   set.From("ifNoMap", "ifBogusMap", "ifMismatchedMap", "ifOkMap"),
						UninstallXDP: set.From("ifNoMap", "ifBogusMap", "ifMismatchedMap", "ifOkMap"),
						CreateMap:    set.From("ifNoMap", "ifBogusMap"),
						RemoveMap:    set.From("ifBogusMap"),
						AddToMap: map[string]map[string]uint32{
							"ifNoMap": {
								"ipset": 1,
							},
							"ifBogusMap": {
								"ipset": 1,
							},
							// no ifOkMap and ifMismatchedMap here, because they are synced memberwise,
							// but ipset has no members, so they do not appear anywhere
						},
					},
				}),
				Entry("has some member problems", testStruct{
					bpfState: map[string]bpfIfaceData{
						"ifNoMap": {
							// no xdp
							// no map
						},
						"ifOkMap": {
							hasXDP:    true,
							mapExists: true,
							mapContents: map[bpf.IPv4Mask]uint32{
								bpf.IPv4Mask{Ip: [4]byte{1, 2, 3, 4}, Mask: 32}: 1,
								bpf.IPv4Mask{Ip: [4]byte{2, 3, 4, 5}, Mask: 32}: 1,
								bpf.IPv4Mask{Ip: [4]byte{3, 4, 5, 6}, Mask: 32}: 1,
							},
						},
						"ifBadMap1": {
							hasXDP:    true,
							mapExists: true,
							mapContents: map[bpf.IPv4Mask]uint32{
								bpf.IPv4Mask{Ip: [4]byte{42, 42, 42, 42}, Mask: 32}: 3,
								bpf.IPv4Mask{Ip: [4]byte{1, 2, 3, 4}, Mask: 16}:     1,
							},
						},
						"ifBadMap2": {
							hasXDP:    true,
							mapExists: true,
							mapContents: map[bpf.IPv4Mask]uint32{
								bpf.IPv4Mask{Ip: [4]byte{1, 2, 3, 4}, Mask: 32}: 3,
								bpf.IPv4Mask{Ip: [4]byte{2, 3, 4, 5}, Mask: 32}: 6,
								bpf.IPv4Mask{Ip: [4]byte{3, 4, 5, 6}, Mask: 32}: 1,
							},
						},
					},
					newCurrentState: map[string]testIfaceData{
						"ifNoMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifOkMap": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifBadMap1": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
						"ifBadMap2": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					ipsetsSrc: &mockIPSetsSource{
						ipsetsMap: map[string]mockIPSetValue{
							"ipset": {
								ipsetType: ipsets.IPSetTypeHashIP,
								members:   set.From("1.2.3.4", "2.3.4.5", "3.4.5.6"),
							},
						},
					},
					actions: &xdpBPFActions{
						InstallXDP: set.From("ifNoMap"),
						CreateMap:  set.From("ifNoMap"),
						AddToMap: map[string]map[string]uint32{
							"ifNoMap": {
								"ipset": 1,
							},
						},
						MembersToAdd: map[string]map[string]uint32{
							"ifBadMap1": {
								"1.2.3.4/32": 1,
								"2.3.4.5/32": 1,
								"3.4.5.6/32": 1,
							},
						},
						MembersToDrop: map[string]map[string]uint32{
							"ifBadMap1": {
								"42.42.42.42/32": 3,
								"1.2.3.4/16":     1,
							},
							"ifBadMap2": {
								"1.2.3.4/32": 2,
								"2.3.4.5/32": 5,
							},
						},
					},
				}),
			)
		})

		Describe("process member updates", func() {
			type testStruct struct {
				ipsets           map[string][]string
				newCurrentState  map[string]testIfaceData
				events           []testCBEvent
				expectedBPFState map[string]map[string]uint32
			}
			DescribeTable("",
				func(s testStruct) {
					ipsetsWithTestStateToBPFStateAndCache := func(ipsets map[string][]string, testState map[string]testIfaceData) (map[string]map[string]uint32, map[string]set.Set[string]) {
						bpfState := make(map[string]map[string]uint32, len(testState))
						cache := make(map[string]set.Set[string])
						for iface, ifaceData := range testState {
							for _, setIDs := range ifaceData.policiesToSets {
								for _, setID := range setIDs {
									for _, member := range ipsets[setID] {
										m, ok := bpfState[iface]
										if !ok {
											m = make(map[string]uint32)
											bpfState[iface] = m
										}
										m[member] += 1
									}
									if _, ok := cache[setID]; !ok {
										cache[setID] = set.FromArray(ipsets[setID])
									}
								}
							}
						}
						return bpfState, cache
					}
					if s.ipsets == nil {
						s.ipsets = make(map[string][]string)
					}
					bpfState, cache := ipsetsWithTestStateToBPFStateAndCache(s.ipsets, s.newCurrentState)
					family := bpf.IPFamilyV4
					lib := stateToBPFDataplane(bpfState, family)
					memberCache := newXDPMemberCache(family, lib)
					state := NewXDPStateWithBPFLibrary(lib, true)
					ipState := state.ipV4State
					ipState.newCurrentState = newXDPSystemState()
					testStateToRealState(s.newCurrentState, nil, ipState.newCurrentState)
					ipState.ipsetIDsToMembers.cache = cache
					for _, event := range s.events {
						event.Do(ipState)
					}
					err := ipState.processMemberUpdates(memberCache)
					Expect(err).ToNot(HaveOccurred())
					actual := bpfDataplaneDump(lib, bpf.IPFamilyV4)
					if s.expectedBPFState == nil {
						s.expectedBPFState = make(map[string]map[string]uint32)
					}
					Expect(actual).To(Equal(s.expectedBPFState))
				},
				Entry("change irrelevant ipset", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						replaceIPSet("ipset2", "4.3.2.1/32", "5.4.3.2/32", "6.6.6.6/32"),
						addMembersIPSet("ipset3", "4.3.2.1/32", "5.4.3.2/32", "6.6.6.6/32"),
						removeMembersIPSet("ipset4", "2.3.4.5/32"),
						removeIPSet("ipset5"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {
							"1.2.3.4/32": 1,
						},
					},
				}),
				Entry("add a member to ipset", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						addMembersIPSet("ipset", "2.3.4.5/32"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {
							"1.2.3.4/32": 1,
							"2.3.4.5/32": 1,
						},
					},
				}),
				Entry("remove a member from ipset", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32", "2.3.4.5/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						removeMembersIPSet("ipset", "2.3.4.5/32"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {
							"1.2.3.4/32": 1,
						},
					},
				}),
				Entry("replace contents of the ipset", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32", "2.3.4.5/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						replaceIPSet("ipset", "4.3.2.1/32", "5.4.3.2/32"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {
							"4.3.2.1/32": 1,
							"5.4.3.2/32": 1,
						},
					},
				}),
				Entry("replace overlapping contents of the ipset", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32", "2.3.4.5/32", "6.6.6.6/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						replaceIPSet("ipset", "4.3.2.1/32", "5.4.3.2/32", "6.6.6.6/32"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {
							"4.3.2.1/32": 1,
							"5.4.3.2/32": 1,
							"6.6.6.6/32": 1,
						},
					},
				}),
				Entry("replace contents of the ipset with further modifications", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32", "2.3.4.5/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						replaceIPSet("ipset", "4.3.2.1/32", "5.4.3.2/32"),
						addMembersIPSet("ipset", "6.5.4.3/32"),
						removeMembersIPSet("ipset", "4.3.2.1/32"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {
							"6.5.4.3/32": 1,
							"5.4.3.2/32": 1,
						},
					},
				}),
				// this is kinda a lame case, because by the time the ipset is removed,
				// normally nothing refers to the ipset any more
				Entry("remove contents of the ipset", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32", "2.3.4.5/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						removeIPSet("ipset"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {},
					},
				}),
				Entry("modify contents of the ipset, then replace it", testStruct{
					ipsets: map[string][]string{
						"ipset": {"1.2.3.4/32", "2.3.4.5/32", "3.4.5.6/32"},
					},
					newCurrentState: map[string]testIfaceData{
						"iface": {
							epID: "ep",
							policiesToSets: map[string][]string{
								"policy": {"ipset"},
							},
						},
					},
					events: []testCBEvent{
						addMembersIPSet("ipset", "4.5.6.7/32"),
						removeMembersIPSet("ipset", "1.2.3.4/32"),
						replaceIPSet("ipset", "4.3.2.1/32", "5.4.3.2/32"),
					},
					expectedBPFState: map[string]map[string]uint32{
						"iface": {
							"4.3.2.1/32": 1,
							"5.4.3.2/32": 1,
						},
					},
				}),
			)
		})

		It("should clean the cache properly", func() {
			testState := map[string]testIfaceData{
				"iface": {
					epID: "ep",
					policiesToSets: map[string][]string{
						"policy": {"ipset"},
					},
				},
				"iface2": {
					epID: "ep2",
					policiesToSets: map[string][]string{
						"policy2": {"ipset2"},
					},
				},
			}
			state := NewXDPStateWithBPFLibrary(bpf.NewMockBPFLib("../../bpf-apache/bin"), true)
			ipState := state.ipV4State
			testStateToRealState(testState, nil, ipState.currentState)
			cache := ipState.ipsetIDsToMembers
			cache.cache = map[string]set.Set[string]{
				"ipset":  set.From("1.2.3.4/32"),
				"ipset2": set.From("2.3.4.5/32"),
				"ipset3": set.From("3.4.5.6/32"),
			}
			cache.pendingReplaces = map[string]set.Set[string]{
				"ipset":  set.From("10.20.30.40/32"),
				"ipset4": set.From("2.2.2.2/32"),
			}
			cache.pendingAdds = map[string]set.Set[string]{
				"ipset2": set.From("11.21.31.41/32"),
				"ipset5": set.From("3.3.3.3/32"),
			}
			cache.pendingDeletions = map[string]set.Set[string]{
				"ipset3": set.From("12.22.32.42/32"),
				"ipset6": set.From("4.4.4.4/32"),
			}
			expectedCache := newIPSetIDsToMembers()
			expectedCache.cache = map[string]set.Set[string]{
				"ipset":  set.From("1.2.3.4/32"),
				"ipset2": set.From("2.3.4.5/32"),
			}
			expectedCache.pendingReplaces = map[string]set.Set[string]{
				"ipset": set.From("10.20.30.40/32"),
			}
			expectedCache.pendingAdds = map[string]set.Set[string]{
				"ipset2": set.From("11.21.31.41/32"),
			}
			expectedCache.pendingDeletions = map[string]set.Set[string]{}
			ipState.cleanupCache()
			Expect(cache).To(Equal(expectedCache))
		})

		Describe("xdpBPFActions.apply", func() {
			type testStruct struct {
				initialState      map[string]map[string]uint32
				ipsetsSrc         ipsetsSource
				ipsetIDsToMembers *ipsetIDsToMembers
				install           []string
				uninstall         []string
				create            []string
				remove            []string
				addToMap          map[string]map[string]uint32
				removeFromMap     map[string]map[string]uint32
				membersToAdd      map[string]map[string]uint32
				membersToDrop     map[string]map[string]uint32
				expectedState     map[string]map[string]uint32
			}

			DescribeTable("",
				func(s testStruct) {
					state := NewXDPStateWithBPFLibrary(bpf.NewMockBPFLib("../../bpf-apache/bin"), false)
					state.ipV4State.bpfActions.InstallXDP.AddAll(s.install)
					state.ipV4State.bpfActions.UninstallXDP.AddAll(s.uninstall)
					state.ipV4State.bpfActions.CreateMap.AddAll(s.create)
					state.ipV4State.bpfActions.RemoveMap.AddAll(s.remove)
					state.ipV4State.bpfActions.MembersToAdd = s.membersToAdd
					state.ipV4State.bpfActions.MembersToDrop = s.membersToDrop
					state.ipV4State.bpfActions.AddToMap = s.addToMap
					state.ipV4State.bpfActions.RemoveFromMap = s.removeFromMap

					st := stateToBPFDataplane(s.initialState, bpf.IPFamilyV4)

					memberCache := newXDPMemberCache(bpf.IPFamilyV4, st)

					_, err := memberCache.bpfLib.NewFailsafeMap()
					Expect(err).NotTo(HaveOccurred())

					err = state.ipV4State.bpfActions.apply(memberCache, s.ipsetIDsToMembers, newConvertingIPSetsSource(s.ipsetsSrc), state.common.xdpModes)
					Expect(err).NotTo(HaveOccurred())

					actual := bpfDataplaneDump(st, bpf.IPFamilyV4)

					Expect(actual).To(Equal(s.expectedState))
				},
				Entry("only add", testStruct{
					initialState: map[string]map[string]uint32{},
					ipsetsSrc: &mockIPSetsSource{
						ipsetsMap: map[string]mockIPSetValue{
							"id0001": {
								ipsetType: ipsets.IPSetTypeHashIP,
								members:   set.From("10.0.0.1", "10.0.0.2"),
							},
							"id0004": {
								ipsetType: ipsets.IPSetTypeHashNet,
								members:   set.From("10.1.0.0/16", "10.1.1.0/24"),
							},
						},
					},
					ipsetIDsToMembers: newIPSetIDsToMembers(),
					install:           []string{"eth0", "eth1"},
					uninstall:         nil,
					create:            []string{"eth0", "eth1"},
					remove:            nil,
					addToMap: map[string]map[string]uint32{
						"eth0": {
							"id0004": 3,
						},
					},
					removeFromMap: nil,
					membersToAdd: map[string]map[string]uint32{
						"eth0": {
							"10.0.0.10/32": 2,
							"10.2.0.0/16":  1,
						},
						"eth1": {
							"10.0.0.3/32": 1,
						},
					},
					membersToDrop: nil,
					expectedState: map[string]map[string]uint32{
						"eth0": {
							"10.0.0.10/32": 2,
							"10.2.0.0/16":  1,
							"10.1.0.0/16":  3,
							"10.1.1.0/24":  3,
						},
						"eth1": {
							"10.0.0.3/32": 1,
						},
					},
				}),
				Entry("drop things with previous final state", testStruct{
					initialState: map[string]map[string]uint32{
						"eth0": {
							"10.0.0.10/32": 2,
							"10.2.0.0/16":  1,
							"10.1.0.0/16":  3,
							"10.1.1.0/24":  3,
						},
						"eth1": {
							"10.0.0.3/32": 1,
						},
					},
					ipsetsSrc: &mockIPSetsSource{},
					ipsetIDsToMembers: &ipsetIDsToMembers{
						cache: map[string]set.Set[string]{
							"id0001": set.From("10.0.0.1", "10.0.0.2"),
							"id0004": set.From("10.1.0.0/16", "10.1.1.0/24"),
						},
						pendingReplaces:  make(map[string]set.Set[string]),
						pendingAdds:      make(map[string]set.Set[string]),
						pendingDeletions: make(map[string]set.Set[string]),
					},
					install:   nil,
					uninstall: []string{"eth1"},
					create:    nil,
					remove:    []string{"eth1"},
					addToMap:  nil,
					removeFromMap: map[string]map[string]uint32{
						"eth0": {
							"id0004": 1,
						},
					},
					membersToAdd: nil,
					membersToDrop: map[string]map[string]uint32{
						"eth0": {
							"10.2.0.0/16": 1,
						},
					},
					expectedState: map[string]map[string]uint32{
						"eth0": {
							"10.0.0.10/32": 2,
							"10.1.0.0/16":  2,
							"10.1.1.0/24":  2,
						},
					},
				}),
				Entry("adds and drops", testStruct{
					initialState: map[string]map[string]uint32{
						"eth0": {
							"10.0.0.1/32": 3,
							"10.0.0.2/32": 2,
							"10.0.0.3/32": 4,
						},
						"eth1": {
							"10.0.1.1/32": 1,
							"10.0.1.2/32": 3,
							"10.0.1.0/24": 1,
						},
					},
					ipsetsSrc: &mockIPSetsSource{
						ipsetsMap: map[string]mockIPSetValue{
							"id0006": {
								ipsetType: ipsets.IPSetTypeHashIP,
								members:   set.From("1.1.1.1", "2.2.2.2"),
							},
							"id0007": {
								ipsetType: ipsets.IPSetTypeHashNet,
								members:   set.From("8.1.2.0/24", "10.1.1.0/24"),
							},
						},
					},
					ipsetIDsToMembers: &ipsetIDsToMembers{
						cache: map[string]set.Set[string]{
							"id0009": set.From("10.0.1.0/24"),
						},
						pendingReplaces:  make(map[string]set.Set[string]),
						pendingAdds:      make(map[string]set.Set[string]),
						pendingDeletions: make(map[string]set.Set[string]),
					},
					install:   []string{"wlan0"},
					uninstall: []string{"eth0"},
					create:    []string{"wlan0"},
					remove:    []string{"eth0"},
					addToMap: map[string]map[string]uint32{
						"eth1": {
							"id0006": 3,
						},
						"wlan0": {
							"id0006": 1,
							"id0007": 1,
						},
					},
					removeFromMap: map[string]map[string]uint32{
						"eth1": {
							"id0009": 1,
						},
					},
					membersToAdd: map[string]map[string]uint32{
						"eth1": {
							"9.9.0.0/16": 2,
						},
						"wlan0": {
							"1.1.1.1/32": 1,
						},
					},
					membersToDrop: map[string]map[string]uint32{
						"eth1": {
							"10.0.1.2/32": 3,
						},
					},
					expectedState: map[string]map[string]uint32{
						"eth1": {
							"1.1.1.1/32":  3,
							"2.2.2.2/32":  3,
							"10.0.1.1/32": 1,
							"9.9.0.0/16":  2,
						},
						"wlan0": {
							"1.1.1.1/32":  2,
							"2.2.2.2/32":  1,
							"8.1.2.0/24":  1,
							"10.1.1.0/24": 1,
						},
					},
				}),
				Entry("replace or remove program that has the undesired mode", testStruct{
					initialState: map[string]map[string]uint32{
						// the _xdpgeneric suffix won't be
						// a part of the iface name
						"eth0_xdpgeneric": {
							"10.0.0.10/32": 1,
						},
						"eth1_xdpgeneric": {
							"10.0.0.10/32": 1,
						},
					},
					ipsetsSrc: &mockIPSetsSource{},
					ipsetIDsToMembers: &ipsetIDsToMembers{
						cache:            make(map[string]set.Set[string]),
						pendingReplaces:  make(map[string]set.Set[string]),
						pendingAdds:      make(map[string]set.Set[string]),
						pendingDeletions: make(map[string]set.Set[string]),
					},
					install:       []string{"eth0"},
					uninstall:     []string{"eth0", "eth1"},
					create:        nil,
					remove:        nil,
					addToMap:      nil,
					removeFromMap: nil,
					membersToAdd:  nil,
					membersToDrop: nil,
					expectedState: map[string]map[string]uint32{
						"eth0": {
							"10.0.0.10/32": 1,
						},
					},
				}),
			)
		})

		Describe("getIfaces", func() {
			type testStruct struct {
				install   []string
				uninstall []string
				create    []string
				remove    []string
				withProgs map[string]progInfo
				withMaps  map[string]mapInfo
				newState  map[string]bool /* needs XDP */
				expected  map[IfaceFlags][]string
			}

			DescribeTable("",
				func(s testStruct) {
					state := NewXDPStateWithBPFLibrary(bpf.NewMockBPFLib("../../bpf-apache/bin"), true)
					state.ipV4State.newCurrentState = newXDPSystemState()
					ipsetsSrc := &nilIPSetsSource{}
					resyncState, err := state.ipV4State.newXDPResyncState(state.common.bpfLib, ipsetsSrc, state.common.programTag, state.common.xdpModes)
					Expect(err).NotTo(HaveOccurred())
					state.ipV4State.bpfActions.InstallXDP.AddAll(s.install)
					state.ipV4State.bpfActions.UninstallXDP.AddAll(s.uninstall)
					state.ipV4State.bpfActions.CreateMap.AddAll(s.create)
					state.ipV4State.bpfActions.RemoveMap.AddAll(s.remove)
					for i, p := range s.withProgs {
						resyncState.ifacesWithProgs[i] = p
					}
					for i, p := range s.withMaps {
						resyncState.ifacesWithMaps[i] = p
					}
					for iface, needsXDP := range s.newState {
						data := xdpIfaceData{}
						if needsXDP {
							policyID := proto.PolicyID{Tier: "default", Name: "bar"}
							endpointID := proto.HostEndpointID{EndpointId: "foo"}
							data.EpID = endpointID
							data.PoliciesToSetIDs = map[proto.PolicyID]set.Set[string]{
								policyID: set.From("ipset"),
							}
						}
						state.ipV4State.newCurrentState.IfaceNameToData[iface] = data
					}
					for f, s := range s.expected {
						Expect(state.ipV4State.getIfaces(resyncState, f)).To(Equal(set.FromArray(s)))
					}
				},
				Entry("simple test", testStruct{
					install:   []string{"eth0", "eth1"},
					uninstall: []string{"eth10"},
					create:    []string{"enps0"},
					remove:    []string{"enps1"},
					withProgs: map[string]progInfo{
						"wlan0": {},
						"wlan1": {},
					},
					withMaps: map[string]mapInfo{
						"wlan0": {},
						"wlan1": {},
					},
					newState: map[string]bool{
						"eth15": true,
						"eth99": false,
					},
					expected: map[IfaceFlags][]string{
						giIX: {
							"eth0",
							"eth1",
						},
						giUX: {
							"eth10",
						},
						giIX | giUX: {
							"eth0",
							"eth1",
							"eth10",
						},
						giCM: {
							"enps0",
						},
						giRM: {
							"enps1",
						},
						giRM | giNS | giWX | giWM: {
							"enps1",
							"eth15",
							"wlan0",
							"wlan1",
						},
						giNS | giWX | giIX | giUX | giWM | giCM | giRM: {
							"eth0",
							"eth1",
							"eth10",
							"enps0",
							"enps1",
							"eth15",
							"wlan0",
							"wlan1",
						},
					},
				}),
			)
		})
	})
})
