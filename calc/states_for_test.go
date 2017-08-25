// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package calc_test

import (
	"fmt"
	"strings"

	"github.com/projectcalico/felix/proto"
	. "github.com/projectcalico/libcalico-go/lib/backend/model"
)

// Pre-defined datastore states.  Each State object wraps up the complete state
// of the datastore as well as the expected state of the dataplane.  The state
// of the dataplane *should* depend only on the current datastore state, not on
// the path taken to get there.  Therefore, it's always a valid test to move
// from any state to any other state (by feeding in the corresponding
// datastore updates) and then assert that the dataplane matches the resulting
// state.

// empty is the base state, with nothing in the datastore or dataplane.
var empty = NewState().withName("<empty>")

// initialisedStore builds on empty, adding in the ready flag and global config.
var initialisedStore = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "InterfacePrefix"}, Value: "cali"},
	KVPair{Key: ReadyFlagKey{}, Value: true},
).withName("<initialised>")

// withPolicy adds a tier and policy containing selectors for all and b=="b"
var withPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20},
).withName("with policy")

// withPolicyIngressOnly adds a tier and ingress policy containing selectors for all
var withPolicyIngressOnly = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_ingress_only},
).withName("with ingress-only policy")

// withPolicyEgressOnly adds a tier and egress policy containing selectors for b=="b"
var withPolicyEgressOnly = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_egress_only},
).withName("with egress-only policy")

// withUntrackedPolicy adds a tier and policy containing selectors for all and b=="b"
var withUntrackedPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_untracked},
).withName("with untracked policy")

// withPreDNATPolicy adds a tier and policy containing selectors for all and a=="a"
var withPreDNATPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pre-dnat-pol-1"}, Value: &policy1_order20_pre_dnat},
).withName("with pre-DNAT policy")

// localEp1WithPolicy adds a local endpoint to the mix.  It matches all and b=="b".
var localEp1WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
).withName("ep1 local, policy")

// localEp1WithIngressPolicy is as above except ingress policy only.
var localEp1WithIngressPolicy = withPolicyIngressOnly.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{
		{"default", []string{"pol-1"}, nil},
	},
).withName("ep1 local, ingress-only policy")

var hostEp1WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
).withName("host ep1, policy")

var hostEp1WithIngressPolicy = withPolicyIngressOnly.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]tierInfo{
		{"default", []string{"pol-1"}, nil},
	},
).withName("host ep1, ingress-only policy")

var hostEp1WithEgressPolicy = withPolicyEgressOnly.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]tierInfo{
		{"default", nil, []string{"pol-1"}},
	},
).withName("host ep1, egress-only policy")

var hostEp1WithUntrackedPolicy = withUntrackedPolicy.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withUntrackedPolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-missing"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]tierInfo{},
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
	[]tierInfo{},
).withName("host ep1, untracked policy")

var hostEp1WithPreDNATPolicy = withPreDNATPolicy.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pre-dnat-pol-1"},
).withPreDNATPolicies(
	proto.PolicyID{"default", "pre-dnat-pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-missing"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]tierInfo{},
	[]tierInfo{},
	[]tierInfo{
		{"default", []string{"pre-dnat-pol-1"}, nil},
	},
).withName("host ep1, pre-DNAT policy")

var hostEp1WithTrackedAndUntrackedPolicy = hostEp1WithUntrackedPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-2"}, Value: &policy1_order20},
).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
	proto.PolicyID{"default", "pol-2"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]tierInfo{
		{"default", []string{"pol-2"}, []string{"pol-2"}},
	},
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
	[]tierInfo{},
).withName("host ep1, tracked+untracked policy")

var hostEp2WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: hostEp2NoNameKey, Value: &hostEp2NoName},
).withIPSet(allSelectorId, []string{
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(bEqBSelectorId, []string{}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-3"},
).withEndpoint(
	hostEpNoNameId,
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
).withName("host ep2, policy")

// Policy ordering tests.  We keep the names of the policies the same but we
// change their orders to check that order trumps name.
var localEp1WithOneTierPolicy123 = policyOrderState(
	[3]float64{order10, order20, order30},
	[3]string{"pol-1", "pol-2", "pol-3"},
)
var localEp1WithOneTierPolicy321 = policyOrderState(
	[3]float64{order30, order20, order10},
	[3]string{"pol-3", "pol-2", "pol-1"},
)
var localEp1WithOneTierPolicyAlpha = policyOrderState(
	[3]float64{order10, order10, order10},
	[3]string{"pol-1", "pol-2", "pol-3"},
)

func policyOrderState(policyOrders [3]float64, expectedOrder [3]string) State {
	policies := [3]Policy{}
	for i := range policies {
		policies[i] = Policy{
			Order:         &policyOrders[i],
			Selector:      "a == 'a'",
			InboundRules:  []Rule{{SrcSelector: allSelector}},
			OutboundRules: []Rule{{SrcSelector: bEpBSelector}},
		}
	}
	state := initialisedStore.withKVUpdates(
		KVPair{Key: localWlEpKey1, Value: &localWlEp1},
		KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policies[0]},
		KVPair{Key: PolicyKey{Name: "pol-2"}, Value: &policies[1]},
		KVPair{Key: PolicyKey{Name: "pol-3"}, Value: &policies[2]},
	).withIPSet(allSelectorId, []string{
		"10.0.0.1", // ep1
		"fc00:fe11::1",
		"10.0.0.2", // ep1 and ep2
		"fc00:fe11::2",
	}).withIPSet(bEqBSelectorId, []string{
		"10.0.0.1",
		"fc00:fe11::1",
		"10.0.0.2",
		"fc00:fe11::2",
	}).withActivePolicies(
		proto.PolicyID{"default", "pol-1"},
		proto.PolicyID{"default", "pol-2"},
		proto.PolicyID{"default", "pol-3"},
	).withActiveProfiles(
		proto.ProfileID{"prof-1"},
		proto.ProfileID{"prof-2"},
		proto.ProfileID{"prof-missing"},
	).withEndpoint(
		localWlEp1Id,
		[]tierInfo{
			{"default", expectedOrder[:], expectedOrder[:]},
		},
	).withName(fmt.Sprintf("ep1 local, 1 tier, policies %v", expectedOrder[:]))
	return state
}

// localEp2WithPolicy adds a different endpoint that doesn't match b=="b".
// This tests an empty IP set.
var localEp2WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(
	bEqBSelectorId, []string{},
).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-3"},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
).withName("ep2 local, policy")

// localEpsWithPolicy contains both of the above endpoints, which have some
// overlapping IPs.  When we sequence this with the states above, we test
// overlapping IP addition and removal.
var localEpsWithPolicy = withPolicy.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-3"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{
		{"default", []string{"pol-1"}, []string{"pol-1"}},
	},
).withName("2 local, overlapping IPs & a policy")

// localEpsWithPolicyUpdatedIPs, when used with localEpsWithPolicy checks
// correct handling of IP address updates.  We add and remove some IPs from
// endpoint 1 and check that only its non-shared IPs are removed from the IP
// sets.
var localEpsWithPolicyUpdatedIPs = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1DifferentIPs},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"11.0.0.1", // ep1
	"fc00:fe12::1",
	"11.0.0.2",
	"fc00:fe12::2",
	"10.0.0.2", // now ep2 only
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(bEqBSelectorId, []string{
	"11.0.0.1", // ep1
	"fc00:fe12::1",
	"11.0.0.2",
	"fc00:fe12::2",
})

// withProfile adds a profile to the initialised state.
var withProfile = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey{"prof-1"}}, Value: &profileRules1},
	KVPair{Key: ProfileTagsKey{ProfileKey{"prof-1"}}, Value: profileTags1},
	KVPair{Key: ProfileLabelsKey{ProfileKey{"prof-1"}}, Value: profileLabels1},
).withName("profile")

// localEpsWithProfile contains a pair of overlapping IP endpoints and a profile
// that matches them both.
var localEpsWithProfile = withProfile.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
	"10.0.0.3", // ep2
	"fc00:fe11::3",
}).withIPSet(tag1LabelID, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-3"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{},
).withName("2 local, overlapping IPs & a profile")

// localEpsWithNonMatchingProfile contains a pair of overlapping IP endpoints and a profile
// that matches them both.
var localEpsWithNonMatchingProfile = withProfile.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1NoProfiles},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2NoProfiles},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{},
).withName("2 local, overlapping IPs & a non-matching profile")

// localEpsWithUpdatedProfile Follows on from localEpsWithProfile, changing the
// profile to use a different tag and selector.
var localEpsWithUpdatedProfile = localEpsWithProfile.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey{"prof-1"}}, Value: &profileRules1TagUpdate},
).withIPSet(
	tag1LabelID, nil,
).withIPSet(
	allSelectorId, nil,
).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1",
	"fc00:fe11::1",
	"10.0.0.2",
	"fc00:fe11::2",
}).withIPSet(
	tag2LabelID, []string{},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{},
).withName("2 local, overlapping IPs & updated profile")

var localEpsWithUpdatedProfileNegatedTags = localEpsWithUpdatedProfile.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey{"prof-1"}}, Value: &profileRules1NegatedTagSelUpdate},
)

// withProfileTagInherit adds a profile that includes rules that match on
// tags as labels.  I.e. a tag of name foo should be equivalent to label foo=""
var withProfileTagInherit = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey{"prof-1"}}, Value: &profileRulesWithTagInherit},
	KVPair{Key: ProfileTagsKey{ProfileKey{"prof-1"}}, Value: profileTags1},
	KVPair{Key: ProfileLabelsKey{ProfileKey{"prof-1"}}, Value: profileLabels1},
).withName("profile")

var localEpsWithTagInheritProfile = withProfileTagInherit.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(tagSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withIPSet(tagFoobarSelectorId, []string{}).withActiveProfiles(
	proto.ProfileID{"prof-1"},
).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-3"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{},
).withName("2 local, overlapping IPs & a tag inherit profile")

var withProfileTagOverriden = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey{"prof-1"}}, Value: &profileRulesWithTagInherit},
	KVPair{Key: ProfileTagsKey{ProfileKey{"prof-1"}}, Value: profileTags1},
	KVPair{Key: ProfileLabelsKey{ProfileKey{"prof-1"}}, Value: profileLabelsTag1},
).withName("profile")

// localEpsWithTagOverriddenProfile Checks that tags-inherited labels can be
// overridden by explicit labels on the profile.
var localEpsWithTagOverriddenProfile = withProfileTagOverriden.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(tagSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withIPSet(tagFoobarSelectorId, []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // ep1 and ep2
	"fc00:fe11::2",
}).withActiveProfiles(
	proto.ProfileID{"prof-1"},
	proto.ProfileID{"prof-2"},
	proto.ProfileID{"prof-3"},
	proto.ProfileID{"prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]tierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{},
).withName("2 local, overlapping IPs & a tag inherit profile")

type StateList []State

func (l StateList) String() string {
	names := make([]string, 0)
	for _, state := range l {
		names = append(names, state.String())
	}
	return "[" + strings.Join(names, ", ") + "]"
}

// identity is a test expander that returns the test unaltered.
func identity(baseTest StateList) (string, []StateList) {
	return "in normal ordering", []StateList{baseTest}
}

// reverseStateOrder returns a StateList containing the same states in
// reverse order.
func reverseStateOrder(baseTest StateList) (desc string, mappedTests []StateList) {
	desc = "with order of states reversed"
	palindrome := true
	mappedTest := StateList{}
	for ii := 0; ii < len(baseTest); ii++ {
		mappedTest = append(mappedTest, baseTest[len(baseTest)-ii-1])
		if &baseTest[len(baseTest)-1-ii] != &baseTest[ii] {
			palindrome = false
		}
	}
	if palindrome {
		// Test was a palindrome so there's no point in reversing it.
		return
	}
	mappedTests = []StateList{mappedTest}
	return
}

// reverseKVOrder returns a StateList containing the states in the same order
// but with their DataStore key order reversed.
func reverseKVOrder(baseTests StateList) (desc string, mappedTests []StateList) {
	desc = "with order of KVs reversed within each state"
	mappedTest := StateList{}
	for _, test := range baseTests {
		mappedState := test.Copy()
		state := mappedState.DatastoreState
		for ii := 0; ii < len(state)/2; ii++ {
			jj := len(state) - ii - 1
			state[ii], state[jj] = state[jj], state[ii]
		}
		mappedTest = append(mappedTest, mappedState)
	}
	mappedTests = []StateList{mappedTest}
	return
}

// insertEmpties inserts an empty state between each state in the base test.
func insertEmpties(baseTest StateList) (desc string, mappedTests []StateList) {
	desc = "with empty state inserted between each state"
	mappedTest := StateList{}
	for _, state := range baseTest {
		mappedTest = append(mappedTest, state)
		mappedTest = append(mappedTest, empty)
	}
	mappedTests = append(mappedTests, mappedTest)
	return
}

func splitStates(baseTest StateList) (desc string, mappedTests []StateList) {
	desc = "with individual states broken out"
	if len(baseTest) <= 1 {
		// No point in splitting a single-item test.
		return
	}
	for _, state := range baseTest {
		mappedTests = append(mappedTests, StateList{state})
	}
	return
}

// squash returns a StateList with all the states squashed into one (which may
// include some deletions in the DatastoreState.
func squashStates(baseTests StateList) (desc string, mappedTests []StateList) {
	mappedTest := StateList{}
	desc = "all states squashed into one"
	if len(baseTests) == 0 {
		return
	}
	kvs := make([]KVPair, 0)
	mappedState := baseTests[len(baseTests)-1].Copy()
	lastTest := empty
	for _, test := range baseTests {
		for _, update := range test.KVDeltas(lastTest) {
			kvs = append(kvs, update.KVPair)
		}
		lastTest = test
	}
	mappedState.DatastoreState = kvs
	mappedState.ExpectedEndpointPolicyOrder = lastTest.ExpectedEndpointPolicyOrder
	mappedState.Name = fmt.Sprintf("squashed(%v)", baseTests)
	mappedTest = append(mappedTest, mappedState)
	mappedTests = []StateList{mappedTest}
	return
}
