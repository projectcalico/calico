// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	. "github.com/projectcalico/felix/calc"

	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	. "github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
)

// Canned hostnames.

const localHostname = "localhostname"
const remoteHostname = "remotehostname"

// Canned selectors.

var (
	allSelector         = "all()"
	allSelectorId       = selectorId(allSelector)
	bEpBSelector        = "b == 'b'"
	bEqBSelectorId      = selectorId(bEpBSelector)
	tagSelector         = "has(tag-1)"
	tagSelectorId       = selectorId(tagSelector)
	tagFoobarSelector   = "tag-1 == 'foobar'"
	tagFoobarSelectorId = selectorId(tagFoobarSelector)
)

// Canned workload endpoints.

var localWlEpKey1 = WorkloadEndpointKey{localHostname, "orch", "wl1", "ep1"}
var remoteWlEpKey1 = WorkloadEndpointKey{remoteHostname, "orch", "wl1", "ep1"}
var localWlEp1Id = "orch/wl1/ep1"
var localWlEpKey2 = WorkloadEndpointKey{localHostname, "orch", "wl2", "ep2"}
var localWlEp2Id = "orch/wl2/ep2"

var localWlEp1 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
}

var localWlEp1NoProfiles = WorkloadEndpoint{
	State: "active",
	Name:  "cali1",
	Mac:   mustParseMac("01:02:03:04:05:06"),
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"),
		mustParseNet("10.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::1/128"),
		mustParseNet("fc00:fe11::2/128")},
}

var localWlEp1DifferentIPs = WorkloadEndpoint{
	State:      "active",
	Name:       "cali1",
	Mac:        mustParseMac("01:02:03:04:05:06"),
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	IPv4Nets: []net.IPNet{mustParseNet("11.0.0.1/32"),
		mustParseNet("11.0.0.2/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe12::1/128"),
		mustParseNet("fc00:fe12::2/128")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
}

var ep1IPs = []string{
	"10.0.0.1", // ep1
	"fc00:fe11::1",
	"10.0.0.2", // shared with ep2
	"fc00:fe11::2",
}

var localWlEp2 = WorkloadEndpoint{
	State:      "active",
	Name:       "cali2",
	ProfileIDs: []string{"prof-2", "prof-3"},
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128")},
	Labels: map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	},
}

var localWlEp2NoProfiles = WorkloadEndpoint{
	State: "active",
	Name:  "cali2",
	IPv4Nets: []net.IPNet{mustParseNet("10.0.0.2/32"),
		mustParseNet("10.0.0.3/32")},
	IPv6Nets: []net.IPNet{mustParseNet("fc00:fe11::2/128"),
		mustParseNet("fc00:fe11::3/128")},
}

var hostEpWithName = HostEndpoint{
	Name:       "eth1",
	ProfileIDs: []string{"prof-1", "prof-2", "prof-missing"},
	ExpectedIPv4Addrs: []net.IP{mustParseIP("10.0.0.1"),
		mustParseIP("10.0.0.2")},
	ExpectedIPv6Addrs: []net.IP{mustParseIP("fc00:fe11::1"),
		mustParseIP("fc00:fe11::2")},
	Labels: map[string]string{
		"id": "loc-ep-1",
		"a":  "a",
		"b":  "b",
	},
}

var hostEpWithNameKey = HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "named",
}
var hostEpWithNameId = "named"

var hostEp2NoName = HostEndpoint{
	ProfileIDs: []string{"prof-2", "prof-3"},
	ExpectedIPv4Addrs: []net.IP{mustParseIP("10.0.0.2"),
		mustParseIP("10.0.0.3")},
	ExpectedIPv6Addrs: []net.IP{mustParseIP("fc00:fe11::2"),
		mustParseIP("fc00:fe11::3")},
	Labels: map[string]string{
		"id": "loc-ep-2",
		"a":  "a",
		"b":  "b2",
	},
}

var hostEp2NoNameKey = HostEndpointKey{
	Hostname:   localHostname,
	EndpointID: "unnamed",
}
var hostEpNoNameId = "unnamed"

// Canned tiers/policies.

var order10 = float64(10)
var order20 = float64(20)
var order30 = float64(30)

var policy1_order20 = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
}

var policy1_order20_untracked = Policy{
	Order:    &order20,
	Selector: "a == 'a'",
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	DoNotTrack: true,
}

var profileRules1 = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: allSelector},
	},
	OutboundRules: []Rule{
		{SrcTag: "tag-1"},
	},
}

var profileRulesWithTagInherit = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: tagSelector},
	},
	OutboundRules: []Rule{
		{SrcSelector: tagFoobarSelector},
	},
}

var profileRules1TagUpdate = ProfileRules{
	InboundRules: []Rule{
		{SrcSelector: bEpBSelector},
	},
	OutboundRules: []Rule{
		{SrcTag: "tag-2"},
	},
}

var profileRules1NegatedTagSelUpdate = ProfileRules{
	InboundRules: []Rule{
		{NotSrcSelector: bEpBSelector},
	},
	OutboundRules: []Rule{
		{NotSrcTag: "tag-2"},
	},
}

var profileTags1 = []string{"tag-1"}
var profileLabels1 = map[string]string{
	"profile": "prof-1",
}
var profileLabelsTag1 = map[string]string{
	"tag-1": "foobar",
}

var tag1LabelID = ipSetIDForTag("tag-1")
var tag2LabelID = ipSetIDForTag("tag-2")

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

// withUntrackedPolicy adds a tier and policy containing selectors for all and b=="b"
var withUntrackedPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_untracked},
).withName("with untracked policy")

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
		{"default", []string{"pol-1"}},
	},
).withName("ep1 local, policy")

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
		{"default", []string{"pol-1"}},
	},
).withName("host ep1, policy")

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
		{"default", []string{"pol-1"}},
	},
).withName("host ep1, untracked policy")

var hostEp1WithTrackedAndUntrackedPolicy = hostEp1WithUntrackedPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-2"}, Value: &policy1_order20},
).withActivePolicies(
	proto.PolicyID{"default", "pol-1"},
	proto.PolicyID{"default", "pol-2"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]tierInfo{
		{"default", []string{"pol-2"}},
	},
	[]tierInfo{
		{"default", []string{"pol-1"}},
	},
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
		{"default", []string{"pol-1"}},
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
			{"default", expectedOrder[:]},
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
		{"default", []string{"pol-1"}},
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
		{"default", []string{"pol-1"}},
	},
).withEndpoint(
	localWlEp2Id,
	[]tierInfo{
		{"default", []string{"pol-1"}},
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

// Each entry in baseTests contains a series of states to move through.  Apart
// from running each of these, we'll also expand each of them by passing it
// through the expansion functions below.  In particular, we'll do each of them
// in reversed order and reversed KV injection order.
var baseTests = []StateList{
	// Empty should be empty!
	{},
	// Add one endpoint then remove it and add another with overlapping IP.
	{localEp1WithPolicy, localEp2WithPolicy},

	// Add one endpoint then another with an overlapping IP, then remove
	// first.
	{localEp1WithPolicy, localEpsWithPolicy, localEp2WithPolicy},

	// Add both endpoints, then return to empty, then add them both back.
	{localEpsWithPolicy, initialisedStore, localEpsWithPolicy},

	// IP updates.
	{localEpsWithPolicy, localEpsWithPolicyUpdatedIPs},

	// Add a profile and a couple of endpoints.  Then update the profile to
	// use different tags and selectors.
	{localEpsWithProfile, localEpsWithUpdatedProfile},

	// Tests of policy ordering.  Each state has one tier but we shuffle
	// the order of the policies within it.
	{localEp1WithOneTierPolicy123,
		localEp1WithOneTierPolicy321,
		localEp1WithOneTierPolicyAlpha},

	// Test mutating the profile list of some endpoints.
	{localEpsWithNonMatchingProfile, localEpsWithProfile},

	// String together some complex updates with profiles and policies
	// coming and going.
	{localEpsWithProfile,
		localEp1WithOneTierPolicy123,
		localEpsWithNonMatchingProfile,
		localEpsWithTagInheritProfile,
		localEpsWithPolicy,
		localEpsWithPolicyUpdatedIPs,
		hostEp1WithPolicy,
		localEpsWithUpdatedProfile,
		withProfileTagInherit,
		localEpsWithNonMatchingProfile,
		localEpsWithUpdatedProfileNegatedTags,
		hostEp1WithUntrackedPolicy,
		localEpsWithTagInheritProfile,
		localEp1WithPolicy,
		localEpsWithProfile},

	// Host endpoint tests.
	{hostEp1WithPolicy, hostEp2WithPolicy},

	// Untracked policy on its own.
	{hostEp1WithUntrackedPolicy},
	// Mixed policy.
	{hostEp1WithTrackedAndUntrackedPolicy},
	// Single policy switches between tracked/untracked.
	{hostEp1WithUntrackedPolicy, hostEp1WithPolicy},
	{hostEp1WithUntrackedPolicy, hostEp1WithTrackedAndUntrackedPolicy, hostEp1WithPolicy},

	// Tag to label inheritance.  Tag foo should be inherited as label
	// foo="".
	{withProfileTagInherit, localEpsWithTagInheritProfile},
	// But if there's an explicit label, it overrides the tag.
	{localEpsWithTagOverriddenProfile, withProfileTagOverriden},

	// TODO(smc): Test config calculation
	// TODO(smc): Test mutation of endpoints
	// TODO(smc): Test mutation of host endpoints
	// TODO(smc): Test validation
	// TODO(smc): Test rule conversions
}

type StateList []State

func (l StateList) String() string {
	names := make([]string, 0)
	for _, state := range l {
		names = append(names, state.String())
	}
	return "[" + strings.Join(names, ", ") + "]"
}

var testExpanders = []func(baseTest StateList) (desc string, mappedTests []StateList){
	identity,
	reverseKVOrder,
	reverseStateOrder,
	insertEmpties,
	splitStates,
	squashStates,
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

// These tests drive the calculation graph directly (and synchronously).
// They take the StateLists in baseTests, expand them using the test expansion
// functions and then drive the graph through the expanded states.  These tests
// also deterministically decide when to flush the calculation graph's buffers
// so they should be deterministic overall.  Any non-determinism is likely to
// come from iterations over maps or sets inside the calculation graph.
//
// Debugging note: since the tests get expanded, a single failure in a base
// test often creates many fails in the output as each expansion of that test
// is also likely to fail.  A good strategy for debugging is to focus on the
// base tests first.
var _ = Describe("Calculation graph state sequencing tests:", func() {
	for _, test := range baseTests {
		baseTest := test
		for _, expander := range testExpanders {
			expanderDesc, expandedTests := expander(baseTest)
			for _, expandedTest := range expandedTests {
				// Always worth adding an empty to the end of the test.
				expandedTest = append(expandedTest, empty)
				desc := fmt.Sprintf("with input states %v %v", baseTest, expanderDesc)
				Describe(desc+" flushing after each KV", func() {
					doStateSequenceTest(expandedTest, afterEachKV)
				})
				Describe(desc+" flushing after each state", func() {
					doStateSequenceTest(expandedTest, afterEachState)
				})
				Describe(desc+" flushing at end only", func() {
					doStateSequenceTest(expandedTest, atEnd)
				})
			}
		}
	}
})

// These tests use the same expansion logic as the synchronous tests above
// but they drive the calculation graph via its asynchronous channel interface.
// Since they don't have control over when the graph gets flushed, they are
// less deterministic than the tests above and they can't test the output after
// every state is reached.
//
// Debugging note: only spend time debugging these tests once the equivalent
// synchronous test above is passing.  It's much easier to debug a
// deterministic test!
var _ = Describe("Async calculation graph state sequencing tests:", func() {
	for _, test := range baseTests {
		if len(test) == 0 {
			continue
		}
		baseTest := test

		for _, expander := range testExpanders {
			expanderDesc, expandedTests := expander(baseTest)
			for _, test := range expandedTests {
				test := test
				It("should handle: "+baseTest.String()+" "+expanderDesc, func() {
					// Create the calculation graph.
					conf := config.New()
					conf.FelixHostname = localHostname
					outputChan := make(chan interface{})
					asyncGraph := NewAsyncCalcGraph(conf, outputChan)
					// And a validation filter, with a channel between it
					// and the async graph.
					validator := NewValidationFilter(asyncGraph)
					toValidator := NewSyncerCallbacksDecoupler()
					// Start the validator in one thread.
					go toValidator.SendTo(validator)
					// And the calc graph in another.
					asyncGraph.Start()
					// Channel to tell us when the input is done.
					done := make(chan bool, 2)
					// Start a thread to inject the KVs.
					go func() {
						log.Info("Input injector thread started")
						lastState := empty
						for _, state := range test {
							log.WithField("state", state).Info("Injecting next state")
							kvDeltas := state.KVDeltas(lastState)
							toValidator.OnUpdates(kvDeltas)
							lastState = state
						}
						toValidator.OnStatusUpdated(api.InSync)

						// Wait for the graph to flush.  We've seen this
						// take >1s on a heavily-loaded test server so we
						// give it a long timeout.
						time.Sleep(10 * time.Second)
						done <- true
					}()

					// Now drain the output from the output channel.
					tracker := newStateTracker()
					inSyncReceived := false
				readLoop:
					for {
						select {
						case <-done:
							log.Info("Got done message, stopping.")
							Expect(inSyncReceived).To(BeTrue(), "Timed out before we got an in-sync message")
							break readLoop
						case update := <-outputChan:
							log.WithField("update", update).Info("Update from channel")
							Expect(inSyncReceived).To(BeFalse(), "Unexpected update after in-sync")
							tracker.onEvent(update)
							if _, ok := update.(*proto.InSync); ok {
								// InSync should be the last message, to make sure, give
								// the graph another few ms before we stop.
								inSyncReceived = true
								go func() {
									time.Sleep(20 * time.Millisecond)
									done <- true
								}()
							}
						}
					}
					state := test[len(test)-1]

					// Async tests are slower to run so we do all the assertions
					// on each test rather than as separate It() blocks.
					Expect(tracker.ipsets).To(Equal(state.ExpectedIPSets),
						"IP sets didn't match expected state after moving to state: %v",
						state.Name)

					Expect(tracker.activePolicies).To(Equal(state.ExpectedPolicyIDs),
						"Active policy IDs were incorrect after moving to state: %v",
						state.Name)

					Expect(tracker.activeProfiles).To(Equal(state.ExpectedProfileIDs),
						"Active profile IDs were incorrect after moving to state: %v",
						state.Name)

					Expect(tracker.endpointToPolicyOrder).To(Equal(state.ExpectedEndpointPolicyOrder),
						"Endpoint policy order incorrect after moving to state: %v",
						state.Name)
				})
			}
		}
	}
})

type flushStrategy int

const (
	afterEachKV flushStrategy = iota
	afterEachState
	atEnd
)

func doStateSequenceTest(expandedTest StateList, flushStrategy flushStrategy) {
	var validationFilter *ValidationFilter
	var calcGraph *dispatcher.Dispatcher
	var tracker *stateTracker
	var eventBuf *EventSequencer
	var lastState State
	var state State
	var sentInSync bool

	BeforeEach(func() {
		tracker = newStateTracker()
		eventBuf = NewEventBuffer(tracker)
		eventBuf.Callback = tracker.onEvent
		calcGraph = NewCalculationGraph(eventBuf, localHostname)
		validationFilter = NewValidationFilter(calcGraph)
		sentInSync = false
		lastState = empty
		state = empty
	})

	// iterStates iterates through the states in turn,
	// executing the expectation function after each
	// state.
	iterStates := func(expectation func()) func() {
		return func() {
			var ii int
			for ii, state = range expandedTest {
				By(fmt.Sprintf("(%v) Moving from state %#v to %#v",
					ii, lastState.Name, state.Name))
				kvDeltas := state.KVDeltas(lastState)
				for _, kv := range kvDeltas {
					fmt.Fprintf(GinkgoWriter, "       -> Injecting KV: %v\n", kv)
					validationFilter.OnUpdates([]api.Update{kv})
					if flushStrategy == afterEachKV {
						if !sentInSync {
							validationFilter.OnStatusUpdated(api.InSync)
							sentInSync = true
						}
						eventBuf.Flush()
					}
				}
				fmt.Fprintln(GinkgoWriter, "       -- <<FLUSH>>")
				if flushStrategy == afterEachState {
					if !sentInSync {
						validationFilter.OnStatusUpdated(api.InSync)
						sentInSync = true
					}
					eventBuf.Flush()
				}
				if flushStrategy == afterEachState || flushStrategy == afterEachKV {
					expectation()
				}
				lastState = state
			}
		}
	}

	// Note: these used to be separate It() blocks but combining them knocks ~10s off the
	// runtime, which is worthwhile!
	It("should result in correct active state", iterStates(func() {
		Expect(tracker.ipsets).To(Equal(state.ExpectedIPSets),
			"IP sets didn't match expected state after moving to state: %v",
			state.Name)
		Expect(tracker.activePolicies).To(Equal(state.ExpectedPolicyIDs),
			"Active policy IDs were incorrect after moving to state: %v",
			state.Name)
		Expect(tracker.activeProfiles).To(Equal(state.ExpectedProfileIDs),
			"Active profile IDs were incorrect after moving to state: %v",
			state.Name)
		Expect(tracker.endpointToPolicyOrder).To(Equal(state.ExpectedEndpointPolicyOrder),
			"Endpoint policy order incorrect after moving to state: %v",
			state.Name)
		Expect(tracker.endpointToUntrackedPolicyOrder).To(Equal(state.ExpectedUntrackedEndpointPolicyOrder),
			"Untracked endpoint policy order incorrect after moving to state: %v",
			state.Name)
		Expect(tracker.activeUntrackedPolicies).To(Equal(state.ExpectedUntrackedPolicyIDs),
			"Untracked policies incorrect after moving to state: %v",
			state.Name)
	}))
}

type stateTracker struct {
	ipsets                         map[string]set.Set
	activePolicies                 set.Set
	activeUntrackedPolicies        set.Set
	activeProfiles                 set.Set
	endpointToPolicyOrder          map[string][]tierInfo
	endpointToUntrackedPolicyOrder map[string][]tierInfo
	config                         map[string]string
}

func newStateTracker() *stateTracker {
	s := &stateTracker{
		ipsets:                         make(map[string]set.Set),
		activePolicies:                 set.New(),
		activeProfiles:                 set.New(),
		activeUntrackedPolicies:        set.New(),
		endpointToPolicyOrder:          make(map[string][]tierInfo),
		endpointToUntrackedPolicyOrder: make(map[string][]tierInfo),
	}
	return s
}

func (s *stateTracker) onEvent(event interface{}) {
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
		s.ipsets[event.Id] = newMembers
	case *proto.IPSetDeltaUpdate:
		members, ok := s.ipsets[event.Id]
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
		_, ok := s.ipsets[event.Id]
		if !ok {
			Fail(fmt.Sprintf("IP set remove for unknown ipset %v", event.Id))
			return
		}
		delete(s.ipsets, event.Id)
	case *proto.ActivePolicyUpdate:
		// TODO: check rules against expected rules
		policyID := *event.Id
		s.activePolicies.Add(policyID)
		if event.Policy.Untracked {
			s.activeUntrackedPolicies.Add(policyID)
		} else {
			s.activeUntrackedPolicies.Discard(policyID)
		}
	case *proto.ActivePolicyRemove:
		policyID := *event.Id
		s.activePolicies.Discard(policyID)
		s.activeUntrackedPolicies.Discard(policyID)
	case *proto.ActiveProfileUpdate:
		// TODO: check rules against expected rules
		s.activeProfiles.Add(*event.Id)
	case *proto.ActiveProfileRemove:
		s.activeProfiles.Discard(*event.Id)
	case *proto.WorkloadEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]tierInfo, len(tiers))
		for i, tier := range event.Endpoint.Tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].PolicyNames = tier.Policies
		}
		id := workloadId(*event.Id)
		s.endpointToPolicyOrder[id.String()] = tierInfos
		s.endpointToUntrackedPolicyOrder[id.String()] = []tierInfo{}
	case *proto.WorkloadEndpointRemove:
		id := workloadId(*event.Id)
		delete(s.endpointToPolicyOrder, id.String())
		delete(s.endpointToUntrackedPolicyOrder, id.String())
	case *proto.HostEndpointUpdate:
		tiers := event.Endpoint.Tiers
		tierInfos := make([]tierInfo, len(tiers))
		for i, tier := range tiers {
			tierInfos[i].Name = tier.Name
			tierInfos[i].PolicyNames = tier.Policies
		}
		id := hostEpId(*event.Id)
		s.endpointToPolicyOrder[id.String()] = tierInfos

		uTiers := event.Endpoint.UntrackedTiers
		uTierInfos := make([]tierInfo, len(uTiers))
		for i, tier := range uTiers {
			uTierInfos[i].Name = tier.Name
			uTierInfos[i].PolicyNames = tier.Policies
		}
		s.endpointToUntrackedPolicyOrder[id.String()] = uTierInfos
	case *proto.HostEndpointRemove:
		id := hostEpId(*event.Id)
		delete(s.endpointToPolicyOrder, id.String())
		delete(s.endpointToUntrackedPolicyOrder, id.String())
	}
}

func (s *stateTracker) UpdateFrom(map[string]string, config.Source) (changed bool, err error) {
	return
}

func (s *stateTracker) RawValues() map[string]string {
	return s.config
}

type tierInfo struct {
	Name        string
	PolicyNames []string
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
