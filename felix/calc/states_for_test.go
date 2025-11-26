// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.

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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/dataplane/mock"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Canned tiers/policies.

var tier1_order20 = Tier{
	Order: &order20,
}

// Pre-defined datastore states.  Each State object wraps up the complete state
// of the datastore as well as the expected state of the dataplane.  The state
// of the dataplane *should* depend only on the current datastore state, not on
// the path taken to get there.  Therefore, it's always a valid test to move
// from any state to any other state (by feeding in the corresponding
// datastore updates) and then assert that the dataplane matches the resulting
// state.
//
// Notice that most of these pre-defined states are compounded. A small test
// might prefer to start with a simpler state instead.

// empty is the base state, with nothing in the datastore or dataplane.
var empty = NewState().withName("<empty>")

// initialisedStore builds on empty, adding in the ready flag and global config.
var initialisedStore = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "InterfacePrefix"}, Value: "cali"},
	KVPair{Key: ReadyFlagKey{}, Value: true},
).withName("<initialised>")

// withPolicy adds a tier and policy containing selectors for all and b=="b"
var (
	pol1KVPair         = KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20}
	pol1KVPairAlways   = KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_always}
	pol1KVPairOnDemand = KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_ondemand}
)

var withPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: TierKey{Name: "default"}, Value: &tier1_order20},
	pol1KVPair,
).withName("with policy")

var withPolicyAlways = initialisedStore.withKVUpdates(
	pol1KVPairAlways,
).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withIPSet(allSelectorId, []string{}).withIPSet(bEqBSelectorId, []string{}).withName("with always-programmed policy")

// withPolicyIngressOnly adds a tier and ingress policy containing selectors for all
var withPolicyIngressOnly = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_ingress_only},
).withName("with ingress-only policy")

// withPolicyEgressOnly adds a tier and egress policy containing selectors for b=="b"
var withPolicyEgressOnly = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_egress_only},
).withName("with egress-only policy")

// withUntrackedPolicy adds a tier and policy containing selectors for all and b=="b"
var withUntrackedPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_untracked},
).withName("with untracked policy")

// withPreDNATPolicy adds a tier and policy containing selectors for all and a=="a"
var withPreDNATPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pre-dnat-pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_pre_dnat},
).withName("with pre-DNAT policy")

// withHttpMethodPolicy adds a policy containing http method selector.
var withHttpMethodPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_http_match},
).withTotalALPPolicies(
	1,
).withName("with http-method policy")

// withServiceAccountPolicy adds two policies containing service account selector.
var withServiceAccountPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_src_service_account},
	KVPair{Key: PolicyKey{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_dst_service_account},
).withTotalALPPolicies(
	2,
).withName("with service-account policy")

// withNonALPPolicy adds a non ALP policy.
var withNonALPPolicy = withPolicy.withTotalALPPolicies(
	0,
).withName("with non-ALP policy")

// Routes for local workloads.  Most of the tests pre-date route generation so they don't have a
// local host resource; hence we get routes with no next hop.
var routelocalWlTenDotOne = types.RouteUpdate{
	Types:         proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "10.0.0.1/32",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

var routelocalWlTenDotTwo = types.RouteUpdate{
	Types:         proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "10.0.0.2/32",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

var routelocalWlTenDotThree = types.RouteUpdate{
	Types:         proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "10.0.0.3/32",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

var routelocalWlV6ColonOne = types.RouteUpdate{
	Types:         proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "fc00:fe11::1/128",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

var routelocalWlV6ColonTwo = types.RouteUpdate{
	Types:         proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "fc00:fe11::2/128",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

var routelocalWlV6ColonThree = types.RouteUpdate{
	Types:         proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "fc00:fe11::3/128",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

// localEp1WithPolicy adds a local endpoint to the mix.  It matches all and b=="b".
var localEp1WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("ep1 local, policy")

// withPolicyAndTier adds a tier and policy containing selectors for all and b=="b"
var withPolicyAndTier = initialisedStore.withKVUpdates(
	KVPair{Key: TierKey{Name: "tier-1"}, Value: &tier1_order20},
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_tier1_order20},
).withName("with policy")

// localEp1WithPolicyAndTier adds a local endpoint to the mix.  It matches all and b=="b".
var localEp1WithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "tier-1",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("ep1 local, policy with non-default tier")

// localEp2WithPolicyAndTier adds a different endpoint that doesn't match b=="b".
// This tests an empty IP set.
var localEp2WithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(
	bEqBSelectorId, []string{},
).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{
		{
			Name:            "tier-1",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("ep2 local, policy")

// Policy ordering tests.  We keep the names of the policies the same but we
// change their orders to check that order trumps name.
var commLocalEp1WithOneTierPolicy123 = commercialPolicyOrderState(
	[3]float64{order10, order20, order30},
	[3]types.PolicyID{
		{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
	},
)

var commLocalEp1WithOneTierPolicy321 = commercialPolicyOrderState(
	[3]float64{order30, order20, order10},
	[3]types.PolicyID{
		{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
	},
)

var commLocalEp1WithOneTierPolicyAlpha = commercialPolicyOrderState(
	[3]float64{order10, order10, order10},
	[3]types.PolicyID{
		{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
	},
)

func commercialPolicyOrderState(policyOrders [3]float64, expectedIDs [3]types.PolicyID) State {
	policies := [3]Policy{}
	for i := range policies {
		policies[i] = Policy{
			Tier:          "tier-1",
			Order:         &policyOrders[i],
			Selector:      "a == 'a'",
			InboundRules:  []Rule{{SrcSelector: allSelector}},
			OutboundRules: []Rule{{SrcSelector: bEpBSelector}},
		}
	}
	state := initialisedStore.withKVUpdates(
		KVPair{Key: localWlEpKey1, Value: &localWlEp1},
		KVPair{Key: TierKey{Name: "tier-1"}, Value: &tier1_order20},
		KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policies[0]},
		KVPair{Key: PolicyKey{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy}, Value: &policies[1]},
		KVPair{Key: PolicyKey{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy}, Value: &policies[2]},
	).withIPSet(allSelectorId, []string{
		"10.0.0.1/32", // ep1
		"fc00:fe11::1/128",
		"10.0.0.2/32", // ep1 and ep2
		"fc00:fe11::2/128",
	}).withIPSet(bEqBSelectorId, []string{
		"10.0.0.1/32",
		"fc00:fe11::1/128",
		"10.0.0.2/32",
		"fc00:fe11::2/128",
	}).withActivePolicies(
		types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
		types.PolicyID{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		types.PolicyID{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
	).withActiveProfiles(
		types.ProfileID{Name: "prof-1"},
		types.ProfileID{Name: "prof-2"},
		types.ProfileID{Name: "prof-missing"},
	).withEndpoint(
		localWlEp1Id,
		[]mock.TierInfo{
			{
				Name:            "tier-1",
				IngressPolicies: expectedIDs[:],
				EgressPolicies:  expectedIDs[:],
			},
		},
	).withRoutes(
		// Routes for the local WEPs.
		routelocalWlTenDotOne,
		routelocalWlTenDotTwo,
		routelocalWlV6ColonOne,
		routelocalWlV6ColonTwo,
	).withName(fmt.Sprintf("ep1 local, 1 tier, policies %v", expectedIDs[:]))
	return state
}

// Tier ordering tests.  We keep the names of the tiers constant but adjust
// their orders.
var localEp1WithTiers123 = tierOrderState(
	[3]float64{order10, order20, order30},
	[3]string{"tier-1", "tier-2", "tier-3"},
)

var localEp1WithTiers321 = tierOrderState(
	[3]float64{order30, order20, order10},
	[3]string{"tier-3", "tier-2", "tier-1"},
)

// These tests use the same order for each tier, checking that the name is
// used as a tie breaker.
var localEp1WithTiersAlpha = tierOrderState(
	[3]float64{order10, order10, order10},
	[3]string{"tier-1", "tier-2", "tier-3"},
)

var localEp1WithTiersAlpha2 = tierOrderState(
	[3]float64{order20, order20, order20},
	[3]string{"tier-1", "tier-2", "tier-3"},
)

var localEp1WithTiersAlpha3 = tierOrderState(
	[3]float64{order20, order20, order10},
	[3]string{"tier-3", "tier-1", "tier-2"},
)

func tierOrderState(tierOrders [3]float64, expectedOrder [3]string) State {
	tiers := [3]Tier{}
	for i := range tiers {
		tiers[i] = Tier{
			Order: &tierOrders[i],
		}
	}

	// initialize three policies with the same order but different tier names
	pol1Tier1 := policy1_order20
	pol1Tier1.Tier = "tier-1"
	pol1Tier2 := policy1_order20
	pol1Tier2.Tier = "tier-2"
	pol1Tier3 := policy1_order20
	pol1Tier3.Tier = "tier-3"

	state := initialisedStore.withKVUpdates(
		KVPair{Key: localWlEpKey1, Value: &localWlEp1},
		KVPair{Key: TierKey{Name: "tier-1"}, Value: &tiers[0]},
		KVPair{Key: PolicyKey{Name: "tier-1-pol", Kind: v3.KindGlobalNetworkPolicy}, Value: &pol1Tier1},
		KVPair{Key: TierKey{Name: "tier-2"}, Value: &tiers[1]},
		KVPair{Key: PolicyKey{Name: "tier-2-pol", Kind: v3.KindGlobalNetworkPolicy}, Value: &pol1Tier2},
		KVPair{Key: TierKey{Name: "tier-3"}, Value: &tiers[2]},
		KVPair{Key: PolicyKey{Name: "tier-3-pol", Kind: v3.KindGlobalNetworkPolicy}, Value: &pol1Tier3},
	).withIPSet(
		allSelectorId, ep1IPs,
	).withIPSet(
		bEqBSelectorId, ep1IPs,
	).withActivePolicies(
		types.PolicyID{Name: "tier-1-pol", Kind: v3.KindGlobalNetworkPolicy},
		types.PolicyID{Name: "tier-2-pol", Kind: v3.KindGlobalNetworkPolicy},
		types.PolicyID{Name: "tier-3-pol", Kind: v3.KindGlobalNetworkPolicy},
	).withActiveProfiles(
		types.ProfileID{Name: "prof-1"},
		types.ProfileID{Name: "prof-2"},
		types.ProfileID{Name: "prof-missing"},
	).withEndpoint(
		localWlEp1Id,
		[]mock.TierInfo{
			{
				Name:            expectedOrder[0],
				IngressPolicies: []types.PolicyID{{Name: expectedOrder[0] + "-pol", Kind: v3.KindGlobalNetworkPolicy}},
				EgressPolicies:  []types.PolicyID{{Name: expectedOrder[0] + "-pol", Kind: v3.KindGlobalNetworkPolicy}},
			},
			{
				Name:            expectedOrder[1],
				IngressPolicies: []types.PolicyID{{Name: expectedOrder[1] + "-pol", Kind: v3.KindGlobalNetworkPolicy}},
				EgressPolicies:  []types.PolicyID{{Name: expectedOrder[1] + "-pol", Kind: v3.KindGlobalNetworkPolicy}},
			},
			{
				Name:            expectedOrder[2],
				IngressPolicies: []types.PolicyID{{Name: expectedOrder[2] + "-pol", Kind: v3.KindGlobalNetworkPolicy}},
				EgressPolicies:  []types.PolicyID{{Name: expectedOrder[2] + "-pol", Kind: v3.KindGlobalNetworkPolicy}},
			},
		},
	).withRoutes(
		// Routes for the local WEPs.
		routelocalWlTenDotOne,
		routelocalWlTenDotTwo,
		routelocalWlV6ColonOne,
		routelocalWlV6ColonTwo,
	).withName(fmt.Sprintf("tier-order-state%v", expectedOrder[:]))
	return state
}

// localEpsWithPolicyAndTier contains both of the above endpoints, which have some
// overlapping IPs.  When we sequence this with the states above, we test
// overlapping IP addition and removal.
var localEpsWithPolicyAndTier = withPolicyAndTier.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "tier-1",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{
		{
			Name:            "tier-1",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("2 local, overlapping IPs & a policy")

var localEp1WithPolicyAlways = localEp1WithPolicy.withKVUpdates(
	pol1KVPairAlways,
).withName("ep1 local, always policy")

var localEp1WithPolicyOnDemand = localEp1WithPolicy.withKVUpdates(
	pol1KVPairOnDemand,
).withName("ep1 local, on-demand explicit policy")

// localEp1WithNamedPortPolicy as above but with named port in the policy.
var localEp1WithNamedPortPolicy = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_selector_and_named_port_tcpport},
).withIPSet(namedPortAllTCPID, []string{
	"10.0.0.1,tcp:8080",
	"10.0.0.2,tcp:8080",
	"fc00:fe11::1,tcp:8080",
	"fc00:fe11::2,tcp:8080",
}).withIPSet(allSelectorId, nil).withName("ep1 local, named port policy")

// localEp1WithNamedPortPolicy as above but with negated named port in the policy.
var localEp1WithNegatedNamedPortPolicy = empty.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_selector_and_negated_named_port_tcpport},
).withIPSet(namedPortAllLessFoobarTCPID, []string{
	"10.0.0.1,tcp:8080",
	"10.0.0.2,tcp:8080",
	"fc00:fe11::1,tcp:8080",
	"fc00:fe11::2,tcp:8080",
}).withIPSet(allLessFoobarSelectorId, []string{
	// The selector gets filled in because it's needed when doing the negation.
	"10.0.0.1/32",
	"10.0.0.2/32",
	"fc00:fe11::1/128",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("ep1 local, negated named port policy")

// As above but using the destination fields in the policy instead of source.
var localEp1WithNegatedNamedPortPolicyDest = localEp1WithNegatedNamedPortPolicy.withKVUpdates(
	KVPair{
		Key:   PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
		Value: &policy1_order20_with_selector_and_negated_named_port_tcpport_dest,
	},
).withName("ep1 local, negated named port policy in destination fields")

// A host endpoint with a named port
var localHostEp1WithNamedPortPolicy = empty.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithNamedPorts},
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_selector_and_named_port_tcpport},
).withIPSet(namedPortAllTCPID, []string{
	"10.0.0.1,tcp:8080",
	"10.0.0.2,tcp:8080",
	"fc00:fe11::1,tcp:8080",
	"fc00:fe11::2,tcp:8080",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
).withEndpoint(
	"named",
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withName("Host endpoint, named port policy")

// As above but with no selector in the rules.
var localEp1WithNamedPortPolicyNoSelector = localEp1WithNamedPortPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_named_port_tcpport},
).withName("ep1 local, named port only")

// As above but with negated named port.
var localEp1WithNegatedNamedPortPolicyNoSelector = localEp1WithNamedPortPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_named_port_tcpport_negated},
).withName("ep1 local, negated named port only")

// localEp1WithIngressPolicy is as above except ingress policy only.
var localEp1WithIngressPolicy = withPolicyIngressOnly.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  nil,
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("ep1 local, ingress-only policy")

// localEp1WithNamedPortPolicy as above but with UDP named port in the policy.
var localEp1WithNamedPortPolicyUDP = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_selector_and_named_port_udpport},
).withIPSet(namedPortAllUDPID, []string{
	"10.0.0.1,udp:9091",
	"10.0.0.2,udp:9091",
	"fc00:fe11::1,udp:9091",
	"fc00:fe11::2,udp:9091",
}).withIPSet(allSelectorId, nil).withName("ep1 local, named port policy")

var hostEp1WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withName("host ep1, policy")

var hostEp1WithIngressPolicy = withPolicyIngressOnly.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  nil,
		},
	},
).withName("host ep1, ingress-only policy")

var hostEp1WithEgressPolicy = withPolicyEgressOnly.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: nil,
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withName("host ep1, egress-only policy")

var hostEp1WithUntrackedPolicy = withUntrackedPolicy.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withUntrackedPolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]mock.TierInfo{},
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
	[]mock.TierInfo{},
).withName("host ep1, untracked policy")

var hostEp1WithPreDNATPolicy = withPreDNATPolicy.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithName},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pre-dnat-pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withPreDNATPolicies(
	types.PolicyID{Name: "pre-dnat-pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]mock.TierInfo{},
	[]mock.TierInfo{},
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pre-dnat-pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  nil,
		},
	},
).withName("host ep1, pre-DNAT policy")

var hostEp1WithTrackedAndUntrackedPolicy = hostEp1WithUntrackedPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20},
).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
	types.PolicyID{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
).withEndpointUntracked(
	hostEpWithNameId,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
	[]mock.TierInfo{},
).withName("host ep1, tracked+untracked policy")

var hostEp2WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: hostEp2NoNameKey, Value: &hostEp2NoName},
).withIPSet(allSelectorId, []string{
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(bEqBSelectorId, []string{}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
).withEndpoint(
	hostEpNoNameId,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withName("host ep2, policy")

// Policy ordering tests.  We keep the names of the policies the same but we
// change their orders to check that order trumps name.
var localEp1WithOneTierPolicy123 = policyOrderState(
	[3]float64{order10, order20, order30},
	[3]types.PolicyID{
		{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
	},
)

var localEp1WithOneTierPolicy321 = policyOrderState(
	[3]float64{order30, order20, order10},
	[3]types.PolicyID{
		{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
	},
)

var localEp1WithOneTierPolicyAlpha = policyOrderState(
	[3]float64{order10, order10, order10},
	[3]types.PolicyID{
		{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
	},
)

func policyOrderState(policyOrders [3]float64, expectedOrder [3]types.PolicyID) State {
	policies := [3]Policy{}
	for i := range policies {
		policies[i] = Policy{
			Tier:          "default",
			Order:         &policyOrders[i],
			Selector:      "a == 'a'",
			InboundRules:  []Rule{{SrcSelector: allSelector}},
			OutboundRules: []Rule{{SrcSelector: bEpBSelector}},
		}
	}
	state := initialisedStore.withKVUpdates(
		KVPair{Key: localWlEpKey1, Value: &localWlEp1},
		KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policies[0]},
		KVPair{Key: PolicyKey{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy}, Value: &policies[1]},
		KVPair{Key: PolicyKey{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy}, Value: &policies[2]},
	).withIPSet(allSelectorId, []string{
		"10.0.0.1/32", // ep1
		"fc00:fe11::1/128",
		"10.0.0.2/32", // ep1 and ep2
		"fc00:fe11::2/128",
	}).withIPSet(bEqBSelectorId, []string{
		"10.0.0.1/32",
		"fc00:fe11::1/128",
		"10.0.0.2/32",
		"fc00:fe11::2/128",
	}).withActivePolicies(
		types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
		types.PolicyID{Name: "pol-2", Kind: v3.KindGlobalNetworkPolicy},
		types.PolicyID{Name: "pol-3", Kind: v3.KindGlobalNetworkPolicy},
	).withActiveProfiles(
		types.ProfileID{Name: "prof-1"},
		types.ProfileID{Name: "prof-2"},
		types.ProfileID{Name: "prof-missing"},
	).withEndpoint(
		localWlEp1Id,
		[]mock.TierInfo{
			{Name: "default", IngressPolicies: expectedOrder[:], EgressPolicies: expectedOrder[:]},
		},
	).withRoutes(
		// Routes for the local WEPs.
		routelocalWlTenDotOne,
		routelocalWlTenDotTwo,
		routelocalWlV6ColonOne,
		routelocalWlV6ColonTwo,
	).withName(fmt.Sprintf("ep1 local, 1 tier, policies %v", expectedOrder[:]))
	return state
}

// localEp2WithPolicy adds a different endpoint that doesn't match b=="b".
// This tests an empty IP set.
var localEp2WithPolicy = withPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(
	bEqBSelectorId, []string{},
).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("ep2 local, policy")

// localEpsWithPolicy contains both of the above endpoints, which have some
// overlapping IPs.  When we sequence this with the states above, we test
// overlapping IP addition and removal.
var localEpsWithPolicy = withPolicy.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActivePolicies(
	types.PolicyID{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("2 local, overlapping IPs & a policy")

var localEpsWithNamedPortsPolicy = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_selector_and_named_port_tcpport},
).withIPSet(
	allSelectorId, nil,
).withIPSet(namedPortAllTCPID, []string{
	"10.0.0.1,tcp:8080", // ep1
	"fc00:fe11::1,tcp:8080",
	"10.0.0.2,tcp:8080", // ep1 and ep2
	"fc00:fe11::2,tcp:8080",
	"10.0.0.3,tcp:8080", // ep2
	"fc00:fe11::3,tcp:8080",
}).withName("2 local, overlapping IPs & a named port policy")

var localEpsWithNamedPortsPolicyTCPPort2 = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_selector_and_named_port_tcpport2},
).withIPSet(
	allSelectorId, nil,
).withIPSet(namedPortAllTCP2ID, []string{
	"10.0.0.1,tcp:1234", // ep1
	"fc00:fe11::1,tcp:1234",

	"10.0.0.2,tcp:1234", // IP shared between ep1 and ep2 but different port no
	"10.0.0.2,tcp:2345",
	"fc00:fe11::2,tcp:1234",
	"fc00:fe11::2,tcp:2345",

	"10.0.0.3,tcp:2345", // ep2
	"fc00:fe11::3,tcp:2345",
}).withName("2 local, overlapping IPs & a named port policy")

// localEpsWithMismatchedNamedPortsPolicy contains a policy that has named port matches where the
// rule has a protocol that doesn't match that in the named port definitions in the endpoint.
var localEpsWithMismatchedNamedPortsPolicy = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy1_order20_with_named_port_mismatched_protocol},
).withIPSet(
	allSelectorId, nil,
).withIPSet(
	bEqBSelectorId, nil,
).withIPSet(
	namedPortID(allSelector, "udp", "tcpport"), []string{},
).withIPSet(
	namedPortID(allSelector, "tcp", "udpport"), []string{},
).withName("Named ports policy with protocol not matching endpoints")

// In this state, we have a couple of endpoints.  EP1 has a profile, through which it inherits
// a label.
var localEpsWithOverlappingIPsAndInheritedLabels = empty.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-1"}, Value: profileLabels1},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
	types.ProfileID{Name: "prof-missing"},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
)

// Building on the above, we add a policy to match on the inherited label, which should produce
// a named port.
var localEpsAndNamedPortPolicyMatchingInheritedLabelOnEP1 = localEpsWithOverlappingIPsAndInheritedLabels.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "inherit-pol", Kind: v3.KindGlobalNetworkPolicy}, Value: &policy_with_named_port_inherit},
).withActivePolicies(
	types.PolicyID{Name: "inherit-pol", Kind: v3.KindGlobalNetworkPolicy},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{{
		Name:            "default",
		IngressPolicies: []types.PolicyID{{Name: "inherit-pol", Kind: v3.KindGlobalNetworkPolicy}},
		EgressPolicies:  []types.PolicyID{{Name: "inherit-pol", Kind: v3.KindGlobalNetworkPolicy}},
	}},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{{
		Name:            "default",
		IngressPolicies: []types.PolicyID{{Name: "inherit-pol", Kind: v3.KindGlobalNetworkPolicy}},
		EgressPolicies:  []types.PolicyID{{Name: "inherit-pol", Kind: v3.KindGlobalNetworkPolicy}},
	}},
).withIPSet(namedPortInheritIPSetID, []string{
	"10.0.0.1,tcp:8080", // ep1
	"fc00:fe11::1,tcp:8080",
	"10.0.0.2,tcp:8080", // ep1 and ep2
	"fc00:fe11::2,tcp:8080",
	// ep2 doesn't match because it doesn't inherit the profile.
}).withName("2 local WEPs with policy matching inherited label on WEP1")

// Add a second profile with the same labels so that both endpoints now match.
var localEpsAndNamedPortPolicyMatchingInheritedLabelBothEPs = localEpsAndNamedPortPolicyMatchingInheritedLabelOnEP1.withKVUpdates(
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-2"}, Value: profileLabels1},
).withIPSet(namedPortInheritIPSetID, []string{
	"10.0.0.1,tcp:8080", // ep1
	"fc00:fe11::1,tcp:8080",
	"10.0.0.2,tcp:8080", // ep1 and ep2
	"fc00:fe11::2,tcp:8080",
	"10.0.0.3,tcp:8080", // ep2
	"fc00:fe11::3,tcp:8080",
}).withName("2 local WEPs with policy matching inherited label on both WEPs")

// Adjust workload 1 so it has duplicate named ports.
var localEpsAndNamedPortPolicyDuplicatePorts = localEpsAndNamedPortPolicyMatchingInheritedLabelBothEPs.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1WithDupeNamedPorts},
).withIPSet(namedPortInheritIPSetID, []string{
	"10.0.0.1,tcp:8080", // ep1
	"fc00:fe11::1,tcp:8080",
	"10.0.0.1,tcp:8081", // ep1
	"fc00:fe11::1,tcp:8081",
	"10.0.0.1,tcp:8082", // ep1
	"fc00:fe11::1,tcp:8082",
	"10.0.0.2,tcp:8081", // ep1
	"fc00:fe11::2,tcp:8081",
	"10.0.0.2,tcp:8082", // ep1
	"fc00:fe11::2,tcp:8082",

	"10.0.0.2,tcp:8080", // ep1 and ep2
	"fc00:fe11::2,tcp:8080",

	"10.0.0.3,tcp:8080", // ep2
	"fc00:fe11::3,tcp:8080",
}).withName("2 local WEPs with policy and duplicate named port on WEP1")

// Then, change the label on EP2 so it no-longer matches.
var localEpsAndNamedPortPolicyNoLongerMatchingInheritedLabelOnEP2 = localEpsAndNamedPortPolicyMatchingInheritedLabelBothEPs.withKVUpdates(
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-2"}, Value: profileLabels2},
).withIPSet(namedPortInheritIPSetID, []string{
	"10.0.0.1,tcp:8080", // ep1
	"fc00:fe11::1,tcp:8080",
	"10.0.0.2,tcp:8080", // ep1 and ep2
	"fc00:fe11::2,tcp:8080",
	// ep2 no longer matches
}).withName("2 local WEPs with policy matching inherited label on WEP1; WEP2 has different label")

// Then, change the label on EP1 so it no-longer matches.
var localEpsAndNamedPortPolicyNoLongerMatchingInheritedLabelOnEP1 = localEpsAndNamedPortPolicyNoLongerMatchingInheritedLabelOnEP2.withKVUpdates(
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-1"}, Value: profileLabels2},
).withIPSet(namedPortInheritIPSetID, []string{
	// No longer any matches.
}).withName("2 local WEPs with policy not matching inherited labels")

// Alternatively, prevent EP2 from matching by removing its profiles.
var localEpsAndNamedPortPolicyEP2ProfileRemoved = localEpsAndNamedPortPolicyMatchingInheritedLabelBothEPs.withKVUpdates(
	KVPair{Key: localWlEpKey2, Value: &localWlEp2WithLabelsButNoProfiles},
).withIPSet(namedPortInheritIPSetID, []string{
	"10.0.0.1,tcp:8080", // ep1
	"fc00:fe11::1,tcp:8080",
	"10.0.0.2,tcp:8080", // ep1 and ep2
	"fc00:fe11::2,tcp:8080",
	// ep2 no longer matches
}).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withName("2 local WEPs with policy matching inherited label on WEP1; WEP2 has no profile")

// Then do the same for EP1.
var localEpsAndNamedPortPolicyBothEPsProfilesRemoved = localEpsAndNamedPortPolicyEP2ProfileRemoved.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1WithLabelsButNoProfiles},
).withIPSet(namedPortInheritIPSetID, []string{
	// Neither EP matches.
}).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withActiveProfiles().withName("2 local WEPs with no matches due to removing profiles from endpoints")

// localEpsWithPolicyUpdatedIPs, when used with localEpsWithPolicy checks
// correct handling of IP address updates.  We add and remove some IPs from
// endpoint 1 and check that only its non-shared IPs are removed from the IP
// sets.
var localEpsWithPolicyUpdatedIPs = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1DifferentIPs},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"11.0.0.1/32", // ep1
	"fc00:fe12::1/128",
	"11.0.0.2/32",
	"fc00:fe12::2/128",
	"10.0.0.2/32", // now ep2 only
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(bEqBSelectorId, []string{
	"11.0.0.1/32", // ep1
	"fc00:fe12::1/128",
	"11.0.0.2/32",
	"fc00:fe12::2/128",
}).withRoutes(
	// Routes for the local WEPs.
	types.RouteUpdate{
		Types:         proto.RouteType_LOCAL_WORKLOAD,
		Dst:           "11.0.0.1/32",
		DstNodeName:   localHostname,
		LocalWorkload: true,
	},
	types.RouteUpdate{
		Types:         proto.RouteType_LOCAL_WORKLOAD,
		Dst:           "11.0.0.2/32",
		DstNodeName:   localHostname,
		LocalWorkload: true,
	},
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	types.RouteUpdate{
		Types:         proto.RouteType_LOCAL_WORKLOAD,
		Dst:           "fc00:fe12::1/128",
		DstNodeName:   localHostname,
		LocalWorkload: true,
	},
	types.RouteUpdate{
		Types:         proto.RouteType_LOCAL_WORKLOAD,
		Dst:           "fc00:fe12::2/128",
		DstNodeName:   localHostname,
		LocalWorkload: true,
	},
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("2 local, non-overlapping IPs")

// withProfile adds a profile to the initialised state.
var withProfile = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey: ProfileKey{Name: "prof-1"}}, Value: &profileRules1},
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-1"}, Value: profileLabels1Tag1},
).withName("profile")

// localEpsWithProfile contains a pair of overlapping IP endpoints and a profile
// that matches them both.
var localEpsWithProfile = withProfile.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"10.0.0.3/32", // ep2
	"fc00:fe11::3/128",
}).withIPSet(tag1LabelID, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("2 local, overlapping IPs & a profile")

// localEpsWithNonMatchingProfile contains a pair of overlapping IP endpoints and a profile
// that matches them both.
var localEpsWithNonMatchingProfile = withProfile.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1NoProfiles},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2NoProfiles},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("2 local, overlapping IPs & a non-matching profile")

// localEpsWithUpdatedProfile Follows on from localEpsWithProfile, changing the
// profile to use a different tag and selector.
var localEpsWithUpdatedProfile = localEpsWithProfile.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey: ProfileKey{Name: "prof-1"}}, Value: &profileRules1TagUpdate},
).withIPSet(
	tag1LabelID, nil,
).withIPSet(
	allSelectorId, nil,
).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
}).withIPSet(
	tag2LabelID, []string{},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{},
).withName("2 local, overlapping IPs & updated profile")

var localEpsWithUpdatedProfileNegatedTags = localEpsWithUpdatedProfile.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey: ProfileKey{Name: "prof-1"}}, Value: &profileRules1NegatedTagSelUpdate},
)

// withProfileTagInherit adds a profile that includes rules that match on
// tags as labels.  I.e. a tag of name foo should be equivalent to label foo=""
var withProfileTagInherit = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey: ProfileKey{Name: "prof-1"}}, Value: &profileRulesWithTagInherit},
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-1"}, Value: profileLabels1Tag1},
).withName("profile")

var localEpsWithTagInheritProfile = withProfileTagInherit.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(tagSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withIPSet(
	tagFoobarSelectorId, []string{},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id, []mock.TierInfo{},
).withEndpoint(
	localWlEp2Id, []mock.TierInfo{},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("2 local, overlapping IPs & a tag inherit profile")

var withProfileTagOverridden = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey: ProfileKey{Name: "prof-1"}}, Value: &profileRulesWithTagInherit},
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-1"}, Value: profileLabelsTag1},
).withName("profile")

// localEpsWithTagOverriddenProfile Checks that tags-inherited labels can be
// overridden by explicit labels on the profile.
var localEpsWithTagOverriddenProfile = withProfileTagOverridden.withKVUpdates(
	// Two local endpoints with overlapping IPs.
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: localWlEpKey2, Value: &localWlEp2},
).withIPSet(tagSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withIPSet(tagFoobarSelectorId, []string{
	"10.0.0.1/32", // ep1
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
}).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-3"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
	routelocalWlV6ColonThree,
).withName("2 local, overlapping IPs & a tag inherit profile")

var hostEp1WithPolicyAndANetworkSet = hostEp1WithPolicy.withKVUpdates(
	KVPair{Key: netSet1Key, Value: &netSet1},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1 and net set.
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"12.0.0.0/24",
	"12.1.0.0/24",
	"feed:beef::/32",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
})

var hostEp1WithPolicyAndTwoNetworkSets = hostEp1WithPolicyAndANetworkSet.withKVUpdates(
	KVPair{Key: netSet2Key, Value: &netSet2},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
	"12.0.0.0/24", // Shared by both net sets.
	"12.1.0.0/24",
	"feed:beef::/32",
	"13.1.0.0/24", // Unique to netset-2
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
})

var hostEp1WithPolicyAndANetworkSetMatchingBEqB = hostEp1WithPolicy.withKVUpdates(
	KVPair{Key: netSet1Key, Value: &netSet1WithBEqB},
).withIPSet(allSelectorId, []string{
	"10.0.0.1/32", // ep1 and net set.
	"fc00:fe11::1/128",
	"10.0.0.2/32", // ep1 and ep2
	"fc00:fe11::2/128",
	"12.0.0.0/24",
	"12.1.0.0/24",
}).withIPSet(bEqBSelectorId, []string{
	"10.0.0.1/32",
	"fc00:fe11::1/128",
	"10.0.0.2/32",
	"fc00:fe11::2/128",
	"12.0.0.0/24",
	"12.1.0.0/24",
})

// RouteUpdate expected for ipPoolWithVXLAN.
var routeUpdateIPPoolVXLAN = types.RouteUpdate{
	Types:       proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPoolWithVXLAN.CIDR.String(),
	NatOutgoing: ipPoolWithVXLAN.Masquerade,
}

// RouteUpdate expected for ipPool2WithVXLAN.
var routeUpdateIPPool2VXLAN = types.RouteUpdate{
	Types:       proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPool2WithVXLAN.CIDR.String(),
	NatOutgoing: ipPool2WithVXLAN.Masquerade,
}

// RouteUpdate expected for ipPoolWithVXLANSlash32.
var routeUpdateIPPoolVXLANSlash32 = types.RouteUpdate{
	Types:       proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPoolWithVXLANSlash32.CIDR.String(),
	NatOutgoing: ipPoolWithVXLANSlash32.Masquerade,
}

// RouteUpdate expected for ipPoolWithVXLANCrossSubnet.
var routeUpdateIPPoolVXLANCrossSubnet = types.RouteUpdate{
	Types:       proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPoolWithVXLANCrossSubnet.CIDR.String(),
	NatOutgoing: ipPoolWithVXLANCrossSubnet.Masquerade,
}

// RouteUpdate expected for v6IPPoolWithVXLAN.
var routeUpdateV6IPPoolVXLAN = types.RouteUpdate{
	Types:       proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         v6IPPoolWithVXLAN.CIDR.String(),
	NatOutgoing: v6IPPoolWithVXLAN.Masquerade,
}

// RouteUpdate expected for ipPoolWithIPIP.
var routeUpdateIPPoolIPIP = types.RouteUpdate{
	Types:       proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_IPIP,
	Dst:         ipPoolWithIPIP.CIDR.String(),
	NatOutgoing: ipPoolWithIPIP.Masquerade,
}

// RouteUpdate expected for the remote host with its normal IP.
var routeUpdateRemoteHost = types.RouteUpdate{
	Types:       proto.RouteType_REMOTE_HOST,
	IpPoolType:  proto.IPPoolType_NONE,
	Dst:         remoteHostIP.String() + "/32",
	DstNodeName: remoteHostname,
	DstNodeIp:   remoteHostIP.String(),
}

// RouteUpdate expected for the second remote host.
var routeUpdateRemoteHost2 = types.RouteUpdate{
	Types:       proto.RouteType_REMOTE_HOST,
	IpPoolType:  proto.IPPoolType_NONE,
	Dst:         remoteHost2IP.String() + "/32",
	DstNodeName: remoteHostname2,
	DstNodeIp:   remoteHost2IP.String(),
}

// RouteUpdate expected for the remote host with its normal IPv6 address.
var routeUpdateRemoteHostV6 = types.RouteUpdate{
	Types:       proto.RouteType_REMOTE_HOST,
	IpPoolType:  proto.IPPoolType_NONE,
	Dst:         remoteHostIPv6.String() + "/128",
	DstNodeName: remoteHostname,
	DstNodeIp:   remoteHostIPv6.String(),
}

// Minimal VXLAN set-up using WorkloadIPs for routing information rather than using
// IPAM blocks. Includes remoteHost2
var vxlanWithWEPIPs = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "RouteSource"}, Value: &workloadIPs},
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLAN},
	KVPair{Key: remoteHost2IPKey, Value: &remoteHost2IP},
	KVPair{Key: remoteHost2VXLANTunnelConfigKey, Value: remoteHost2VXLANTunnelIP},
).withName("VXLAN using WorkloadIPs").withVTEPs(
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname2,
		Mac:            "66:40:18:59:1f:16",
		Ipv4Addr:       remoteHost2VXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost2,
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: false},
)

// Adds in an workload on remoteHost2 and expected route.
var vxlanWithWEPIPsAndWEP = vxlanWithWEPIPs.withKVUpdates(
	KVPair{Key: remoteWlEpKey2, Value: &remoteWlEp1},
).withName("VXLAN using WorkloadIPs and a WEP").withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost2,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.5/32",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
	},
)

// Add in another workload with the same IP, but on a different node - remoteHost1.
// Since this new host sorts lower than the original, its should mask the route of the
// WEP on the other node.
var vxlanWithWEPIPsAndWEPDuplicate = vxlanWithWEPIPsAndWEP.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
	KVPair{Key: remoteWlEpKey1, Value: &remoteWlEp1},
).withName("VXLAN using WorkloadIPs and overlapping WEPs").withVTEPs(
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname2,
		Mac:            "66:40:18:59:1f:16",
		Ipv4Addr:       remoteHost2VXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	routeUpdateRemoteHost2,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.5/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
)

// Minimal VXLAN set-up using Calico IPAM, all the data needed for a remote VTEP, a pool and a block.
var vxlanWithBlock = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLAN},
	KVPair{Key: remoteIPAMBlockKey, Value: &remoteIPAMBlock},
	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
).withName("VXLAN").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: false},
).withRoutes(vxlanWithBlockRoutes...)

var vxlanWithBlockRoutes = []types.RouteUpdate{
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	// Single route for the block.
	{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
}

var (
	remoteNodeResKey = ResourceKey{Name: remoteHostname, Kind: apiv3.KindNode}
	localNodeResKey  = ResourceKey{Name: localHostname, Kind: apiv3.KindNode}
)

// As vxlanWithBlock but with a host sharing the same IP.  No route update because we tie-break on host name.
var vxlanWithBlockDupNodeIP = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHost2IPKey, Value: &remoteHostIP},
).withName("VXLAN with dup node IP")

var vxlanWithDupNodeIPRemoved = vxlanWithBlockDupNodeIP.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: nil},
).withName("VXLAN with dup node IP removed").withVTEPs().withRoutes(
	routeUpdateIPPoolVXLAN,
	// Remote host 2 but with remotehost's IP:
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         remoteHostIP.String() + "/32",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHostIP.String(),
	},
	// Single route for the block.  No IP because the block belongs to remotehost and its IP was
	// removed.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
)

// As vxlanWithBlock but with node resources instead of host IPs.
var vxlanWithBlockNodeRes = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: nil},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: remoteHostIP.String() + "/24",
		}},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIP.String() + "/24",
	},
).withName("VXLAN with node resource (node resources)")

// As vxlanWithBlock but with some superfluous IPv6 resources (VXLAN is IPv4 only).
var vxlanWithIPv6Resources = vxlanWithBlock.withKVUpdates(
	KVPair{Key: v6IPPoolKey, Value: &v6IPPool},
	KVPair{Key: remotev6IPAMBlockKey, Value: &remotev6IPAMBlock},
).withRoutes(
	append(vxlanWithBlockRoutes,
		types.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_NO_ENCAP,
			Dst:         "feed:beef:0:0:1::/96",
			DstNodeName: remoteHostname,
		},
		types.RouteUpdate{
			Types:      proto.RouteType_CIDR_INFO,
			IpPoolType: proto.IPPoolType_NO_ENCAP,
			Dst:        "feed:beef::/64",
		},
	)...,
).withName("VXLAN with IPv6 Resources")

// Minimal VXLAN set-up with a MAC address override for the remote node.
var vxlanWithMAC = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelMACConfigKey, Value: remoteHostVXLANTunnelMAC},
).withName("VXLAN MAC").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            remoteHostVXLANTunnelMAC,
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
)

// As vxlanWithBlock but with a more complex block.  The block has some allocated IPs on the same
// node as well as one that's borrowed by a second node.  We add the extra VTEP config for the
// other node.
var vxlanWithBlockAndBorrows = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteIPAMBlockKey, Value: &remoteIPAMBlockWithBorrows},
	KVPair{Key: remoteHost2IPKey, Value: &remoteHost2IP},
	KVPair{Key: remoteHost2VXLANTunnelConfigKey, Value: remoteHost2VXLANTunnelIP},
).withName("VXLAN borrow").withVTEPs(
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname2,
		Mac:            "66:40:18:59:1f:16",
		Ipv4Addr:       remoteHost2VXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	routeUpdateRemoteHost2,
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.2/32",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
		Borrowed:    true,
	},
)

// vxlanWithBlock but with a different tunnel IP.
var vxlanWithBlockAndDifferentTunnelIP = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP2},
).withName("VXLAN different tunnel IP").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP2,
		ParentDeviceIp: remoteHostIP.String(),
	},
)

// vxlanWithBlock but with a different node IP.
var vxlanWithBlockAndDifferentNodeIP = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: &remoteHost2IP},
).withName("VXLAN different node IP").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         remoteHost2IP.String() + "/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHost2IP.String(),
	},
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
	},
)

// As vxlanWithBlockAndBorrows but with the owner of the block and the borrows switched.
var vxlanBlockOwnerSwitch = vxlanWithBlockAndBorrows.withKVUpdates(
	KVPair{Key: remoteIPAMBlockKey, Value: &remoteIPAMBlockWithBorrowsSwitched},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	routeUpdateRemoteHost2,
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
	},
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
		Borrowed:    true,
	},
).withName("VXLAN owner switch")

// VXLAN set-up with local block.
var vxlanLocalBlockWithBorrows = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLAN},

	KVPair{Key: localHostIPKey, Value: &localHostIP},
	KVPair{Key: localHostVXLANTunnelConfigKey, Value: localHostVXLANTunnelIP},

	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},

	KVPair{Key: localIPAMBlockKey, Value: &localIPAMBlockWithBorrows},
).withVTEPs(
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
	types.VXLANTunnelEndpointUpdate{
		Node:           localHostname,
		Mac:            "66:48:f6:56:dc:f1",
		Ipv4Addr:       localHostVXLANTunnelIP,
		ParentDeviceIp: localHostIP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		NatOutgoing: true,
	},
	types.RouteUpdate{
		// Route for the borrowed IP - this is marked remote because the pod is hosted on a remote node,
		// but also marked as local because it's borrowed from a block on the local node.
		Types:       proto.RouteType_REMOTE_WORKLOAD | proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
		Borrowed:    true,
	},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: false},
)

var localVXLANWep1Route1 = types.RouteUpdate{
	Types:         proto.RouteType_LOCAL_WORKLOAD,
	IpPoolType:    proto.IPPoolType_VXLAN,
	Dst:           "10.0.0.1/32",
	DstNodeName:   localHostname,
	DstNodeIp:     localHostIP.String(),
	NatOutgoing:   true,
	LocalWorkload: true,
}

var localVXLANWep1Route2 = types.RouteUpdate{
	// The IPAM block 10.0.0.0/29 is assigned to the local host, but the IPAM
	// block attributes mark 10.0.0.2/32 as borrowed by a remote host.
	Types:         proto.RouteType_REMOTE_WORKLOAD | proto.RouteType_LOCAL_WORKLOAD,
	IpPoolType:    proto.IPPoolType_VXLAN,
	Dst:           "10.0.0.2/32",
	DstNodeName:   localHostname,
	DstNodeIp:     localHostIP.String(),
	NatOutgoing:   true,
	LocalWorkload: true,
	Borrowed:      true,
}

// As vxlanLocalBlockWithBorrows but with a local workload.  The local workload has an IP that overlaps with
// the remote workload, we take that in preference to the remote route.
var vxlanLocalBlockWithBorrowsLocalWEP = vxlanLocalBlockWithBorrows.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		NatOutgoing: true,
	},
	// Plus individual routes for the local WEPs.
	localVXLANWep1Route1,
	localVXLANWep1Route2,
	// Plus V6 workloads
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withName("VXLAN local with borrows with local WEP override").withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withEndpoint("orch/wl1/ep1", []mock.TierInfo{})

// As vxlanLocalBlockWithBorrows but using Node resources instead of host IPs.
var vxlanLocalBlockWithBorrowsNodeRes = vxlanLocalBlockWithBorrows.withKVUpdates(
	KVPair{Key: localHostIPKey, Value: nil},
	KVPair{Key: remoteHostIPKey, Value: nil},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: remoteHostIPWithPrefix,
		}},
	}},
	KVPair{Key: localNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: localHostIPWithPrefix,
		}},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIPWithPrefix,
	},
	&proto.HostMetadataV4V6Update{
		Hostname: localHostname,
		Ipv4Addr: localHostIPWithPrefix,
	},
).withName("VXLAN local with borrows (node resources)")

// As vxlanLocalBlockWithBorrowsNodeRes using the cross-subnet version of the IP pool.
// Hosts are in the same subnet.
var vxlanLocalBlockWithBorrowsCrossSubnetNodeRes = vxlanLocalBlockWithBorrowsNodeRes.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLANCrossSubnet},
).withRoutes(
	routeUpdateIPPoolVXLANCrossSubnet,
	routeUpdateRemoteHost,
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		SameSubnet:  true, // cross subnet.
	},
	types.RouteUpdate{
		// Route for the borrowed IP - this is marked remote because the pod is hosted on a remote node,
		// but also marked as local because it's borrowed from a block on the local node.
		Types:       proto.RouteType_REMOTE_WORKLOAD | proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		SameSubnet:  true, // cross subnet.
		Borrowed:    true,
	},
).withName("VXLAN local with borrows cross subnet (node resources)")

// As vxlanLocalBlockWithBorrowsCrossSubnetNodeRes but hosts are in a different pool.
var vxlanLocalBlockWithBorrowsDifferentSubnetNodeRes = vxlanLocalBlockWithBorrowsNodeRes.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLANCrossSubnet},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: remoteHostIP.String(), // Omitting the /32 here to check the v3 validator is used for this resource.
		}},
	}},
	KVPair{Key: localNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: localHostIP.String() + "/32",
		}},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
	},
	&proto.HostMetadataV4V6Update{
		Hostname: localHostname,
		Ipv4Addr: localHostIP.String() + "/32",
	},
).withRoutes(
	routeUpdateIPPoolVXLANCrossSubnet,
	routeUpdateRemoteHost,
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		SameSubnet:  true, // cross subnet.
	},
	types.RouteUpdate{
		// Route for the borrowed IP - this is marked remote because the pod is hosted on a remote node,
		// but also marked as local because it's borrowed from a block on the local node.
		Types:       proto.RouteType_REMOTE_WORKLOAD | proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		SameSubnet:  false, // subnets don't match.
		Borrowed:    true,
	},
).withName("VXLAN cross subnet different subnet (node resources)")

// vxlanWithBlockAndBorrows but missing the VTEP information for the first host.
var vxlanWithBlockAndBorrowsAndMissingFirstVTEP = vxlanWithBlockAndBorrows.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: nil},
).withName("VXLAN borrow missing VTEP").withVTEPs(
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname2,
		Mac:            "66:40:18:59:1f:16",
		Ipv4Addr:       remoteHost2VXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost2,
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.2/32",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
		Borrowed:    true,
	},
)

// As vxlanWithBlock but with the IP pool switched to IPIP mode.
var vxlanToIPIPSwitch = vxlanWithBlock.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithIPIP},
).withName("VXLAN switched to IPIP").withRoutes(
	routeUpdateIPPoolIPIP,
	routeUpdateRemoteHost,
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_IPIP,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
	},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: true, VxlanEnabled: false, VxlanEnabledV6: false},
)

var vxlanBlockDelete = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteIPAMBlockKey, Value: nil},
).withName("VXLAN block removed").withRoutes(
	// VXLAN block route removed but still keep the IP pool and host routes.
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
).withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
)

var vxlanHostIPDelete = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: nil},
).withName("VXLAN host IP removed").withRoutes(
	routeUpdateIPPoolVXLAN,
	// Host removed but keep the route without the node IP.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   "",
		NatOutgoing: true,
	},
).withVTEPs()

var vxlanTunnelIPDelete = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: nil},
).withName("VXLAN tunnel IP removed").withVTEPs()

// Corner case: VXLAN set-up where the IP pool and block are both /32s.
var vxlanSlash32 = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLANSlash32},
	KVPair{Key: remoteIPAMSlash32BlockKey, Value: &remoteIPAMBlockSlash32},
	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
).withName("VXLAN /32").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	// No CIDR_INFO route, it gets subsumed into the REMOTE_WORKLOAD one.
	routeUpdateRemoteHost,
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: false},
)

var vxlanSlash32NoBlock = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLANSlash32},
	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
).withName("VXLAN /32 no block").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLANSlash32,
	routeUpdateRemoteHost,
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: false},
)

var vxlanSlash32NoPool = empty.withKVUpdates(
	KVPair{Key: remoteIPAMSlash32BlockKey, Value: &remoteIPAMBlockSlash32},
	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
).withName("VXLAN /32 no pool").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	routeUpdateRemoteHost,
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "10.0.0.0/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
	},
)

// Minimal IPv6 VXLAN set-up using Calico IPAM, all the data needed for a remote VTEP, a pool and a block.
var vxlanV6WithBlock = empty.withKVUpdates(
	KVPair{Key: v6IPPoolKey, Value: &v6IPPoolWithVXLAN},
	KVPair{Key: remotev6IPAMBlockKey, Value: &remotev6IPAMBlock},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv6Address: remoteHostIPv6.String() + "/96",
		}},
	}},
	KVPair{Key: remoteHostVXLANV6TunnelConfigKey, Value: remoteHostVXLANV6TunnelIP},
).withName("VXLAN IPv6").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: false, VxlanEnabledV6: true},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv6Addr: remoteHostIPv6.String() + "/96",
	},
).withRoutes(vxlanV6WithBlockRoutes...)

var vxlanV6WithBlockRoutes = []types.RouteUpdate{
	routeUpdateV6IPPoolVXLAN,
	routeUpdateRemoteHostV6,
	// Single route for the block.
	{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "feed:beef:0:0:1::/96",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIPv6.String(),
		NatOutgoing: true,
	},
}

var vxlanV6BlockDelete = vxlanV6WithBlock.withKVUpdates(
	KVPair{Key: remotev6IPAMBlockKey, Value: nil},
).withName("VXLAN IPv6 block removed").withRoutes(
	// VXLAN block route removed but still keep the IP pool and host routes.
	routeUpdateV6IPPoolVXLAN,
	routeUpdateRemoteHostV6,
).withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

var vxlanV6NodeResIPDelete = vxlanV6WithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{}},
	}},
).withHostMetadataV4V6().withName("VXLAN IPv6 Node Resource IP removed").withRoutes(
	routeUpdateV6IPPoolVXLAN,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "feed:beef:0:0:1::/96",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
).withVTEPs()

var vxlanV6NodeResBGPDelete = vxlanV6WithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: nil},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
	},
).withName("VXLAN IPv6 Node Resource BGP removed").withRoutes(
	routeUpdateV6IPPoolVXLAN,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "feed:beef:0:0:1::/96",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
).withVTEPs()

var vxlanV6NodeResDelete = vxlanV6WithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: nil},
).withHostMetadataV4V6().withName("VXLAN IPv6 Node Resource removed").withRoutes(
	routeUpdateV6IPPoolVXLAN,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "feed:beef:0:0:1::/96",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
).withVTEPs()

var vxlanV6TunnelIPDelete = vxlanV6WithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANV6TunnelConfigKey, Value: nil},
).withName("VXLAN IPv6 tunnel IP removed").withVTEPs()

var vxlanV6WithMAC = vxlanV6WithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANV6TunnelMACConfigKey, Value: remoteHostVXLANV6TunnelMAC},
).withName("VXLAN IPv6 with MAC").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		MacV6:            remoteHostVXLANV6TunnelMAC,
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

// IPv4+IPv6 VXLAN (dual stack)
var vxlanV4V6WithBlock = empty.withKVUpdates(
	KVPair{Key: v6IPPoolKey, Value: &v6IPPoolWithVXLAN},
	KVPair{Key: remotev6IPAMBlockKey, Value: &remotev6IPAMBlock},
	KVPair{Key: remoteHostVXLANV6TunnelConfigKey, Value: remoteHostVXLANV6TunnelIP},
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLAN},
	KVPair{Key: remoteIPAMBlockKey, Value: &remoteIPAMBlock},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: remoteHostIP.String() + "/24",
			IPv6Address: remoteHostIPv6.String() + "/96",
		}},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIP.String() + "/24",
		Ipv6Addr: remoteHostIPv6.String() + "/96",
	},
).withName("VXLAN IPv4+IPv6").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		Mac:              "66:3e:ca:a4:db:65",
		Ipv4Addr:         remoteHostVXLANTunnelIP,
		ParentDeviceIp:   remoteHostIP.String(),
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: true},
).withRoutes(append(vxlanWithBlockRoutes, vxlanV6WithBlockRoutes...)...)

var vxlanV4V6BlockV6Delete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remotev6IPAMBlockKey, Value: nil},
).withName("VXLAN IPv4+IPv6 with IPv6 block removed").withRoutes(
	append(vxlanWithBlockRoutes,
		routeUpdateV6IPPoolVXLAN,
		routeUpdateRemoteHostV6)...,
).withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		Mac:              "66:3e:ca:a4:db:65",
		Ipv4Addr:         remoteHostVXLANTunnelIP,
		ParentDeviceIp:   remoteHostIP.String(),
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

var vxlanV4V6BlockV4Delete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteIPAMBlockKey, Value: nil},
).withName("VXLAN IPv4+IPv6 with IPv4 block removed").withRoutes(
	// VXLAN block route removed but still keep the IP pool and host routes.
	append(vxlanV6WithBlockRoutes,
		routeUpdateIPPoolVXLAN,
		routeUpdateRemoteHost)...,
).withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		Mac:              "66:3e:ca:a4:db:65",
		Ipv4Addr:         remoteHostVXLANTunnelIP,
		ParentDeviceIp:   remoteHostIP.String(),
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

var vxlanV4V6NodeResIPv4Delete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv6Address: remoteHostIPv6.String() + "/96",
		}},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv6Addr: remoteHostIPv6.String() + "/96",
	},
).withName("VXLAN IPv4+IPv6 Node Resource IPv4 removed").withRoutes(
	append(vxlanV6WithBlockRoutes,
		routeUpdateIPPoolVXLAN,
		// Host removed but keep the route without the node IP.
		types.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "10.0.1.0/29",
			DstNodeName: remoteHostname,
			DstNodeIp:   "",
			NatOutgoing: true,
		})...,
).withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

var vxlanV4V6NodeResIPv6Delete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: remoteHostIP.String() + "/24",
		}},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIP.String() + "/24",
	},
).withName("VXLAN IPv4+IPv6 Node Resource IPv6 removed").withRoutes(
	append(vxlanWithBlockRoutes,
		routeUpdateV6IPPoolVXLAN,
		types.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_VXLAN,
			Dst:         "feed:beef:0:0:1::/96",
			DstNodeName: remoteHostname,
			NatOutgoing: true,
		})...,
).withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
)

var vxlanV4V6NodeResBGPDelete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{BGP: nil},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
	},
).withName("VXLAN IPv4+IPv6 Node Resource BGP removed").withRoutes(
	routeUpdateIPPoolVXLAN,
	// Host removed but keep the route without the node IP.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   "",
		NatOutgoing: true,
	},
	routeUpdateV6IPPoolVXLAN,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "feed:beef:0:0:1::/96",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
).withVTEPs()

var vxlanV4V6NodeResDelete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: nil},
).withHostMetadataV4V6().withName("VXLAN IPv4+IPv6 Node Resource removed").withRoutes(
	routeUpdateIPPoolVXLAN,
	// Host removed but keep the route without the node IP.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   "",
		NatOutgoing: true,
	},
	routeUpdateV6IPPoolVXLAN,
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "feed:beef:0:0:1::/96",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
).withVTEPs()

var vxlanV4V6TunnelIPv4Delete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: nil},
).withName("VXLAN IPv4+IPv6 tunnel IPv4 removed").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

var vxlanV4V6TunnelIPv6Delete = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANV6TunnelConfigKey, Value: nil},
).withName("VXLAN IPv4+IPv6 tunnel IPv6 removed").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
)

var vxlanV4V6WithMAC = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelMACConfigKey, Value: remoteHostVXLANTunnelMAC},
	KVPair{Key: remoteHostVXLANV6TunnelMACConfigKey, Value: remoteHostVXLANV6TunnelMAC},
).withName("VXLAN IPv4+IPv6 with IPv4+IPv6 MAC").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		Mac:              remoteHostVXLANTunnelMAC,
		Ipv4Addr:         remoteHostVXLANTunnelIP,
		ParentDeviceIp:   remoteHostIP.String(),
		MacV6:            remoteHostVXLANV6TunnelMAC,
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

var vxlanV4V6WithV4MAC = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelMACConfigKey, Value: remoteHostVXLANTunnelMAC},
).withName("VXLAN IPv4+IPv6 with IPv4+IPv6 MAC").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		Mac:              remoteHostVXLANTunnelMAC,
		Ipv4Addr:         remoteHostVXLANTunnelIP,
		ParentDeviceIp:   remoteHostIP.String(),
		MacV6:            "66:a0:68:c9:4c:79",
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

var vxlanV4V6WithV6MAC = vxlanV4V6WithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANV6TunnelMACConfigKey, Value: remoteHostVXLANV6TunnelMAC},
).withName("VXLAN IPv4+IPv6 with IPv4+IPv6 MAC").withVTEPs(
	// VTEP for the remote node.
	types.VXLANTunnelEndpointUpdate{
		Node:             remoteHostname,
		Mac:              "66:3e:ca:a4:db:65",
		Ipv4Addr:         remoteHostVXLANTunnelIP,
		ParentDeviceIp:   remoteHostIP.String(),
		MacV6:            remoteHostVXLANV6TunnelMAC,
		Ipv6Addr:         remoteHostVXLANV6TunnelIP,
		ParentDeviceIpv6: remoteHostIPv6.String(),
	},
)

// Corner case: host inside an IP pool.
var hostInIPPool = vxlanWithBlock.withKVUpdates(
	KVPair{Key: hostCoveringIPPoolKey, Value: &hostCoveringIPPool},
).withName("host in IP pool").withRoutes(
	routeUpdateIPPoolVXLAN,
	types.RouteUpdate{
		Types:       proto.RouteType_CIDR_INFO,
		IpPoolType:  proto.IPPoolType_NO_ENCAP,
		Dst:         hostCoveringIPPool.CIDR.String(),
		NatOutgoing: true,
	},
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_HOST,
		IpPoolType:  proto.IPPoolType_NO_ENCAP, // Host now marked as inside the IP pool.
		Dst:         remoteHostIP.String() + "/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
	// Single route for the block.
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: false},
)

// we start from vxlan setup as the test framework expects vxlan enabled
var nodesWithMoreIPs = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address: remoteHostIPWithPrefix,
			},
			Addresses: []apiv3.NodeAddress{
				{
					Address: remoteHostIPWithPrefix,
				},
				{
					Address: "1.2.3.4",
				},
			},
		},
	}},
	KVPair{Key: localNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address: localHostIPWithPrefix,
			},
			Addresses: []apiv3.NodeAddress{
				{
					Address: localHostIPWithPrefix,
				},
				{
					Address: "4.3.2.1",
				},
			},
		},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIPWithPrefix,
	},
	&proto.HostMetadataV4V6Update{
		Hostname: localHostname,
		Ipv4Addr: localHostIPWithPrefix,
	},
).withRoutes(nodesWithMoreIPsRoutes...).
	withName("routes for nodes with more IPs")

var nodesWithMoreIPsRoutes = append(vxlanWithBlockRoutes[0:len(vxlanWithBlockRoutes):len(vxlanWithBlockRoutes) /* force copy */],
	types.RouteUpdate{
		Types:       proto.RouteType_REMOTE_HOST,
		Dst:         "1.2.3.4/32",
		DstNodeIp:   remoteHostIP.String(),
		DstNodeName: remoteHostname,
	},
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		Dst:         localHostIP.String() + "/32",
		DstNodeIp:   localHostIP.String(),
		DstNodeName: localHostname,
	},
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		Dst:         "4.3.2.1/32",
		DstNodeIp:   localHostIP.String(),
		DstNodeName: localHostname,
	},
)

var nodesWithMoreIPsAndDuplicates = nodesWithMoreIPs.withKVUpdates(
	KVPair{
		Key: remoteNodeResKey, Value: &apiv3.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: remoteHostname,
			},
			Spec: apiv3.NodeSpec{
				BGP: &apiv3.NodeBGPSpec{
					IPv4Address: remoteHostIPWithPrefix,
				},
				Addresses: []apiv3.NodeAddress{
					{
						Address: "1.2.3.4",
					},
					{
						Address: remoteHostIPWithPrefix,
					},
					{
						Address: remoteHostIPWithPrefix,
					},
					{
						Address: "1.2.3.4/19",
					},
					{
						Address: "1.2.3.4",
					},
				},
			},
		},
	},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: localHostname,
		Ipv4Addr: localHostIPWithPrefix,
	},
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIPWithPrefix,
	},
).withName("routes for nodes with more IPs and duplicates")

var nodesWithDifferentAddressTypes = nodesWithMoreIPs.withKVUpdates(
	KVPair{Key: localNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address: localHostIPWithPrefix,
			},
			Addresses: []apiv3.NodeAddress{
				{
					Address: localHostIPWithPrefix,
				},
				{
					Address: "4.3.2.1",
				},
				{
					Address: "feed:dead:beef::/64",
				},
				{
					Address: "some.thing.like.a.domain.name",
				},
			},
		},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{ // from nodesWithMoreIPs
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIPWithPrefix,
	},
	&proto.HostMetadataV4V6Update{
		Hostname: localHostname,
		Ipv4Addr: localHostIPWithPrefix,
	},
).withRoutes(append(nodesWithMoreIPsRoutes,
	// IPv6 route is now valid
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		Dst:         "feed:dead:beef::/128",
		DstNodeName: localHostname,
	})...,
).withName("routes for nodes with more IPs some of them unexpected/invalid")

var nodesWithMoreIPsRoutesDeletedExtras = append(vxlanWithBlockRoutes[0:len(vxlanWithBlockRoutes):len(vxlanWithBlockRoutes) /* force copy */],
	types.RouteUpdate{
		Types:       proto.RouteType_LOCAL_HOST,
		Dst:         localHostIP.String() + "/32",
		DstNodeIp:   localHostIP.String(),
		DstNodeName: localHostname,
	},
)

var nodesWithMoreIPsDeleted = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: remoteHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address: remoteHostIPWithPrefix,
			},
			Addresses: []apiv3.NodeAddress{
				{
					Address: remoteHostIPWithPrefix,
				},
			},
		},
	}},
	KVPair{Key: localNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address: localHostIPWithPrefix,
			},
			Addresses: []apiv3.NodeAddress{
				{
					Address: localHostIPWithPrefix,
				},
			},
		},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIPWithPrefix,
	},
	&proto.HostMetadataV4V6Update{
		Hostname: localHostname,
		Ipv4Addr: localHostIPWithPrefix,
	},
).withRoutes(nodesWithMoreIPsRoutesDeletedExtras...).
	withName("routes for nodes with more IPs deleted the extra IPs")

// Local workload endpoint and an endpoint slice for service named "svc".
var endpointSliceAndLocalWorkload = empty.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: endpointSliceKey1, Value: &endpointSlice1},
).withRoutes(
	// Routes for the local WEP.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlV6ColonOne,
	routelocalWlV6ColonTwo,
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{},
).withActiveProfiles(
	types.ProfileID{Name: "prof-1"},
	types.ProfileID{Name: "prof-2"},
	types.ProfileID{Name: "prof-missing"},
).withName("EndpointSliceInactive")

// Add a network policy that makes the endpoint slice active.
var endpointSliceActive = endpointSliceAndLocalWorkload.withKVUpdates(
	KVPair{Key: servicePolicyKey, Value: &servicePolicy},
).withName("EndpointSliceActive").withIPSet("svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg", []string{
	"10.0.0.1,tcp:80",
}).withActivePolicies(
	types.PolicyID{Name: "svc-policy", Kind: v3.KindGlobalNetworkPolicy},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:           "default",
			EgressPolicies: []types.PolicyID{{Name: "svc-policy", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
)

// Change the endpoint slice
var endpointSliceActiveNewIPs = endpointSliceActive.withName("EndpointSliceActiveNewIPs").withKVUpdates(
	KVPair{Key: endpointSliceKey1, Value: &endpointSlice1NewIPs},
).withIPSet("svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg", []string{
	"10.0.0.1,tcp:80",
	"10.0.0.2,tcp:80",
	"10.0.0.3,tcp:80",
})

var endpointSliceActiveNewIPs2 = endpointSliceActive.withName("EndpointSliceActiveNewIPs2").withKVUpdates(
	KVPair{Key: endpointSliceKey1, Value: &endpointSlice1NewIPs2},
).withIPSet("svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg", []string{
	"10.0.0.2,tcp:80",
	"10.0.0.3,tcp:80",
	"10.0.0.4,tcp:80",
})

// Overlap two endpoint slices
var endpointSliceOverlap = endpointSliceActiveNewIPs.withName("EndpointSliceOverlap").withKVUpdates(
	KVPair{Key: endpointSliceKey2, Value: &endpointSlice2NewIPs2},
).withIPSet("svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg", []string{
	"10.0.0.1,tcp:80",
	"10.0.0.2,tcp:80",
	"10.0.0.3,tcp:80",
	"10.0.0.4,tcp:80",
})

var endpointSlice2OnlyActiveNewIPs2 = endpointSliceActive.withName("EndpointSlice2ActiveNewIPs2").withKVUpdates(
	KVPair{Key: endpointSliceKey1, Value: nil},
	KVPair{Key: endpointSliceKey2, Value: &endpointSlice2NewIPs2},
).withIPSet("svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg", []string{
	"10.0.0.2,tcp:80",
	"10.0.0.3,tcp:80",
	"10.0.0.4,tcp:80",
})

// Add a network policy that makes the endpoint slice active, this time with an ingress policy.
var endpointSliceActiveSpecNoPorts = endpointSliceAndLocalWorkload.withKVUpdates(
	KVPair{Key: servicePolicyKey, Value: &servicePolicyNoPorts},
).withName("EndpointSliceActiveNoPorts").withIPSet("svcnoport:T03S_6hogdrGKrNFBcbKTFsH_uKwDHEo8JddOg", []string{
	"10.0.0.1/32",
}).withActivePolicies(
	types.PolicyID{Name: "svc-policy", Kind: v3.KindGlobalNetworkPolicy},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "svc-policy", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
)

// Add the egress policy too...
var endpointSliceActiveSpecPortsAndNoPorts = endpointSliceActiveSpecNoPorts.withKVUpdates(
	KVPair{Key: servicePolicyKey2, Value: &servicePolicy},
).withName(
	"EndpointSliceActivePortsNoPorts",
).withIPSet("svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg", []string{
	"10.0.0.1,tcp:80",
}).withActivePolicies(
	types.PolicyID{Name: "svc-policy", Kind: v3.KindGlobalNetworkPolicy},
	types.PolicyID{Name: "svc-policy2", Kind: v3.KindGlobalNetworkPolicy},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:            "default",
			IngressPolicies: []types.PolicyID{{Name: "svc-policy", Kind: v3.KindGlobalNetworkPolicy}},
			EgressPolicies:  []types.PolicyID{{Name: "svc-policy2", Kind: v3.KindGlobalNetworkPolicy}},
		},
	},
)

var encapWithIPIPPool = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithIPIP},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: true, VxlanEnabled: false, VxlanEnabledV6: false},
).withRoutes(
	routeUpdateIPPoolIPIP,
).withName("Encap with IPIP Pool")

var encapWithVXLANPool = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLAN},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true, VxlanEnabledV6: false},
).withRoutes(
	routeUpdateIPPoolVXLAN,
).withName("Encap with VXLAN Pool")

var encapWithIPIPAndVXLANPool = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithIPIP},
	KVPair{Key: ipPoolKey2, Value: &ipPool2WithVXLAN},
).withExpectedEncapsulation(
	&proto.Encapsulation{IpipEnabled: true, VxlanEnabled: true, VxlanEnabledV6: false},
).withRoutes(
	routeUpdateIPPoolIPIP,
	routeUpdateIPPool2VXLAN,
).withName("Encap with IPIP and VXLAN Pools")

var wireguardV4 = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "WireguardEnabled"}, Value: &t},
	KVPair{
		Key: WireguardKey{NodeName: remoteHostname},
		Value: &Wireguard{
			InterfaceIPv4Addr: &remoteHost2IP,
			PublicKey:         wgPublicKey1.String(),
		},
	},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address: remoteHostIP.String() + "/24",
			},
			Wireguard: &apiv3.NodeWireguardSpec{
				InterfaceIPv4Address: remoteHost2IP.String(),
			},
		},
		Status: apiv3.NodeStatus{
			WireguardPublicKey: wgPublicKey1.String(),
		},
	}},
).withName("Wireguard IPv4").withRoutes(
	[]types.RouteUpdate{
		routeUpdateRemoteHost,
		{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_NONE,
			Dst:         remoteHost2IP.String() + "/32",
			DstNodeName: remoteHostname,
			DstNodeIp:   remoteHostIP.String(),
			TunnelType:  &proto.TunnelType{Wireguard: true},
		},
	}...,
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteHostname,
		Ipv4Addr: remoteHostIP.String() + "/24",
	},
).withWireguardEndpoints(
	[]types.WireguardEndpointUpdate{
		{
			Hostname:          remoteHostname,
			PublicKey:         wgPublicKey1.String(),
			InterfaceIpv4Addr: remoteHost2IP.String(),
		},
	}...,
)

var wireguardV6 = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "WireguardEnabledV6"}, Value: &t},
	KVPair{
		Key: WireguardKey{NodeName: remoteHostname},
		Value: &Wireguard{
			InterfaceIPv6Addr: &remoteHost2IPv6,
			PublicKeyV6:       wgPublicKey2.String(),
		},
	},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv6Address: remoteHostIPv6.String() + "/96",
			},
			Wireguard: &apiv3.NodeWireguardSpec{
				InterfaceIPv6Address: remoteHost2IPv6.String(),
			},
		},
		Status: apiv3.NodeStatus{
			WireguardPublicKeyV6: wgPublicKey2.String(),
		},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteNodeResKey.Name,
		Ipv6Addr: remoteHostIPv6.String() + "/96",
	},
).withName("Wireguard IPv6").withRoutes(
	[]types.RouteUpdate{
		routeUpdateRemoteHostV6,
		{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_NONE,
			Dst:         remoteHost2IPv6.String() + "/128",
			DstNodeName: remoteHostname,
			DstNodeIp:   remoteHostIPv6.String(),
			TunnelType:  &proto.TunnelType{Wireguard: true},
		},
	}...,
).withWireguardV6Endpoints(
	[]types.WireguardEndpointV6Update{
		{
			Hostname:          remoteHostname,
			PublicKeyV6:       wgPublicKey2.String(),
			InterfaceIpv6Addr: remoteHost2IPv6.String(),
		},
	}...,
)

var wireguardV4V6 = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "WireguardEnabled"}, Value: &t},
	KVPair{Key: GlobalConfigKey{Name: "WireguardEnabledV6"}, Value: &t},
	KVPair{
		Key: WireguardKey{NodeName: remoteHostname},
		Value: &Wireguard{
			InterfaceIPv4Addr: &remoteHost2IP,
			PublicKey:         wgPublicKey1.String(),
			InterfaceIPv6Addr: &remoteHost2IPv6,
			PublicKeyV6:       wgPublicKey2.String(),
		},
	},
	KVPair{Key: remoteNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address: remoteHostIP.String() + "/24",
				IPv6Address: remoteHostIPv6.String() + "/96",
			},
			Wireguard: &apiv3.NodeWireguardSpec{
				InterfaceIPv4Address: remoteHost2IP.String(),
				InterfaceIPv6Address: remoteHost2IPv6.String(),
			},
		},
		Status: apiv3.NodeStatus{
			WireguardPublicKey:   wgPublicKey1.String(),
			WireguardPublicKeyV6: wgPublicKey2.String(),
		},
	}},
).withHostMetadataV4V6(
	&proto.HostMetadataV4V6Update{
		Hostname: remoteNodeResKey.Name,
		Ipv4Addr: remoteHostIP.String() + "/24",
		Ipv6Addr: remoteHostIPv6.String() + "/96",
	},
).withName("Wireguard IPv4+IPv6").withRoutes(
	[]types.RouteUpdate{
		routeUpdateRemoteHost,
		routeUpdateRemoteHostV6,
		{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_NONE,
			Dst:         remoteHost2IP.String() + "/32",
			DstNodeName: remoteHostname,
			DstNodeIp:   remoteHostIP.String(),
			TunnelType:  &proto.TunnelType{Wireguard: true},
		},
		{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_NONE,
			Dst:         remoteHost2IPv6.String() + "/128",
			DstNodeName: remoteHostname,
			DstNodeIp:   remoteHostIPv6.String(),
			TunnelType:  &proto.TunnelType{Wireguard: true},
		},
	}...,
).withWireguardEndpoints(
	[]types.WireguardEndpointUpdate{
		{
			Hostname:          remoteHostname,
			PublicKey:         wgPublicKey1.String(),
			InterfaceIpv4Addr: remoteHost2IP.String(),
		},
	}...,
).withWireguardV6Endpoints(
	[]types.WireguardEndpointV6Update{
		{
			Hostname:          remoteHostname,
			PublicKeyV6:       wgPublicKey2.String(),
			InterfaceIpv6Addr: remoteHost2IPv6.String(),
		},
	}...,
)

type StateList []State

func (l StateList) String() string {
	names := make([]string, 0)
	for _, state := range l {
		names = append(names, state.String())
	}
	return "[" + strings.Join(names, ", ") + "]"
}

// UsesNodeResources returns true if any of the KVs in this state are apiv3.Node resources.
// Some calculation graph nodes support either the v3 Node or the old model.HostIP object.
func (l StateList) UsesNodeResources() bool {
	for _, s := range l {
		for _, kv := range s.DatastoreState {
			if resourceKey, ok := kv.Key.(ResourceKey); ok && resourceKey.Kind == apiv3.KindNode {
				return true
			}
		}
	}
	return false
}

// RouteSource returns the route source to use for the test, based on the states in the test.
// If the states include a Felix configuration update to set the route source, then it is used.
// Otherwise, default to CalicoIPAM
func (l StateList) RouteSource() string {
	for _, s := range l {
		for _, kv := range s.DatastoreState {
			if resourceKey, ok := kv.Key.(GlobalConfigKey); ok && resourceKey.Name == "RouteSource" {
				if kv.Value != nil {
					return *kv.Value.(*string)
				}
			}
		}
	}
	return "CalicoIPAM"
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
	first := true
	for _, state := range baseTest {
		if !first {
			mappedTest = append(mappedTest, empty)
		} else {
			first = false
		}
		mappedTest = append(mappedTest, state)
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
