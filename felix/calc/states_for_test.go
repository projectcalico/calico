// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	"github.com/projectcalico/calico/felix/dataplane/mock"
	"github.com/projectcalico/calico/felix/proto"
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
var pol1KVPair = KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20}
var withPolicy = initialisedStore.withKVUpdates(
	pol1KVPair,
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

// withHttpMethodPolicy adds a policy containing http method selector.
var withHttpMethodPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_http_match},
).withTotalALPPolicies(
	1,
).withName("with http-method policy")

// withServiceAccountPolicy adds two policies containing service account selector.
var withServiceAccountPolicy = initialisedStore.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_src_service_account},
	KVPair{Key: PolicyKey{Name: "pol-2"}, Value: &policy1_order20_dst_service_account},
).withTotalALPPolicies(
	2,
).withName("with service-account policy")

// withNonALPPolicy adds a non ALP policy.
var withNonALPPolicy = withPolicy.withTotalALPPolicies(
	0,
).withName("with non-ALP policy")

// Routes for local workloads.  Most of the tests pre-date route generation so they don't have a
// local host resource; hence we get routes with no next hop.
var routelocalWlTenDotOne = proto.RouteUpdate{
	Type:          proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "10.0.0.1/32",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

var routelocalWlTenDotTwo = proto.RouteUpdate{
	Type:          proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "10.0.0.2/32",
	DstNodeName:   localHostname,
	LocalWorkload: true,
}

var routelocalWlTenDotThree = proto.RouteUpdate{
	Type:          proto.RouteType_LOCAL_WORKLOAD,
	Dst:           "10.0.0.3/32",
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
).withName("ep1 local, policy")

// localEp1WithNamedPortPolicy as above but with named port in the policy.
var localEp1WithNamedPortPolicy = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_selector_and_named_port_tcpport},
).withIPSet(namedPortAllTCPID, []string{
	"10.0.0.1,tcp:8080",
	"10.0.0.2,tcp:8080",
	"fc00:fe11::1,tcp:8080",
	"fc00:fe11::2,tcp:8080",
}).withIPSet(allSelectorId, nil).withName("ep1 local, named port policy")

// localEp1WithNamedPortPolicy as above but with negated named port in the policy.
var localEp1WithNegatedNamedPortPolicy = empty.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_selector_and_negated_named_port_tcpport},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{
			Name:               "default",
			IngressPolicyNames: []string{"pol-1"},
		},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
).withName("ep1 local, negated named port policy")

// As above but using the destination fields in the policy instead of source.
var localEp1WithNegatedNamedPortPolicyDest = localEp1WithNegatedNamedPortPolicy.withKVUpdates(
	KVPair{
		Key:   PolicyKey{Name: "pol-1"},
		Value: &policy1_order20_with_selector_and_negated_named_port_tcpport_dest,
	},
).withName("ep1 local, negated named port policy in destination fields")

// A host endpoint with a named port
var localHostEp1WithNamedPortPolicy = empty.withKVUpdates(
	KVPair{Key: hostEpWithNameKey, Value: &hostEpWithNamedPorts},
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_selector_and_named_port_tcpport},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
).withEndpoint(
	"named",
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
	},
).withName("Host endpoint, named port policy")

// As above but with no selector in the rules.
var localEp1WithNamedPortPolicyNoSelector = localEp1WithNamedPortPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_named_port_tcpport},
).withName("ep1 local, named port only")

// As above but with negated named port.
var localEp1WithNegatedNamedPortPolicyNoSelector = localEp1WithNamedPortPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_named_port_tcpport_negated},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: nil},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
).withName("ep1 local, ingress-only policy")

// localEp1WithNamedPortPolicy as above but with UDP named port in the policy.
var localEp1WithNamedPortPolicyUDP = localEp1WithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_selector_and_named_port_udpport},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: nil},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	hostEpWithNameId,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: nil, EgressPolicyNames: []string{"pol-1"}},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withUntrackedPolicies(
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]mock.TierInfo{},
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
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
	proto.PolicyID{Tier: "default", Name: "pre-dnat-pol-1"},
).withPreDNATPolicies(
	proto.PolicyID{Tier: "default", Name: "pre-dnat-pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]mock.TierInfo{},
	[]mock.TierInfo{},
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pre-dnat-pol-1"}, EgressPolicyNames: nil},
	},
).withName("host ep1, pre-DNAT policy")

var hostEp1WithTrackedAndUntrackedPolicy = hostEp1WithUntrackedPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-2"}, Value: &policy1_order20},
).withActivePolicies(
	proto.PolicyID{Tier: "default", Name: "pol-1"},
	proto.PolicyID{Tier: "default", Name: "pol-2"},
).withEndpointUntracked(
	hostEpWithNameId,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-2"}, EgressPolicyNames: []string{"pol-2"}},
	},
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-3"},
).withEndpoint(
	hostEpNoNameId,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
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
		proto.PolicyID{Tier: "default", Name: "pol-1"},
		proto.PolicyID{Tier: "default", Name: "pol-2"},
		proto.PolicyID{Tier: "default", Name: "pol-3"},
	).withActiveProfiles(
		proto.ProfileID{Name: "prof-1"},
		proto.ProfileID{Name: "prof-2"},
		proto.ProfileID{Name: "prof-missing"},
	).withEndpoint(
		localWlEp1Id,
		[]mock.TierInfo{
			{Name: "default", IngressPolicyNames: expectedOrder[:], EgressPolicyNames: expectedOrder[:]},
		},
	).withRoutes(
		// Routes for the local WEPs.
		routelocalWlTenDotOne,
		routelocalWlTenDotTwo,
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-3"},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
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
	proto.PolicyID{Tier: "default", Name: "pol-1"},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-3"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
	},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{
		{Name: "default", IngressPolicyNames: []string{"pol-1"}, EgressPolicyNames: []string{"pol-1"}},
	},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
).withName("2 local, overlapping IPs & a policy")

var localEpsWithNamedPortsPolicy = localEpsWithPolicy.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_selector_and_named_port_tcpport},
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
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_selector_and_named_port_tcpport2},
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
	KVPair{Key: PolicyKey{Name: "pol-1"}, Value: &policy1_order20_with_named_port_mismatched_protocol},
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
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-3"},
	proto.ProfileID{Name: "prof-missing"},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
)

// Building on the above, we add a policy to match on the inherited label, which should produce
// a named port.
var localEpsAndNamedPortPolicyMatchingInheritedLabelOnEP1 = localEpsWithOverlappingIPsAndInheritedLabels.withKVUpdates(
	KVPair{Key: PolicyKey{Name: "inherit-pol"}, Value: &policy_with_named_port_inherit},
).withActivePolicies(
	proto.PolicyID{Tier: "default", Name: "inherit-pol"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{{Name: "default",
		IngressPolicyNames: []string{"inherit-pol"},
		EgressPolicyNames:  []string{"inherit-pol"},
	}},
).withEndpoint(
	localWlEp2Id,
	[]mock.TierInfo{{Name: "default",
		IngressPolicyNames: []string{"inherit-pol"},
		EgressPolicyNames:  []string{"inherit-pol"},
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
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
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
	proto.RouteUpdate{
		Type:          proto.RouteType_LOCAL_WORKLOAD,
		Dst:           "11.0.0.1/32",
		DstNodeName:   localHostname,
		LocalWorkload: true,
	},
	proto.RouteUpdate{
		Type:          proto.RouteType_LOCAL_WORKLOAD,
		Dst:           "11.0.0.2/32",
		DstNodeName:   localHostname,
		LocalWorkload: true,
	},
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
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
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-3"},
	proto.ProfileID{Name: "prof-missing"},
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
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-3"},
	proto.ProfileID{Name: "prof-missing"},
).withEndpoint(
	localWlEp1Id, []mock.TierInfo{},
).withEndpoint(
	localWlEp2Id, []mock.TierInfo{},
).withRoutes(
	// Routes for the local WEPs.
	routelocalWlTenDotOne,
	routelocalWlTenDotTwo,
	routelocalWlTenDotThree,
).withName("2 local, overlapping IPs & a tag inherit profile")

var withProfileTagOverriden = initialisedStore.withKVUpdates(
	KVPair{Key: ProfileRulesKey{ProfileKey: ProfileKey{Name: "prof-1"}}, Value: &profileRulesWithTagInherit},
	KVPair{Key: ResourceKey{Kind: v3.KindProfile, Name: "prof-1"}, Value: profileLabelsTag1},
).withName("profile")

// localEpsWithTagOverriddenProfile Checks that tags-inherited labels can be
// overridden by explicit labels on the profile.
var localEpsWithTagOverriddenProfile = withProfileTagOverriden.withKVUpdates(
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
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-3"},
	proto.ProfileID{Name: "prof-missing"},
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
var routeUpdateIPPoolVXLAN = proto.RouteUpdate{
	Type:        proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPoolWithVXLAN.CIDR.String(),
	NatOutgoing: ipPoolWithVXLAN.Masquerade,
}

// RouteUpdate expected for ipPool2WithVXLAN.
var routeUpdateIPPool2VXLAN = proto.RouteUpdate{
	Type:        proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPool2WithVXLAN.CIDR.String(),
	NatOutgoing: ipPool2WithVXLAN.Masquerade,
}

// RouteUpdate expected for ipPoolWithVXLANSlash32.
var routeUpdateIPPoolVXLANSlash32 = proto.RouteUpdate{
	Type:        proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPoolWithVXLANSlash32.CIDR.String(),
	NatOutgoing: ipPoolWithVXLANSlash32.Masquerade,
}

// RouteUpdate expected for ipPoolWithVXLANCrossSubnet.
var routeUpdateIPPoolVXLANCrossSubnet = proto.RouteUpdate{
	Type:        proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_VXLAN,
	Dst:         ipPoolWithVXLANCrossSubnet.CIDR.String(),
	NatOutgoing: ipPoolWithVXLANCrossSubnet.Masquerade,
}

// RouteUpdate expected for ipPoolWithIPIP.
var routeUpdateIPPoolIPIP = proto.RouteUpdate{
	Type:        proto.RouteType_CIDR_INFO,
	IpPoolType:  proto.IPPoolType_IPIP,
	Dst:         ipPoolWithIPIP.CIDR.String(),
	NatOutgoing: ipPoolWithIPIP.Masquerade,
}

// RouteUpdate expected for the remote host with its normal IP.
var routeUpdateRemoteHost = proto.RouteUpdate{
	Type:        proto.RouteType_REMOTE_HOST,
	IpPoolType:  proto.IPPoolType_NONE,
	Dst:         remoteHostIP.String() + "/32",
	DstNodeName: remoteHostname,
	DstNodeIp:   remoteHostIP.String(),
}

// RouteUpdate expected for the second remote host.
var routeUpdateRemoteHost2 = proto.RouteUpdate{
	Type:        proto.RouteType_REMOTE_HOST,
	IpPoolType:  proto.IPPoolType_NONE,
	Dst:         remoteHost2IP.String() + "/32",
	DstNodeName: remoteHostname2,
	DstNodeIp:   remoteHost2IP.String(),
}

// Minimal VXLAN set-up using WorkloadIPs for routing information rather than using
// IPAM blocks. Includes remoteHost2
var vxlanWithWEPIPs = empty.withKVUpdates(
	KVPair{Key: GlobalConfigKey{Name: "RouteSource"}, Value: &workloadIPs},
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLAN},
	KVPair{Key: remoteHost2IPKey, Value: &remoteHost2IP},
	KVPair{Key: remoteHost2VXLANTunnelConfigKey, Value: remoteHost2VXLANTunnelIP},
).withName("VXLAN using WorkloadIPs").withVTEPs(
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname2,
		Mac:            "66:40:18:59:1f:16",
		Ipv4Addr:       remoteHost2VXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost2,
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true},
)

// Adds in an workload on remoteHost2 and expected route.
var vxlanWithWEPIPsAndWEP = vxlanWithWEPIPs.withKVUpdates(
	KVPair{Key: remoteWlEpKey2, Value: &remoteWlEp1},
).withName("VXLAN using WorkloadIPs and a WEP").withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost2,
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
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
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname2,
		Mac:            "66:40:18:59:1f:16",
		Ipv4Addr:       remoteHost2VXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	routeUpdateRemoteHost2,
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
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
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true},
).withRoutes(vxlanWithBlockRoutes...)

var vxlanWithBlockRoutes = []proto.RouteUpdate{
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
}

var remoteNodeResKey = ResourceKey{Name: remoteHostname, Kind: apiv3.KindNode}
var localNodeResKey = ResourceKey{Name: localHostname, Kind: apiv3.KindNode}

// As vxlanWithBlock but with a host sharing the same IP.  No route update because we tie-break on host name.
var vxlanWithBlockDupNodeIP = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHost2IPKey, Value: &remoteHostIP},
).withName("VXLAN with dup node IP")

var vxlanWithDupNodeIPRemoved = vxlanWithBlockDupNodeIP.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: nil},
).withName("VXLAN with dup node IP removed").withVTEPs().withRoutes(
	routeUpdateIPPoolVXLAN,
	// Remote host 2 but with remotehost's IP:
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         remoteHostIP.String() + "/32",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHostIP.String(),
	},
	// Single route for the block.  No IP because the block belongs to remotehost and its IP was
	// removed.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
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
		}}}},
).withName("VXLAN with node resource (node resources)")

// As vxlanWithBlock but with some superfluous IPv6 resources (VXLAN is IPv4 only).
var vxlanWithIPv6Resources = vxlanWithBlock.withKVUpdates(
	KVPair{Key: v6IPPoolKey, Value: &v6IPPool},
	KVPair{Key: remotev6IPAMBlockKey, Value: &remotev6IPAMBlock},
).withName("VXLAN with IPv6")

// Minimal VXLAN set-up with a MAC address override for the remote node.
var vxlanWithMAC = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelMACConfigKey, Value: remoteHostVXLANTunnelMAC},
).withName("VXLAN MAC").withVTEPs(
	// VTEP for the remote node.
	proto.VXLANTunnelEndpointUpdate{
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
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
	proto.VXLANTunnelEndpointUpdate{
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
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.2/32",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
	},
)

// vxlanWithBlock but with a different tunnel IP.
var vxlanWithBlockAndDifferentTunnelIP = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP2},
).withName("VXLAN different tunnel IP").withVTEPs(
	// VTEP for the remote node.
	proto.VXLANTunnelEndpointUpdate{
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
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         remoteHost2IP.String() + "/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHost2IP.String(),
	},
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
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
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
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
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
	proto.VXLANTunnelEndpointUpdate{
		Node:           localHostname,
		Mac:            "66:48:f6:56:dc:f1",
		Ipv4Addr:       localHostVXLANTunnelIP,
		ParentDeviceIp: localHostIP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		NatOutgoing: true,
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true},
)

var localVXLANWep1Route1 = proto.RouteUpdate{
	Type:          proto.RouteType_LOCAL_WORKLOAD,
	IpPoolType:    proto.IPPoolType_VXLAN,
	Dst:           "10.0.0.1/32",
	DstNodeName:   localHostname,
	DstNodeIp:     localHostIP.String(),
	NatOutgoing:   true,
	LocalWorkload: true,
}

var localVXLANWep1Route2 = proto.RouteUpdate{
	Type:          proto.RouteType_LOCAL_WORKLOAD,
	IpPoolType:    proto.IPPoolType_VXLAN,
	Dst:           "10.0.0.2/32",
	DstNodeName:   localHostname,
	DstNodeIp:     localHostIP.String(),
	NatOutgoing:   true,
	LocalWorkload: true,
}

// As vxlanLocalBlockWithBorrows but with a local workload.  The local workload has an IP that overlaps with
// the remote workload, we take that in preference to the remote route.
var vxlanLocalBlockWithBorrowsLocalWEP = vxlanLocalBlockWithBorrows.withKVUpdates(
	KVPair{Key: localWlEpKey1, Value: &localWlEp1},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		NatOutgoing: true,
	},
	// Plus individual routes for the local WEPs.
	localVXLANWep1Route1,
	localVXLANWep1Route2,
).withName("VXLAN local with borrows with local WEP override").withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
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
		}}}},
	KVPair{Key: localNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: localHostIPWithPrefix,
		}}}},
).withName("VXLAN local with borrows (node resources)")

// As vxlanLocalBlockWithBorrowsNodeRes using the cross-subnet version of the IP pool.
// Hosts are in the same subnet.
var vxlanLocalBlockWithBorrowsCrossSubnetNodeRes = vxlanLocalBlockWithBorrowsNodeRes.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLANCrossSubnet},
).withRoutes(
	routeUpdateIPPoolVXLANCrossSubnet,
	routeUpdateRemoteHost,
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		SameSubnet:  true, // cross subnet.
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		SameSubnet:  true, // cross subnet.
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
		}}}},
	KVPair{Key: localNodeResKey, Value: &apiv3.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: localHostname,
		},
		Spec: apiv3.NodeSpec{BGP: &apiv3.NodeBGPSpec{
			IPv4Address: localHostIP.String() + "/32",
		}}}},
).withRoutes(
	routeUpdateIPPoolVXLANCrossSubnet,
	routeUpdateRemoteHost,
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_HOST,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         localHostIP.String() + "/32",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
	},
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/29",
		DstNodeName: localHostname,
		DstNodeIp:   localHostIP.String(),
		SameSubnet:  true, // cross subnet.
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.2/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		SameSubnet:  false, // subnets don't match.
	},
).withName("VXLAN cross subnet different subnet (node resources)")

// vxlanWithBlockAndBorrows but missing the VTEP information for the first host.
var vxlanWithBlockAndBorrowsAndMissingFirstVTEP = vxlanWithBlockAndBorrows.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: nil},
).withName("VXLAN borrow missing VTEP").withVTEPs(
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname2,
		Mac:            "66:40:18:59:1f:16",
		Ipv4Addr:       remoteHost2VXLANTunnelIP,
		ParentDeviceIp: remoteHost2IP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost2,
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		NatOutgoing: true,
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.2/32",
		DstNodeName: remoteHostname2,
		DstNodeIp:   remoteHost2IP.String(),
		NatOutgoing: true,
	},
)

// As vxlanWithBlock but with the IP pool switched to IPIP mode.
var vxlanToIPIPSwitch = vxlanWithBlock.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithIPIP},
).withName("VXLAN switched to IPIP").withRoutes(
	routeUpdateIPPoolIPIP,
	routeUpdateRemoteHost,
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_IPIP,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
	},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: true, VxlanEnabled: false},
)

var vxlanBlockDelete = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteIPAMBlockKey, Value: nil},
).withName("VXLAN block removed").withRoutes(
	// VXLAN block route removed but still keep the IP pool and host routes.
	routeUpdateIPPoolVXLAN,
	routeUpdateRemoteHost,
)

var vxlanHostIPDelete = vxlanWithBlock.withKVUpdates(
	KVPair{Key: remoteHostIPKey, Value: nil},
).withName("VXLAN host IP removed").withRoutes(
	routeUpdateIPPoolVXLAN,
	// Host removed but keep the route without the node IP.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
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
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	// No CIDR_INFO route, it gets subsumed into the REMOTE_WORKLOAD one.
	routeUpdateRemoteHost,
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.0.0/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true},
)

var vxlanSlash32NoBlock = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLANSlash32},
	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
).withName("VXLAN /32 no block").withVTEPs(
	// VTEP for the remote node.
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	routeUpdateIPPoolVXLANSlash32,
	routeUpdateRemoteHost,
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true},
)

var vxlanSlash32NoPool = empty.withKVUpdates(
	KVPair{Key: remoteIPAMSlash32BlockKey, Value: &remoteIPAMBlockSlash32},
	KVPair{Key: remoteHostIPKey, Value: &remoteHostIP},
	KVPair{Key: remoteHostVXLANTunnelConfigKey, Value: remoteHostVXLANTunnelIP},
).withName("VXLAN /32 no pool").withVTEPs(
	// VTEP for the remote node.
	proto.VXLANTunnelEndpointUpdate{
		Node:           remoteHostname,
		Mac:            "66:3e:ca:a4:db:65",
		Ipv4Addr:       remoteHostVXLANTunnelIP,
		ParentDeviceIp: remoteHostIP.String(),
	},
).withRoutes(
	routeUpdateRemoteHost,
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_NONE,
		Dst:         "10.0.0.0/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
	},
)

// Corner case: host inside an IP pool.
var hostInIPPool = vxlanWithBlock.withKVUpdates(
	KVPair{Key: hostCoveringIPPoolKey, Value: &hostCoveringIPPool},
).withName("host in IP pool").withRoutes(
	routeUpdateIPPoolVXLAN,
	proto.RouteUpdate{
		Type:        proto.RouteType_CIDR_INFO,
		IpPoolType:  proto.IPPoolType_NO_ENCAP,
		Dst:         hostCoveringIPPool.CIDR.String(),
		NatOutgoing: true,
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_HOST,
		IpPoolType:  proto.IPPoolType_NO_ENCAP, // Host now marked as inside the IP pool.
		Dst:         remoteHostIP.String() + "/32",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
	// Single route for the block.
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_WORKLOAD,
		IpPoolType:  proto.IPPoolType_VXLAN,
		Dst:         "10.0.1.0/29",
		DstNodeName: remoteHostname,
		DstNodeIp:   remoteHostIP.String(),
		NatOutgoing: true,
	},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true},
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
		}}},
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
		}}},
).withRoutes(nodesWithMoreIPsRoutes...).
	withName("routes for nodes with more IPs")

var nodesWithMoreIPsRoutes = append(vxlanWithBlockRoutes[0:len(vxlanWithBlockRoutes):len(vxlanWithBlockRoutes) /* force copy */],
	proto.RouteUpdate{
		Type:        proto.RouteType_REMOTE_HOST,
		Dst:         "1.2.3.4/32",
		DstNodeIp:   remoteHostIP.String(),
		DstNodeName: remoteHostname,
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_HOST,
		Dst:         localHostIP.String() + "/32",
		DstNodeIp:   localHostIP.String(),
		DstNodeName: localHostname,
	},
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_HOST,
		Dst:         "4.3.2.1/32",
		DstNodeIp:   localHostIP.String(),
		DstNodeName: localHostname,
	},
)

var nodesWithMoreIPsAndDuplicates = nodesWithMoreIPs.withKVUpdates(
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
		}}},
).withRoutes(nodesWithMoreIPsRoutes...).
	withName("routes for nodes with more IPs someof them unexpected/invalid")

var nodesWithMoreIPsRoutesDeletedExtras = append(vxlanWithBlockRoutes[0:len(vxlanWithBlockRoutes):len(vxlanWithBlockRoutes) /* force copy */],
	proto.RouteUpdate{
		Type:        proto.RouteType_LOCAL_HOST,
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
		}}},
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
		}}},
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
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{},
).withActiveProfiles(
	proto.ProfileID{Name: "prof-1"},
	proto.ProfileID{Name: "prof-2"},
	proto.ProfileID{Name: "prof-missing"},
).withName("EndpointSliceInactive")

// Add a network policy that makes the endpoint slice active.
var endpointSliceActive = endpointSliceAndLocalWorkload.withKVUpdates(
	KVPair{Key: servicePolicyKey, Value: &servicePolicy},
).withName("EndpointSliceActive").withIPSet("svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg", []string{
	"10.0.0.1,tcp:80",
}).withActivePolicies(
	proto.PolicyID{Tier: "default", Name: "svc-policy"},
).withEndpoint(
	localWlEp1Id,
	[]mock.TierInfo{
		{Name: "default", EgressPolicyNames: []string{"svc-policy"}},
	},
)

var encapWithIPIPPool = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithIPIP},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: true, VxlanEnabled: false},
).withRoutes(
	routeUpdateIPPoolIPIP,
).withName("Encap with IPIP Pool")

var encapWithVXLANPool = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithVXLAN},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: false, VxlanEnabled: true},
).withRoutes(
	routeUpdateIPPoolVXLAN,
).withName("Encap with VXLAN Pool")

var encapWithIPIPAndVXLANPool = empty.withKVUpdates(
	KVPair{Key: ipPoolKey, Value: &ipPoolWithIPIP},
	KVPair{Key: ipPoolKey2, Value: &ipPool2WithVXLAN},
).withExpectedEncapsulation(
	proto.Encapsulation{IpipEnabled: true, VxlanEnabled: true},
).withRoutes(
	routeUpdateIPPoolIPIP,
	routeUpdateIPPool2VXLAN,
).withName("Encap with IPIP and VXLAN Pools")

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
