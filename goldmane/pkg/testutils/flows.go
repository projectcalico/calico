package testutils

import (
	"math/rand/v2"

	"github.com/projectcalico/calico/goldmane/proto"
)

func NewRandomFlow(start int64) *proto.Flow {
	srcNames := map[int]string{
		0: "client-aggr-1",
		1: "client-aggr-2",
		2: "client-aggr-3",
		3: "client-aggr-4",
	}
	dstNames := map[int]string{
		0: "server-aggr-1",
		1: "server-aggr-2",
		2: "server-aggr-3",
		3: "server-aggr-4",
	}
	actions := map[int]proto.Action{
		0: proto.Action_Allow,
		1: proto.Action_Deny,
	}
	reporters := map[int]proto.Reporter{
		0: proto.Reporter_Src,
		1: proto.Reporter_Dst,
	}
	services := map[int]string{
		0: "frontend-service",
		1: "backend-service",
		2: "db-service",
	}
	namespaces := map[int]string{
		0: "test-ns",
		1: "test-ns-2",
		2: "test-ns-3",
	}
	tiers := map[int]string{
		0: "tier-1",
		1: "tier-2",
		2: "default",
	}
	policies := map[int]string{
		0: "policy-1",
		1: "policy-2",
	}
	indices := map[int]int64{
		0: 0,
		1: 1,
		2: 2,
		3: 3,
	}

	dstNs := randomFromMap(namespaces)
	srcNs := randomFromMap(namespaces)
	action := randomFromMap(actions)
	reporter := randomFromMap(reporters)
	polNs := dstNs
	if reporter == proto.Reporter_Src {
		polNs = srcNs
	}
	f := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:           randomFromMap(srcNames),
			SourceNamespace:      srcNs,
			DestName:             randomFromMap(dstNames),
			DestNamespace:        dstNs,
			Proto:                "tcp",
			Action:               action,
			Reporter:             reporter,
			DestServiceName:      randomFromMap(services),
			DestServicePort:      80,
			DestServiceNamespace: dstNs,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_CalicoNetworkPolicy,
						Tier:        randomFromMap(tiers),
						Name:        randomFromMap(policies),
						Namespace:   polNs,
						Action:      action,
						PolicyIndex: randomFromMap(indices),
						RuleIndex:   0,
					},
					{
						Kind:        proto.PolicyKind_CalicoNetworkPolicy,
						Tier:        "default",
						Name:        "default-allow",
						Namespace:   "default",
						Action:      proto.Action_Allow,
						PolicyIndex: 1,
						RuleIndex:   1,
					},
				},
			},
		},
		StartTime:               start,
		EndTime:                 start + 1,
		BytesIn:                 100,
		BytesOut:                200,
		PacketsIn:               10,
		PacketsOut:              20,
		NumConnectionsStarted:   1,
		NumConnectionsLive:      2,
		NumConnectionsCompleted: 3,
	}

	// For now, just copy the enforced policies to the pending policies. This is
	// equivalent to there being no staged policies in the trace.
	f.Key.Policies.PendingPolicies = f.Key.Policies.EnforcedPolicies
	return f
}

func randomFromMap[E comparable](m map[int]E) E {
	// Generate a random number within the size of the map.
	return m[rand.IntN(len(m))]
}
