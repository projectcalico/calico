// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package testutils

import (
	"fmt"

	"github.com/projectcalico/calico/goldmane/proto"
)

// IngestFlows returns n flows with distinct keys, about ten labels per side and a short
// policy trace, all starting at start. The shape approximates a busy cluster's flow logs.
func IngestFlows(n int, start int64) []*proto.Flow {
	out := make([]*proto.Flow, n)
	for i := range n {
		srcNs := fmt.Sprintf("ns-%d", i%50)
		dstNs := fmt.Sprintf("ns-%d", (i/3)%50)
		reporter := proto.Reporter(i % 2)
		polNs := dstNs
		if reporter == proto.Reporter_Src {
			polNs = srcNs
		}
		srcApp := fmt.Sprintf("client-%d", i%500)
		dstApp := fmt.Sprintf("server-%d", (i/7)%300)
		hits := []*proto.PolicyHit{
			{Kind: proto.PolicyKind_CalicoNetworkPolicy, Tier: "security", Name: "allow-dns", Namespace: polNs, Action: proto.Action_Pass, PolicyIndex: 0, RuleIndex: 1},
			{Kind: proto.PolicyKind_NetworkPolicy, Tier: "default", Name: fmt.Sprintf("np-%d", i%40), Namespace: polNs, Action: proto.Action_Allow, PolicyIndex: 1, RuleIndex: int64(i % 3)},
		}
		out[i] = &proto.Flow{
			Key: &proto.FlowKey{
				SourceName:           srcApp + "-7d9f8b6c5-*",
				SourceNamespace:      srcNs,
				SourceType:           proto.EndpointType_WorkloadEndpoint,
				DestName:             dstApp + "-5c6b7d8e9-*",
				DestNamespace:        dstNs,
				DestType:             proto.EndpointType_WorkloadEndpoint,
				DestPort:             int64(8000 + i%17),
				DestServiceName:      dstApp,
				DestServiceNamespace: dstNs,
				DestServicePortName:  "http",
				DestServicePort:      80,
				Proto:                "tcp",
				Reporter:             reporter,
				Action:               proto.Action_Allow,
				Policies: &proto.PolicyTrace{
					EnforcedPolicies: hits,
					PendingPolicies:  hits,
				},
			},
			StartTime:             start,
			EndTime:               start + 15,
			SourceLabels:          ingestLabels(srcApp, srcNs, i),
			DestLabels:            ingestLabels(dstApp, dstNs, i/7),
			PacketsIn:             100,
			PacketsOut:            200,
			BytesIn:               10000,
			BytesOut:              20000,
			NumConnectionsStarted: 1,
			NumConnectionsLive:    1,
		}
	}
	return out
}

func ingestLabels(app, ns string, i int) []string {
	return []string{
		"projectcalico.org/namespace=" + ns,
		"app.kubernetes.io/name=" + app,
		"pod-template-hash=7d9f8b6c5",
		"app.kubernetes.io/instance=" + app + "-prod",
		fmt.Sprintf("app.kubernetes.io/version=v1.%d", i%5),
		"app.kubernetes.io/component=web",
		"app.kubernetes.io/part-of=shop",
		"team=platform",
		"env=prod",
		"projectcalico.org/serviceaccount=default",
	}
}
