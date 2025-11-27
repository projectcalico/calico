// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
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

package flowlog

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	net2 "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	sendCongestionWnd = 10
	smoothRtt         = 1
	minRtt            = 2
	mss               = 4
	localHostEpKey1   = model.HostEndpointKey{
		Hostname:   "localhost",
		EndpointID: "eth1",
	}
	localHostEp1 = &model.HostEndpoint{
		Name:              "eth1",
		ExpectedIPv4Addrs: []net2.IP{utils.MustParseIP("10.0.0.1")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "loc-ep-1",
		}),
	}
	localHostEd1 = &calc.LocalEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(localHostEpKey1, localHostEp1),

		Ingress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{
				{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}: 0,
				{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}: 0,
			},
			TierData: map[string]*calc.TierData{
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(
						v3.KindGlobalNetworkPolicy,
						"default",
						"policy2",
						"",
						calc.RuleIndexTierDefaultAction,
						rules.RuleDirIngress,
						rules.RuleActionDeny,
					),
					EndOfTierMatchIndex: 0,
				},
			},
			ProfileMatchIndex: 0,
		},
		Egress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{
				{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}: 0,
				{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}: 0,
			},
			TierData: map[string]*calc.TierData{
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(
						v3.KindGlobalNetworkPolicy,
						"default",
						"policy2",
						"",
						calc.RuleIndexTierDefaultAction,
						rules.RuleDirIngress,
						rules.RuleActionDeny,
					),
					EndOfTierMatchIndex: 0,
				},
			},
			ProfileMatchIndex: 0,
		},
	}

	remoteHostEpKey1 = model.HostEndpointKey{
		Hostname:   "remotehost",
		EndpointID: "eth1",
	}
	remoteHostEp1 = &model.HostEndpoint{
		Name:              "eth1",
		ExpectedIPv4Addrs: []net2.IP{utils.MustParseIP("20.0.0.1")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "rem-ep-1",
		}),
	}
	remoteHostEd1 = &calc.RemoteEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(remoteHostEpKey1, remoteHostEp1),
	}

	flowMetaDefault = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 1},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 20, 0, 0, 1},
			Proto: 6,
			L4Src: 54123,
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "iperf-4235-5623461",
			AggregatedName: "iperf-4235-*",
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "nginx-412354-5123451",
			AggregatedName: "nginx-412354-*",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaDefaultWithService = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 1},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 20, 0, 0, 1},
			Proto: 6,
			L4Src: 54123,
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "iperf-4235-5623461",
			AggregatedName: "iperf-4235-*",
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "nginx-412354-5123451",
			AggregatedName: "nginx-412354-*",
		},
		DstService: FlowService{
			Namespace: "foo-ns",
			Name:      "foo-svc",
			PortName:  "foo-port",
			PortNum:   8080,
		},
		Action:   "allow",
		Reporter: "dst",
	}

	flowMetaDefaultNoSourceMeta = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 1},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 20, 0, 0, 1},
			Proto: 6,
			L4Src: 54123,
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "net",
			Namespace:      "-",
			Name:           "-",
			AggregatedName: "pvt",
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "nginx-412354-5123451",
			AggregatedName: "nginx-412354-*",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaDefaultNoDestMeta = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 1},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 20, 0, 0, 1},
			Proto: 6,
			L4Src: 54123,
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "iperf-4235-5623461",
			AggregatedName: "iperf-4235-*",
		},
		DstMeta: endpoint.Metadata{
			Type:           "net",
			Namespace:      "-",
			Name:           "-",
			AggregatedName: "pub",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaSourcePorts = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 0, 0, 1},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 20, 0, 0, 1},
			Proto: 6,
			L4Src: -1, // Is the only attribute that gets disregarded.
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "iperf-4235-5623461",
			AggregatedName: "iperf-4235-*",
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "nginx-412354-5123451",
			AggregatedName: "nginx-412354-*",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaPrefix = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1, // Is the only attribute that gets disregarded.
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "-",
			AggregatedName: "iperf-4235-*", // Keeping just the Generate Name
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "-",
			AggregatedName: "nginx-412354-*",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaPrefixNoSourceMeta = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1, // Is the only attribute that gets disregarded.
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "net", // No EndpointMeta associated but Src IP Private
			Namespace:      "-",
			Name:           "-",
			AggregatedName: "pvt",
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "-",
			AggregatedName: "nginx-412354-*",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaPrefixNoDestMeta = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1,
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "-",
			AggregatedName: "iperf-4235-*", // Keeping just the Generate Name
		},
		DstMeta: endpoint.Metadata{
			Type:           "net", // No EndpointMeta associated but Dst IP Public
			Namespace:      "-",
			Name:           "-",
			AggregatedName: "pub",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaPrefixWithName = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1,
			L4Dst: 80,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "-",
			AggregatedName: "iperf-4235-*", // Keeping just the Generate Name
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "-",
			AggregatedName: "manually-created-pod", // Keeping the Name. No Generatename.
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaNoDestPorts = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1, // Is the only attribute that gets disregarded.
			L4Dst: -1,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "-",
			AggregatedName: "iperf-4235-*", // Keeping just the Generate Name
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "-",
			AggregatedName: "nginx-412354-*",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaNoDestPortsWithService = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1, // Is the only attribute that gets disregarded.
			L4Dst: -1,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "-",
			AggregatedName: "iperf-4235-*", // Keeping just the Generate Name
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "-",
			AggregatedName: "nginx-412354-*",
		},
		DstService: FlowService{
			Namespace: "foo-ns",
			Name:      "foo-svc",
			PortName:  "-",
			PortNum:   8080,
		},
		Action:   "allow",
		Reporter: "dst",
	}

	flowMetaNoDestPortNoDestMeta = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1,
			L4Dst: -1,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "kube-system",
			Name:           "-",
			AggregatedName: "iperf-4235-*",
		},
		DstMeta: endpoint.Metadata{
			Type:           "net",
			Namespace:      "-",
			Name:           "-",
			AggregatedName: "pub",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}

	flowMetaNoDestPortNoSourceMeta = FlowMeta{
		Tuple: tuple.Tuple{
			Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Proto: 6,
			L4Src: -1,
			L4Dst: -1,
		},
		SrcMeta: endpoint.Metadata{
			Type:           "net",
			Namespace:      "-",
			Name:           "-",
			AggregatedName: "pvt",
		},
		DstMeta: endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           "-",
			AggregatedName: "nginx-412354-*",
		},
		DstService: EmptyService,
		Action:     "allow",
		Reporter:   "dst",
	}
)

// Common metric Update definitions
var (
	// Metric update without a connection (ingress stats match those of muConn1Rule1AllowUpdate).
	muWithEndpointMeta = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
			),
		},
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muWithEndpointMetaExpire = metric.Update{
		UpdateType: metric.UpdateTypeExpire,
		Tuple:      tuple1,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
			),
		},
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
	}

	muWithEndpointMetaWithService = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
			),
		},
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		DstService: metric.ServiceInfo{
			ServicePortName: proxy.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "foo-ns",
					Name:      "foo-svc",
				},
				Port: "foo-port",
			},
			PortNum: 8080,
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muWithEndpointMetaAndDifferentLabels = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true", "new-label": "true"})},
			),
		},
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "false"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muWithoutSrcEndpointMeta = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp:      nil,
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muWithoutDstEndpointMeta = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
			),
		},
		DstEp:        nil,
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muWithOrigSourceIPs = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp:      nil,
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muWithOrigSourceIPsExpire = metric.Update{
		UpdateType: metric.UpdateTypeExpire,
		Tuple:      tuple1,
		SrcEp:      nil,
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 0,
			DeltaBytes:   0,
		},
	}

	muWithOrigSourceIPsUnknownRuleID = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp:      nil,
		DstEp:      nil,
		UnknownRuleID: &calc.RuleID{
			PolicyID: calc.PolicyID{
				Name:      "__UNKNOWN__",
				Namespace: "__UNKNOWN__",
			},
			Index:     -2,
			IndexStr:  "-2",
			Action:    rules.RuleActionAllow,
			Direction: rules.RuleDirIngress,
		},
		IsConnection: false,
	}

	muWithMultipleOrigSourceIPs = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp:      nil,
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muWithEndpointMetaWithoutGenerateName = metric.Update{
		UpdateType: metric.UpdateTypeReport,
		Tuple:      tuple1,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
			),
		},
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/manually-created-pod",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	// Metric update without a connection (ingress stats match those of muConn1Rule1AllowUpdate).
	muWithSNATPort = metric.Update{
		UpdateType:      metric.UpdateTypeReport,
		Tuple:           tuple1,
		NatOutgoingPort: 6789,
		SrcEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-01",
					OrchestratorID: "k8s",
					WorkloadID:     "kube-system/iperf-4235-5623461",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
			),
		},
		DstEp: &calc.RemoteEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(
				model.WorkloadEndpointKey{
					Hostname:       "node-02",
					OrchestratorID: "k8s",
					WorkloadID:     "default/nginx-412354-5123451",
					EndpointID:     "4352",
				},
				&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
			),
		},
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muConn1Rule1AllowExpire = metric.Update{
		UpdateType:   metric.UpdateTypeExpire,
		Tuple:        tuple1,
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:  false,
		IsConnection: true,
		InMetric: metric.Value{
			DeltaPackets: 4,
			DeltaBytes:   44,
		},
		OutMetric: metric.Value{
			DeltaPackets: 3,
			DeltaBytes:   24,
		},
	}

	muNoConn3Rule2DenyUpdate = metric.Update{
		UpdateType:   metric.UpdateTypeReport,
		Tuple:        tuple3,
		RuleIDs:      []*calc.RuleID{egressRule2Deny},
		HasDenyRule:  true,
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   40,
		},
	}

	muNoConn3Rule2DenyExpire = metric.Update{
		UpdateType:   metric.UpdateTypeExpire,
		Tuple:        tuple3,
		RuleIDs:      []*calc.RuleID{egressRule2Deny},
		HasDenyRule:  true,
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 0,
			DeltaBytes:   0,
		},
	}

	muConn2Rule1AllowUpdate = metric.Update{
		UpdateType:   metric.UpdateTypeReport,
		Tuple:        tuple2,
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:  false,
		IsConnection: true,
		InMetric: metric.Value{
			DeltaPackets: 7,
			DeltaBytes:   77,
		},
	}

	muConn2Rule1AllowExpire = metric.Update{
		UpdateType:   metric.UpdateTypeExpire,
		Tuple:        tuple2,
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:  false,
		IsConnection: true,
		InMetric: metric.Value{
			DeltaPackets: 8,
			DeltaBytes:   88,
		},
	}
)
