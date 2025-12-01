// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowlog

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	srcPort1 = 54123
	srcPort2 = 54124
	srcPort3 = 54125
	srcPort4 = 54125
	srcPort5 = 54126
	srcPort6 = 54127
	dstPort  = 80
)

// Common Tuple definitions
var (
	tuple1 = tuple.Make(localIp1, remoteIp1, proto_tcp, srcPort1, dstPort)
	tuple2 = tuple.Make(localIp1, remoteIp2, proto_tcp, srcPort2, dstPort)
	tuple3 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort1, dstPort)
	tuple4 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort4, dstPort)
	tuple5 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort5, dstPort)
	tuple6 = tuple.Make(localIp2, remoteIp1, proto_tcp, srcPort6, dstPort)
	tuple7 = tuple.Make(EmptyIP, EmptyIP, proto_tcp, unsetIntField, dstPort)
)

var (
	proto_tcp         = 6
	localIp1Str       = "10.0.0.1"
	localIp1          = utils.IpStrTo16Byte(localIp1Str)
	localIp2Str       = "10.0.0.2"
	localIp2          = utils.IpStrTo16Byte(localIp2Str)
	remoteIp1Str      = "20.0.0.1"
	remoteIp1         = utils.IpStrTo16Byte(remoteIp1Str)
	remoteIp2Str      = "20.0.0.2"
	remoteIp2         = utils.IpStrTo16Byte(remoteIp2Str)
	publicIP1Str      = "1.0.0.1"
	publicIP2Str      = "2.0.0.2"
	ingressRule1Allow = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"default",
		"policy1",
		"",
		0,
		rules.RuleDirIngress,
		rules.RuleActionAllow,
	)
	egressRule2Deny = calc.NewRuleID(
		v3.KindGlobalNetworkPolicy,
		"default",
		"policy2",
		"",
		0,
		rules.RuleDirEgress,
		rules.RuleActionDeny,
	)
)

// Common MetricUpdate definitions
var (
	// Metric update without a connection (ingress stats match those of muConn1Rule1AllowUpdate).
	muNoConn1Rule1AllowUpdate = metric.Update{
		UpdateType:   metric.UpdateTypeReport,
		Tuple:        tuple1,
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:  false,
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	muNoConn1Rule2DenyUpdate = metric.Update{
		UpdateType:   metric.UpdateTypeReport,
		Tuple:        tuple1,
		RuleIDs:      []*calc.RuleID{egressRule2Deny},
		HasDenyRule:  true,
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   40,
		},
	}

	// Metric update without a connection (ingress stats match those of muConn1Rule1AllowUpdate).
	muNoConn1Rule1AllowUpdateWithEndpointMeta = metric.Update{
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
		HasDenyRule:  false,
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 1,
			DeltaBytes:   20,
		},
	}

	// Identical rule/direction connections with differing tuples
	muConn1Rule1AllowUpdate = metric.Update{
		UpdateType:   metric.UpdateTypeReport,
		Tuple:        tuple1,
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		IsConnection: true,
		HasDenyRule:  false,
		InMetric: metric.Value{
			DeltaPackets: 2,
			DeltaBytes:   22,
		},
		OutMetric: metric.Value{
			DeltaPackets: 3,
			DeltaBytes:   33,
		},
	}

	muConn1Rule1HTTPReqAllowUpdate = metric.Update{
		UpdateType:   metric.UpdateTypeReport,
		Tuple:        tuple1,
		RuleIDs:      []*calc.RuleID{ingressRule1Allow},
		HasDenyRule:  false,
		IsConnection: true,
		InMetric: metric.Value{
			DeltaPackets: 200,
			DeltaBytes:   22000,
		},
		OutMetric: metric.Value{
			DeltaPackets: 300,
			DeltaBytes:   33000,
		},
	}

	muNoConn1Rule2DenyExpire = metric.Update{
		UpdateType:   metric.UpdateTypeExpire,
		Tuple:        tuple1,
		RuleIDs:      []*calc.RuleID{egressRule2Deny},
		HasDenyRule:  true,
		IsConnection: false,
		InMetric: metric.Value{
			DeltaPackets: 0,
			DeltaBytes:   0,
		},
	}
)

func checkProcessArgs(actual, expected []string, numArgs int) bool {
	count := 0
	actualArgSet := set.New[string]()
	for _, a := range actual {
		actualArgSet.Add(a)
	}
	if actualArgSet.Len() != numArgs {
		return false
	}
	for arg := range actualArgSet.All() {
		for _, e := range expected {
			if arg == e {
				count = count + 1
			}
		}
	}
	return count == numArgs
}

// compareProcessReportedStats compares FlowProcessReportedStats. With process Args
// being aggregated into a list, and the order in which these args are added of the
// arguments is not guaranteed, explicitly iterate over the args list and compare.
func compareProcessReportedStats(actual, expected FlowProcessReportedStats) bool {
	return actual.FlowReportedStats == expected.FlowReportedStats
}

var _ = Describe("Flow log aggregator tests", func() {
	// TODO(SS): Pull out the convenience functions for re-use.

	expectFlowLog := func(fl FlowLog, t tuple.Tuple, nf, nfs, nfc int, a Action, fr ReporterType, pi, po, bi, bo int, sm, dm endpoint.Metadata, dsvc FlowService, sl, dl map[string]string, fep, fpp FlowPolicySet) {
		expectedFlow := newExpectedFlowLog(t, nf, nfs, nfc, a, fr, pi, po, bi, bo, sm, dm, dsvc, sl, dl, fep, fpp)

		// We don't include the start and end time in the comparison, so copy to a new log without these
		var flNoTime FlowLog
		flNoTime.FlowMeta = fl.FlowMeta
		flNoTime.FlowLabels = fl.FlowLabels
		flNoTime.FlowEnforcedPolicySet = fl.FlowEnforcedPolicySet
		flNoTime.FlowPendingPolicySet = fl.FlowPendingPolicySet

		var expFlowNoProc FlowLog
		expFlowNoProc.FlowMeta = expectedFlow.FlowMeta
		expFlowNoProc.FlowLabels = expectedFlow.FlowLabels
		expFlowNoProc.FlowEnforcedPolicySet = expectedFlow.FlowEnforcedPolicySet
		expFlowNoProc.FlowPendingPolicySet = expectedFlow.FlowPendingPolicySet

		Expect(flNoTime).Should(Equal(expFlowNoProc))
	}

	calculatePacketStats := func(mus ...metric.Update) (epi, epo, ebi, ebo int) {
		for _, mu := range mus {
			epi += mu.InMetric.DeltaPackets
			epo += mu.OutMetric.DeltaPackets
			ebi += mu.InMetric.DeltaBytes
			ebo += mu.OutMetric.DeltaBytes
		}
		return
	}

	Context("Flow log aggregator aggregation verification", func() {
		var ca *Aggregator

		BeforeEach(func() {
			ca = NewAggregator()
		})

		It("aggregates the fed metric updates", func() {
			By("endpoint prefix names")
			ca = NewAggregator()
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			// Construct a similar update; same tuple but diff src ports.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta
			// TODO(SS): Handle and organize these test constants better. Right now they are all over the places
			// like reporter_prometheus_test.go, collector_test.go , etc.
			tuple1Copy := tuple1
			// Everything can change in the 5-tuple except for the dst port.
			tuple1Copy.L4Src = 44123
			tuple1Copy.Src = utils.IpStrTo16Byte("10.0.0.3")
			tuple1Copy.Dst = utils.IpStrTo16Byte("10.0.0.9")
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.Tuple = tuple1Copy

			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5434134",
						EndpointID:     "23456",
					},
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-6543645",
						EndpointID:     "256267",
					},
					&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
				),
			}

			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate()
			// Two updates should still result in 1 flow
			Expect(len(messages)).Should(Equal(1))
			// Updating the Workload IDs and labels for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5434134",
						EndpointID:     "23456",
					},
					// this new MetricUpdates src endpointMeta has a different label than one currently being tracked.
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"prod-app": "true"})},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-6543645",
						EndpointID:     "256267",
					},
					// different label on the destination workload than one being tracked.
					&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "false"})},
				),
			}

			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate()
			// Two updates should still result in 1 flow
			Expect(len(messages)).Should(Equal(1))

			By("by endpoint IP classification as the meta name when meta info is missing")
			ca = NewAggregator()
			endpointMeta := calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5623461",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
				),
			}

			muWithoutDstEndpointMeta := metric.Update{
				UpdateType:   metric.UpdateTypeReport,
				Tuple:        tuple.Make(utils.IpStrTo16Byte("192.168.0.4"), utils.IpStrTo16Byte("192.168.0.14"), proto_tcp, srcPort1, dstPort),
				SrcEp:        &endpointMeta, // src endpoint meta info available
				DstEp:        nil,           // dst endpoint meta info not available
				RuleIDs:      []*calc.RuleID{ingressRule1Allow},
				HasDenyRule:  false,
				IsConnection: false,
				InMetric: metric.Value{
					DeltaPackets: 1,
					DeltaBytes:   20,
				},
			}
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMeta)).NotTo(HaveOccurred())

			// Another metric update comes in. This time on a different dst private IP
			muWithoutDstEndpointMetaCopy := muWithoutDstEndpointMeta
			muWithoutDstEndpointMetaCopy.Tuple.Dst = utils.IpStrTo16Byte("192.168.0.17")
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate()
			// One flow expected: srcMeta.GenerateName -> pvt
			// Two updates should still result in 1 flow
			Expect(len(messages)).Should(Equal(1))

			// Initial Update
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMeta)).NotTo(HaveOccurred())
			// + metric update comes in. This time on a non-private dst IP
			muWithoutDstEndpointMetaCopy.Tuple.Dst = utils.IpStrTo16Byte("198.17.8.43")
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate()
			// 2nd flow expected: srcMeta.GenerateName -> pub
			// Three updates so far should result in 2 flows
			Expect(len(messages)).Should(Equal(2)) // Metric Update comes in with a non private as the dst IP

			// Initial Updates
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMeta)).NotTo(HaveOccurred())
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			// + metric update comes in. This time with missing src endpointMeta
			muWithoutDstEndpointMetaCopy.SrcEp = nil
			muWithoutDstEndpointMetaCopy.DstEp = &endpointMeta
			Expect(ca.FeedUpdate(&muWithoutDstEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate()

			// 3rd flow expected: pvt -> dst.GenerateName
			// Four updates so far should result in 3 flows
			Expect(len(messages)).Should(Equal(3)) // Metric Update comes in with a non private as the dst IP

			// Confirm the expected flow metas
			fm1 := FlowMeta{
				Tuple: tuple.Tuple{
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Proto: 6,
					L4Src: unsetIntField,
					L4Dst: 80,
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

			fm2 := FlowMeta{
				Tuple: tuple.Tuple{
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Proto: 6,
					L4Src: unsetIntField,
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
					Namespace:      "kube-system",
					Name:           "-",
					AggregatedName: "iperf-4235-*",
				},
				DstService: EmptyService,
				Action:     "allow",
				Reporter:   "dst",
			}

			fm3 := FlowMeta{
				Tuple: tuple.Tuple{
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Proto: 6,
					L4Src: unsetIntField,
					L4Dst: 80,
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
					AggregatedName: "pvt",
				},
				DstService: EmptyService,
				Action:     "allow",
				Reporter:   "dst",
			}

			flowLogMetas := []FlowMeta{}
			for _, fl := range messages {
				flowLogMetas = append(flowLogMetas, fl.FlowMeta)
			}

			Expect(flowLogMetas).Should(ConsistOf(fm1, fm2, fm3))
		})

		It("aggregates labels from metric updates", func() {
			By("intersecting labels in FlowSpec when IncludeLabels configured")
			ca := NewAggregator().IncludeLabels(true)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())

			// Construct a similar update; but the endpoints have different labels
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta
			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5623461",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "iperf-4235-",
						Labels:       uniquelabels.Make(map[string]string{"test-app": "true", "new-label": "true"}), // "new-label" appended
					},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-5123451",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "nginx-412354-",
						Labels:       uniquelabels.Make(map[string]string{"k8s-app": "false"}), // conflicting labels; originally "k8s-app": "true"
					},
				),
			}
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate()
			// Since the FlowMeta remains the same it should still equal 1.
			Expect(len(messages)).Should(Equal(1))
			message := *(messages[0])

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			srcMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "kube-system",
				Name:           "-",
				AggregatedName: "iperf-4235-*",
			}
			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "-",
				AggregatedName: "nginx-412354-*",
			}
			// The labels should have been intersected correctly.
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectFlowLog(message, tuple7, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn*2, expectedPacketsOut, expectedBytesIn*2, expectedBytesOut, srcMeta, dstMeta, EmptyService, map[string]string{"test-app": "true"}, map[string]string{}, nil, nil)

			By("not affecting flow logs when IncludeLabels is disabled")
			ca = NewAggregator().IncludeLabels(false)
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())

			// Construct a similar update; but the endpoints have different labels
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy = muNoConn1Rule1AllowUpdateWithEndpointMeta
			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5623461",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "iperf-4235-",
						Labels:       uniquelabels.Make(map[string]string{"test-app": "true", "new-label": "true"}), // "new-label" appended
					},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-5123451",
						EndpointID:     "4352",
					},
					&model.WorkloadEndpoint{
						GenerateName: "nginx-412354-",
						Labels:       uniquelabels.Make(map[string]string{"k8s-app": "false"}), // conflicting labels; originally "k8s-app": "true"
					},
				),
			}
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate()
			// Since the FlowMeta remains the same it should still equal 1.
			Expect(len(messages)).Should(Equal(1))
			message = *(messages[0])

			expectedNumFlows = 1
			expectedNumFlowsStarted = 1
			expectedNumFlowsCompleted = 0
			srcMeta = endpoint.Metadata{
				Type:           "wep",
				Namespace:      "kube-system",
				Name:           "-",
				AggregatedName: "iperf-4235-*",
			}
			dstMeta = endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "-",
				AggregatedName: "nginx-412354-*",
			}
			// The labels should have been intersected right.
			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut = calculatePacketStats(muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)
			expectFlowLog(message, tuple7, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn*2, expectedPacketsOut, expectedBytesIn*2, expectedBytesOut, srcMeta, dstMeta, EmptyService, nil, nil, nil, nil) // nil & nil for Src and Dst Labels respectively.
		})

		It("GetAndCalibrate does not cause a data race contention on the flowEntry after FeedUpdate adds it to the flowStore", func() {
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta

			var messages []*FlowLog

			time.AfterFunc(2*time.Second, func() {
				Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			})

			// ok GetAndCalibrate is a little after feedupdate because feedupdate has some preprocesssing
			// before ti accesses flowstore
			time.AfterFunc(2*time.Second+10*time.Millisecond, func() {
				messages = ca.GetAndCalibrate()
			})

			time.Sleep(3 * time.Second)
			Expect(len(messages)).Should(Equal(1))

			message := messages[0]

			expectedNumFlows := 1
			expectedNumFlowsStarted := 1
			expectedNumFlowsCompleted := 0
			srcMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "kube-system",
				Name:           "-",
				AggregatedName: "iperf-4235-*",
			}
			dstMeta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           "-",
				AggregatedName: "nginx-412354-*",
			}

			expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut := calculatePacketStats(muNoConn1Rule1AllowUpdateWithEndpointMeta)
			expectFlowLog(*message, tuple7, expectedNumFlows, expectedNumFlowsStarted, expectedNumFlowsCompleted, ActionAllow, ReporterDst,
				expectedPacketsIn, expectedPacketsOut, expectedBytesIn, expectedBytesOut, srcMeta, dstMeta, EmptyService, nil, nil, nil, nil)
		})
	})

	Context("Flow log aggregator service aggregation", func() {
		service := FlowService{Namespace: "foo-ns", Name: "foo-svc", PortName: "foo-port", PortNum: 8080}
		It("Does not aggregate endpoints with and without service with FlowPrefixName aggregation", func() {
			By("Creating an aggregator for allow")
			caa := NewAggregator().ForAction(rules.RuleActionAllow).IncludeService(true)

			By("Feeding two updates one with service, one without (otherwise identical)")
			_ = caa.FeedUpdate(&muWithEndpointMeta)
			_ = caa.FeedUpdate(&muWithEndpointMetaWithService)

			By("Checking calibration")
			messages := caa.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(2))
			services := []FlowService{messages[0].DstService, messages[1].DstService}
			Expect(services).To(ConsistOf(EmptyService, service))
		})
	})

	Context("Flow log aggregator filter verification", func() {
		It("Filters out MetricUpdate based on filter applied", func() {
			By("Creating 2 aggregators - one for denied packets, and one for allowed packets")
			var caa, cad *Aggregator

			By("Checking that the MetricUpdate with deny action is only processed by the aggregator with the deny filter")
			caa = NewAggregator().ForAction(rules.RuleActionAllow)
			cad = NewAggregator().ForAction(rules.RuleActionDeny)

			Expect(caa.FeedUpdate(&muNoConn1Rule2DenyUpdate)).NotTo(HaveOccurred())
			messages := caa.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(0))
			Expect(cad.FeedUpdate(&muNoConn1Rule2DenyUpdate)).NotTo(HaveOccurred())
			messages = cad.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(1))

			By("Checking that the MetricUpdate with allow action is only processed by the aggregator with the allow filter")
			caa = NewAggregator().ForAction(rules.RuleActionAllow)
			cad = NewAggregator().ForAction(rules.RuleActionDeny)

			Expect(caa.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages = caa.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(1))
			Expect(cad.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages = cad.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(0))
		})
	})

	Context("Flow log aggregator http request countes", func() {
		It("Aggregates HTTP allowed and denied packets", func() {
			By("Feeding in two updates containing HTTP request counts")
			ca := NewAggregator().ForAction(rules.RuleActionAllow)
			Expect(ca.FeedUpdate(&muConn1Rule1HTTPReqAllowUpdate)).NotTo(HaveOccurred())
			Expect(ca.FeedUpdate(&muConn1Rule1HTTPReqAllowUpdate)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(1))
			// StartedFlowRefs count should be 1
			flowLog := messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(1))
		})
	})

	Context("Flow log aggregator flowstore lifecycle", func() {
		It("Purges only the completed aggregated flowMetas", func() {
			By("Accounting for only the completed 5-tuple refs when making a purging decision")
			ca := NewAggregator()
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			// Construct a similar update; same tuple but diff src ports.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy := muNoConn1Rule1AllowUpdateWithEndpointMeta
			tuple1Copy := tuple1
			// Everything can change in the 5-tuple except for the dst port.
			tuple1Copy.L4Src = 44123
			tuple1Copy.Src = utils.IpStrTo16Byte("10.0.0.3")
			tuple1Copy.Dst = utils.IpStrTo16Byte("10.0.0.9")
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.Tuple = tuple1Copy

			// Updating the Workload IDs for src and dst.
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.SrcEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-01",
						OrchestratorID: "k8s",
						WorkloadID:     "kube-system/iperf-4235-5434134",
						EndpointID:     "23456",
					},
					&model.WorkloadEndpoint{GenerateName: "iperf-4235-", Labels: uniquelabels.Make(map[string]string{"test-app": "true"})},
				),
			}

			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.DstEp = &calc.RemoteEndpointData{
				CommonEndpointData: calc.CalculateCommonEndpointData(
					model.WorkloadEndpointKey{
						Hostname:       "node-02",
						OrchestratorID: "k8s",
						WorkloadID:     "default/nginx-412354-6543645",
						EndpointID:     "256267",
					},
					&model.WorkloadEndpoint{GenerateName: "nginx-412354-", Labels: uniquelabels.Make(map[string]string{"k8s-app": "true"})},
				),
			}

			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate()
			// Two updates should still result in 1 flowMeta
			Expect(len(messages)).Should(Equal(1))
			// flowStore is not purged of the entry since the flowRefs havn't been expired
			Expect(len(ca.flowStore)).Should(Equal(1))
			// And the no. of Started Flows should be 2
			flowLog := messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(2))

			// Update one of the two flows and expire the other.
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			muNoConn1Rule1AllowUpdateWithEndpointMetaCopy.UpdateType = metric.UpdateTypeExpire
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMetaCopy)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(1))
			// flowStore still carries that 1 flowMeta
			Expect(len(ca.flowStore)).Should(Equal(1))
			flowLog = messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(0))
			Expect(flowLog.NumFlowsCompleted).Should(Equal(1))
			Expect(flowLog.NumFlows).Should(Equal(2))

			// Expire the sole flowRef
			muNoConn1Rule1AllowUpdateWithEndpointMeta.UpdateType = metric.UpdateTypeExpire
			Expect(ca.FeedUpdate(&muNoConn1Rule1AllowUpdateWithEndpointMeta)).NotTo(HaveOccurred())
			// Pre-purge/Dispatch the meta still lingers
			Expect(len(ca.flowStore)).Should(Equal(1))
			// On a dispatch the flowMeta is eventually purged
			messages = ca.GetAndCalibrate()
			Expect(len(ca.flowStore)).Should(Equal(0))
			flowLog = messages[0]
			Expect(flowLog.NumFlowsStarted).Should(Equal(0))
			Expect(flowLog.NumFlowsCompleted).Should(Equal(1))
			Expect(flowLog.NumFlows).Should(Equal(1))
		})

		It("Updates the stats associated with the flows", func() {
			By("Accounting for only the packet/byte counts as seen during the interval")
			ca := NewAggregator().ForAction(rules.RuleActionAllow)
			Expect(ca.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages := ca.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(1))
			// After the initial update the counts as expected.
			flowLog := messages[0]
			Expect(flowLog.PacketsIn).Should(Equal(2))
			Expect(flowLog.BytesIn).Should(Equal(22))
			Expect(flowLog.PacketsOut).Should(Equal(3))
			Expect(flowLog.BytesOut).Should(Equal(33))

			// The flow doesn't expire. But the Get should reset the stats.
			// A new update on top, then, should result in the same counts
			Expect(ca.FeedUpdate(&muConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			messages = ca.GetAndCalibrate()
			Expect(len(messages)).Should(Equal(1))
			// After the initial update the counts as expected.
			flowLog = messages[0]
			Expect(flowLog.PacketsIn).Should(Equal(2))
			Expect(flowLog.BytesIn).Should(Equal(22))
			Expect(flowLog.PacketsOut).Should(Equal(3))
			Expect(flowLog.BytesOut).Should(Equal(33))
		})
	})
})
