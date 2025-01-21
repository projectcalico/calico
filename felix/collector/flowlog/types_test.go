// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/boundedset"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("FlowMeta construction from metric Update", func() {
	DescribeTable("generates the correct FlowMeta using",
		func(input metric.Update, aggregation AggregationKind, expected FlowMeta) {
			var flowMeta FlowMeta
			var err error

			flowMeta, err = NewFlowMeta(input, aggregation, true)
			Expect(err).To(BeNil())
			Expect(flowMeta).Should(Equal(expected))
		},
		Entry("full endpoints and prefix aggregation", muWithEndpointMeta, FlowPrefixName, flowMetaPrefix),
		Entry("no source endpoints and prefix aggregation", muWithoutSrcEndpointMeta, FlowPrefixName, flowMetaPrefixNoSourceMeta),
		Entry("no destination endpoints and prefix aggregation", muWithoutDstEndpointMeta, FlowPrefixName, flowMetaPrefixNoDestMeta),
		Entry("no generated name and prefix aggregation", muWithEndpointMetaWithoutGenerateName, FlowPrefixName, flowMetaPrefixWithName),
	)
})

func consists(actual, expected []FlowProcessReportedStats) bool {
	count := 0
	for _, expflow := range expected {
		for _, actFlow := range actual {
			if compareProcessReportedStats(expflow, actFlow) {
				count = count + 1
			}
		}
	}
	return count == len(expected)
}

var _ = Describe("Flow log types tests", func() {
	Context("FlowExtraRef from metric Update", func() {
		It("generates the correct flowExtrasRef", func() {
			By("Extracting the correct information")
			fe := NewFlowExtrasRef(muWithOrigSourceIPs, testMaxBoundedSetSize)
			expectedFlowExtraRef := flowExtrasRef{
				originalSourceIPs: boundedset.NewFromSlice(testMaxBoundedSetSize, []net.IP{net.ParseIP("1.0.0.1")}),
			}
			Expect(fe.originalSourceIPs.ToIPSlice()).Should(ConsistOf(expectedFlowExtraRef.originalSourceIPs.ToIPSlice()))
			Expect(fe.originalSourceIPs.TotalCount()).Should(Equal(expectedFlowExtraRef.originalSourceIPs.TotalCount()))
			Expect(fe.originalSourceIPs.TotalCountDelta()).Should(Equal(expectedFlowExtraRef.originalSourceIPs.TotalCountDelta()))

			By("aggregating the metric update")
			fe.aggregateFlowExtrasRef(muWithMultipleOrigSourceIPs)
			expectedFlowExtraRef = flowExtrasRef{
				originalSourceIPs: boundedset.NewFromSlice(testMaxBoundedSetSize, []net.IP{net.ParseIP("1.0.0.1"), net.ParseIP("2.0.0.2")}),
			}
			Expect(fe.originalSourceIPs.ToIPSlice()).Should(ConsistOf(expectedFlowExtraRef.originalSourceIPs.ToIPSlice()))
			Expect(fe.originalSourceIPs.TotalCount()).Should(Equal(expectedFlowExtraRef.originalSourceIPs.TotalCount()))
			Expect(fe.originalSourceIPs.TotalCountDelta()).Should(Equal(expectedFlowExtraRef.originalSourceIPs.TotalCountDelta()))
		})
	})

	Context("FlowStatsByProcess from metric Update", func() {
		It("stores the correct FlowStatsByProcess with including process information is disabled", func() {
			By("Extracting the correct information")
			fsp := NewFlowStatsByProcess(&muWithEndpointMeta, false, 3)
			Expect(fsp.statsByProcessName).Should(HaveLen(1))
			Expect(fsp.statsByProcessName).Should(HaveKey("-"))
			expectedReportedStats := []FlowProcessReportedStats{
				FlowProcessReportedStats{
					FlowReportedStats: FlowReportedStats{
						PacketsIn:         1,
						PacketsOut:        0,
						BytesIn:           20,
						BytesOut:          0,
						NumFlows:          1,
						NumFlowsStarted:   1,
						NumFlowsCompleted: 0,
					},
				},
			}
			Expect(fsp.getActiveFlowsCount()).Should(Equal(1))
			Expect(consists(fsp.toFlowProcessReportedStats(), expectedReportedStats)).Should(Equal(true))

			By("aggregating the metric update")
			fsp.aggregateFlowStatsByProcess(&muWithEndpointMetaWithService)
			Expect(fsp.statsByProcessName).Should(HaveLen(1))
			Expect(fsp.statsByProcessName).Should(HaveKey("-"))
			expectedReportedStats = []FlowProcessReportedStats{
				FlowProcessReportedStats{
					FlowReportedStats: FlowReportedStats{
						PacketsIn:         2,
						PacketsOut:        0,
						BytesIn:           40,
						BytesOut:          0,
						NumFlows:          1,
						NumFlowsStarted:   1,
						NumFlowsCompleted: 0,
					},
				},
			}
			Expect(fsp.getActiveFlowsCount()).Should(Equal(1))
			Expect(consists(fsp.toFlowProcessReportedStats(), expectedReportedStats)).Should(Equal(true))

			By("aggregating the metric update with update type expire")
			fsp.aggregateFlowStatsByProcess(&muWithEndpointMetaExpire)
			Expect(fsp.statsByProcessName).Should(HaveLen(1))
			Expect(fsp.statsByProcessName).Should(HaveKey("-"))
			expectedReportedStats = []FlowProcessReportedStats{
				FlowProcessReportedStats{
					FlowReportedStats: FlowReportedStats{
						PacketsIn:         2,
						PacketsOut:        0,
						BytesIn:           40,
						BytesOut:          0,
						NumFlows:          1,
						NumFlowsStarted:   1,
						NumFlowsCompleted: 1,
					},
				},
			}
			Expect(fsp.getActiveFlowsCount()).Should(Equal(0))
			Expect(consists(fsp.toFlowProcessReportedStats(), expectedReportedStats)).Should(Equal(true))

			By("cleaning up the stats for the process name")
			remainingActiveFlowsCount := fsp.gc()
			Expect(remainingActiveFlowsCount).Should(Equal(0))
			Expect(fsp.statsByProcessName).Should(HaveLen(0))
		})
	})
})

type TraceAndMetrics struct {
	Traces  []FlowPolicySet
	Packets int
	Bytes   int
}

func setEgressTraceAndMetrics(mu metric.Update, egress []*calc.RuleID, bytesOut, packetsOut int) *metric.Update {
	mu.RuleIDs = egress
	mu.OutMetric = metric.Value{
		DeltaPackets: packetsOut,
		DeltaBytes:   bytesOut,
	}
	return &mu
}

var _ = Describe("FlowPolicySets", func() {
	var ca *Aggregator

	egress1 := calc.NewRuleID("tier1", "policy1", "namespace1", 0, rules.RuleDirEgress, rules.RuleActionAllow)
	egress2 := calc.NewRuleID("tier2", "policy2", "namespace2", 1, rules.RuleDirEgress, rules.RuleActionAllow)
	egress3 := calc.NewRuleID("tier3", "policy3", "namespace3", 3, rules.RuleDirEgress, rules.RuleActionAllow)
	egress4 := calc.NewRuleID("tier4", "policy4", "namespace4", 1, rules.RuleDirEgress, rules.RuleActionAllow)

	BeforeEach(func() {
		ca = NewAggregator()
	})

	DescribeTable("splits up FlowStore into multiple FlowLogs for multiple items in the FlowPolicySets",
		func(mus []*metric.Update, aggregation AggregationKind, expected TraceAndMetrics) {
			ca.IncludePolicies(true)
			for _, mu := range mus {
				Expect(ca.FeedUpdate(mu)).NotTo(HaveOccurred())
			}
			flowlogs := ca.GetAndCalibrate()

			// Validate
			Expect(len(flowlogs)).Should(Equal(len(expected.Traces)))

			for i := 0; i < len(flowlogs); i++ {
				Expect(flowlogs[i].FlowPolicySet).Should(Equal(expected.Traces[i]))
				Expect(flowlogs[i].FlowProcessReportedStats.PacketsOut).Should(Equal(expected.Packets))
				Expect(flowlogs[i].FlowProcessReportedStats.BytesOut).Should(Equal(expected.Bytes))
			}
		},
		Entry("muWithEndpointMeta, FlowPrefixName",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1, egress2, egress3, egress4}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1, egress4}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1, egress2, egress4, egress3}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1, egress2, egress3, egress4}, 54, 2),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1, egress2, egress4, egress3}, 6, 1),
			},
			FlowPrefixName,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.policy1|allow|0": emptyValue, "1|tier2|namespace2/tier2.policy2|allow|1": emptyValue, "2|tier3|namespace3/tier3.policy3|allow|3": emptyValue, "3|tier4|namespace4/tier4.policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.policy1|allow|0": emptyValue, "1|tier4|namespace4/tier4.policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.policy1|allow|0": emptyValue, "1|tier2|namespace2/tier2.policy2|allow|1": emptyValue, "2|tier4|namespace4/tier4.policy4|allow|1": emptyValue, "3|tier3|namespace3/tier3.policy3|allow|3": emptyValue},
				},
				Packets: 21,
				Bytes:   246,
			},
		),
	)
})
