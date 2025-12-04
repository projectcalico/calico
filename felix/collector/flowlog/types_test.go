// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
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

type TraceAndMetrics struct {
	Traces         []FlowPolicySet
	EnforcedTraces []FlowPolicySet
	PendingTrace   FlowPolicySet
	Packets        int
	Bytes          int
}

func setEgressTraceAndMetrics(mu metric.Update, egress, pendingEgress []*calc.RuleID, bytesOut, packetsOut int) *metric.Update {
	mu.RuleIDs = egress
	mu.PendingRuleIDs = pendingEgress
	mu.OutMetric = metric.Value{
		DeltaPackets: packetsOut,
		DeltaBytes:   bytesOut,
	}
	return &mu
}

var _ = Describe("FlowPolicySets", func() {
	var ca *Aggregator

	egress1Staged := calc.NewRuleID(v3.KindStagedNetworkPolicy, "tier1", "policy1", "namespace1", 0, rules.RuleDirEgress, rules.RuleActionAllow)
	egress2 := calc.NewRuleID(v3.KindNetworkPolicy, "tier2", "policy2", "namespace2", 1, rules.RuleDirEgress, rules.RuleActionAllow)
	egress3 := calc.NewRuleID(v3.KindNetworkPolicy, "tier3", "policy3", "namespace3", 3, rules.RuleDirEgress, rules.RuleActionAllow)
	egress4 := calc.NewRuleID(v3.KindNetworkPolicy, "tier4", "policy4", "namespace4", 1, rules.RuleDirEgress, rules.RuleActionAllow)

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
				Expect(flowlogs[i].FlowEnforcedPolicySet).Should(Equal(expected.EnforcedTraces[i]))
				Expect(flowlogs[i].FlowPendingPolicySet).Should(Equal(expected.PendingTrace))
				Expect(flowlogs[i].FlowProcessReportedStats.PacketsOut).Should(Equal(expected.Packets))
				Expect(flowlogs[i].FlowProcessReportedStats.BytesOut).Should(Equal(expected.Bytes))
			}
		},
		Entry("muWithEndpointMeta, FlowDefault",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 54, 2),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 6, 1),
			},
			FlowDefault,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      21,
				Bytes:        246,
			},
		),
		Entry("muWithEndpointMeta, FlowSourcePort",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 54, 2),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 6, 1),
			},
			FlowSourcePort,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      21,
				Bytes:        246,
			},
		),
		Entry("muWithEndpointMeta, FlowPrefixName",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 54, 2),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 6, 1),
			},
			FlowPrefixName,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      21,
				Bytes:        246,
			},
		),
		Entry("muWithEndpointMeta, FlowNoDestPorts",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 54, 2),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 6, 1),
			},
			FlowNoDestPorts,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      21,
				Bytes:        246,
			},
		),
		Entry("muWithEndpointMeta, FlowDefault",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMetaExpire, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMetaAndDifferentLabels, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMetaExpire, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMetaExpire, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMetaAndDifferentLabels, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMetaAndDifferentLabels, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMetaWithService, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMetaWithService, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithEndpointMetaWithService, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithEndpointMetaAndDifferentLabels, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithEndpointMetaAndDifferentLabels, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
			},
			FlowDefault,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      93,
				Bytes:        980,
			},
		),
		Entry("muWithoutSrcEndpointMeta, FlowDefault",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithoutSrcEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithoutSrcEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithoutSrcEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithoutSrcEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithoutSrcEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithoutSrcEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
			},
			FlowDefault,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      36,
				Bytes:        372,
			},
		),
		Entry("muWithoutDstEndpointMeta, FlowDefault",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithoutDstEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithoutDstEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithoutDstEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithoutDstEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithoutDstEndpointMeta, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithoutDstEndpointMeta, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
			},
			FlowDefault,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      36,
				Bytes:        372,
			},
		),
		Entry("muWithOrigSourceIPs, FlowDefault",
			[]*metric.Update{
				setEgressTraceAndMetrics(muWithOrigSourceIPs, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithOrigSourceIPs, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithOrigSourceIPsExpire, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muWithOrigSourceIPsExpire, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithOrigSourceIPs, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithOrigSourceIPsExpire, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muWithOrigSourceIPsExpire, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muWithOrigSourceIPs, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
			},
			FlowDefault,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      48,
				Bytes:        474,
			},
		),
		Entry("muConn2Rule1Allow, FlowDefault",
			[]*metric.Update{
				setEgressTraceAndMetrics(muConn2Rule1AllowUpdate, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muConn2Rule1AllowUpdate, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muConn2Rule1AllowExpire, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muConn2Rule1AllowExpire, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muConn2Rule1AllowUpdate, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muConn2Rule1AllowExpire, []*calc.RuleID{egress1Staged, egress2, egress3, egress4}, []*calc.RuleID{egress1Staged}, 84, 6),
				setEgressTraceAndMetrics(muConn2Rule1AllowExpire, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
				setEgressTraceAndMetrics(muConn2Rule1AllowExpire, []*calc.RuleID{egress1Staged, egress2, egress4, egress3}, []*calc.RuleID{egress1Staged}, 68, 9),
				setEgressTraceAndMetrics(muConn2Rule1AllowUpdate, []*calc.RuleID{egress1Staged, egress4}, []*calc.RuleID{egress1Staged}, 34, 3),
			},
			FlowDefault,
			TraceAndMetrics{
				Traces: []FlowPolicySet{
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue, "3|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue, "1|tier2|namespace2/policy2|allow|1": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue, "3|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				EnforcedTraces: []FlowPolicySet{
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier3|namespace3/policy3|allow|3": emptyValue, "2|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier4|namespace4/policy4|allow|1": emptyValue},
					{"0|tier2|namespace2/policy2|allow|1": emptyValue, "1|tier4|namespace4/policy4|allow|1": emptyValue, "2|tier3|namespace3/policy3|allow|3": emptyValue},
				},
				PendingTrace: FlowPolicySet{"0|tier1|namespace1/tier1.staged:policy1|allow|0": emptyValue},
				Packets:      48,
				Bytes:        524,
			},
		),
	)
})
