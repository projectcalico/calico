// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package collector_test

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
)

var (
	allowIngressRid0 = &calc.RuleID{
		Action:   rules.RuleActionAllow,
		Index:    1,
		IndexStr: "1",
		PolicyID: calc.PolicyID{
			Name: "P1",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T1",
		Direction: rules.RuleDirIngress,
	}
	denyIngressRid0 = &calc.RuleID{
		Action:   rules.RuleActionDeny,
		Index:    2,
		IndexStr: "2",
		PolicyID: calc.PolicyID{
			Name: "P2",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T2",
		Direction: rules.RuleDirIngress,
	}
	allowIngressRid1 = &calc.RuleID{
		Action:   rules.RuleActionAllow,
		Index:    1,
		IndexStr: "1",
		PolicyID: calc.PolicyID{
			Name: "P1",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T3",
		Direction: rules.RuleDirIngress,
	}
	denyIngressRid1 = &calc.RuleID{
		Action:   rules.RuleActionDeny,
		Index:    2,
		IndexStr: "2",
		PolicyID: calc.PolicyID{
			Name: "P2",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T4",
		Direction: rules.RuleDirIngress,
	}
	allowIngressRid2 = &calc.RuleID{
		Action:   rules.RuleActionAllow,
		Index:    1,
		IndexStr: "1",
		PolicyID: calc.PolicyID{
			Name: "P2",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T5",
		Direction: rules.RuleDirIngress,
	}
	nextTierIngressRid0 = &calc.RuleID{
		Action:   rules.RuleActionPass,
		Index:    3,
		IndexStr: "3",
		PolicyID: calc.PolicyID{
			Name: "P1",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T6",
		Direction: rules.RuleDirIngress,
	}
	nextTierIngressRid1 = &calc.RuleID{
		Action:   rules.RuleActionPass,
		Index:    4,
		IndexStr: "4",
		PolicyID: calc.PolicyID{
			Name: "P2",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T7",
		Direction: rules.RuleDirIngress,
	}
	allowIngressRid11 = &calc.RuleID{
		Action:   rules.RuleActionAllow,
		Index:    1,
		IndexStr: "1",
		PolicyID: calc.PolicyID{
			Name: "P1",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T8",
		Direction: rules.RuleDirIngress,
	}
	denyIngressRid21 = &calc.RuleID{
		Action:   rules.RuleActionDeny,
		Index:    1,
		IndexStr: "1",
		PolicyID: calc.PolicyID{
			Name: "P1",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T9",
		Direction: rules.RuleDirIngress,
	}

	nextTierEgressRid0 = &calc.RuleID{
		Action:   rules.RuleActionPass,
		Index:    2,
		IndexStr: "2",
		PolicyID: calc.PolicyID{
			Name: "P4",
		},
		Tier:      "T10",
		Direction: rules.RuleDirEgress,
	}
	allowEgressRid2 = &calc.RuleID{
		Action:   rules.RuleActionAllow,
		Index:    3,
		IndexStr: "3",
		PolicyID: calc.PolicyID{
			Name: "P3",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Tier:      "T11",
		Direction: rules.RuleDirEgress,
	}
)

var _ = Describe("Tuple", func() {
	var t *tuple.Tuple
	Describe("Parse Ipv4 Tuple", func() {
		BeforeEach(func() {
			var src, dst [16]byte
			copy(src[:], net.ParseIP("127.0.0.1").To16())
			copy(dst[:], net.ParseIP("127.1.1.1").To16())
			t = tuple.New(src, dst, 6, 12345, 80)
		})
		It("should parse correctly", func() {
			Expect(t.SourceNet().String()).To(Equal("127.0.0.1"))
			Expect(t.DestNet().String()).To(Equal("127.1.1.1"))
		})
	})
})

var _ = Describe("Rule Trace", func() {
	var data *collector.Data
	var t *tuple.Tuple

	BeforeEach(func() {
		var src, dst [16]byte
		copy(src[:], net.ParseIP("127.0.0.1").To16())
		copy(dst[:], net.ParseIP("127.1.1.1").To16())
		t = tuple.New(src, dst, 6, 12345, 80)
		data = collector.NewData(*t, nil, nil)
	})

	Describe("Data with no ingress or egress rule trace ", func() {
		It("should have length equal to init len", func() {
			Expect(data.IngressRuleTrace.Len()).To(Equal(collector.RuleTraceInitLen))
			Expect(data.EgressRuleTrace.Len()).To(Equal(collector.RuleTraceInitLen))
		})
		It("should be dirty", func() {
			Expect(data.IsDirty()).To(Equal(true))
		})
	})

	Describe("Adding a RuleID to the Ingress Rule Trace", func() {
		BeforeEach(func() {
			rm := data.AddRuleID(allowIngressRid0, 0, 0, 0)
			Expect(rm).To(Equal(collector.RuleMatchSet))
		})
		It("should have path length equal to 1", func() {
			Expect(data.IngressRuleTrace.Path()).To(HaveLen(1))
		})
		It("should have action set to allow", func() {
			Expect(data.IngressAction()).To(Equal(rules.RuleActionAllow))
		})
		It("should be dirty", func() {
			Expect(data.IsDirty()).To(BeTrue())
		})
		It("should return a conflict for same rule Index but different values", func() {
			Expect(data.AddRuleID(denyIngressRid1, 0, 0, 0)).To(Equal(collector.RuleMatchIsDifferent))
		})
	})

	Describe("RuleTrace conflicts (ingress)", func() {
		BeforeEach(func() {
			rm := data.AddRuleID(allowIngressRid0, 0, 0, 0)
			Expect(rm).To(Equal(collector.RuleMatchSet))
		})
		Context("Adding a rule tracepoint that conflicts", func() {
			var dirtyFlag bool
			BeforeEach(func() {
				dirtyFlag = data.IsDirty()
				rm := data.AddRuleID(denyIngressRid0, 0, 0, 0)
				Expect(rm).To(Equal(collector.RuleMatchIsDifferent))
			})
			It("should have path length unchanged and equal to 1", func() {
				Expect(data.IngressRuleTrace.Path()).To(HaveLen(1))
			})
			It("should have action unchanged and set to allow", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionAllow))
			})
			Specify("dirty flag should be unchanged", func() {
				Expect(data.IsDirty()).To(Equal(dirtyFlag))
			})
		})
		Context("Replacing a rule tracepoint that was conflicting", func() {
			BeforeEach(func() {
				data.ReplaceRuleID(denyIngressRid0, 0, 0, 0)
			})
			It("should have path length unchanged and equal to 1", func() {
				Expect(data.IngressRuleTrace.Path()).To(HaveLen(1))
			})
			It("should have action set to deny", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionDeny))
			})
			It("should be dirty", func() {
				Expect(data.IsDirty()).To(Equal(true))
			})
		})
	})
	Describe("RuleTraces with next Tier", func() {
		BeforeEach(func() {
			rm := data.AddRuleID(nextTierIngressRid0, 0, 0, 0)
			Expect(rm).To(Equal(collector.RuleMatchSet))
		})
		Context("Adding a rule tracepoint with action", func() {
			BeforeEach(func() {
				rm := data.AddRuleID(allowIngressRid1, 1, 0, 0)
				Expect(rm).To(Equal(collector.RuleMatchSet))
			})
			It("should have path length 2", func() {
				Expect(data.IngressRuleTrace.Path()).To(HaveLen(2))
			})
			It("should have length unchanged and equal to initial length", func() {
				Expect(data.IngressRuleTrace.Len()).To(Equal(collector.RuleTraceInitLen))
			})
			It("should have action set to allow", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionAllow))
			})
		})
		Context("Adding a rule tracepoint with action and Index past initial length", func() {
			BeforeEach(func() {
				rm := data.AddRuleID(allowIngressRid11, 11, 0, 0)
				Expect(rm).To(Equal(collector.RuleMatchSet))
			})
			It("should have path length 2 (since path is contracted)", func() {
				Expect(data.IngressRuleTrace.Path()).To(HaveLen(2))
			})
			It("should have length twice of initial length", func() {
				Expect(data.IngressRuleTrace.Len()).To(Equal(collector.RuleTraceInitLen * 2))
			})
			It("should have action set to allow", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionAllow))
			})
		})
		Context("Adding a rule tracepoint with action and Index past double the initial length", func() {
			BeforeEach(func() {
				rm := data.AddRuleID(denyIngressRid21, 21, 0, 0)
				Expect(rm).To(Equal(collector.RuleMatchSet))
			})
			It("should have path length 22", func() {
				Expect(data.IngressRuleTrace.Path()).To(HaveLen(2))
			})
			It("should have length thrice of initial length", func() {
				Expect(data.IngressRuleTrace.Len()).To(Equal(collector.RuleTraceInitLen * 3))
			})
			It("should have action set to deny", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionDeny))
			})
		})
		Context("Adding a rule tracepoint that conflicts", func() {
			BeforeEach(func() {
				rm := data.AddRuleID(allowIngressRid0, 0, 0, 0)
				Expect(rm).To(Equal(collector.RuleMatchIsDifferent))
			})
			It("should return a nil path", func() {
				Expect(data.IngressRuleTrace.Path()).To(BeNil())
			})
			It("should have not have action set", func() {
				Expect(data.IngressAction()).NotTo(Equal(rules.RuleActionAllow))
				Expect(data.IngressAction()).NotTo(Equal(rules.RuleActionDeny))
			})
		})
		Context("Replacing a rule tracepoint that was conflicting", func() {
			BeforeEach(func() {
				data.ReplaceRuleID(allowIngressRid0, 0, 0, 0)
			})
			It("should have path length unchanged and equal to 1", func() {
				Expect(len(data.IngressRuleTrace.Path())).To(Equal(1))
			})
			It("should have action set to allow", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionAllow))
			})
		})
	})
	Describe("RuleTraces with multiple tiers", func() {
		BeforeEach(func() {
			// Ingress
			rc := data.AddRuleID(nextTierIngressRid0, 0, 0, 0)
			Expect(rc).To(Equal(collector.RuleMatchSet))
			rc = data.AddRuleID(nextTierIngressRid1, 1, 0, 0)
			Expect(rc).To(Equal(collector.RuleMatchSet))
			rc = data.AddRuleID(allowIngressRid2, 2, 0, 0)
			Expect(rc).To(Equal(collector.RuleMatchSet))
			// Egress
			rc = data.AddRuleID(nextTierEgressRid0, 0, 0, 0)
			Expect(rc).To(Equal(collector.RuleMatchSet))
			rc = data.AddRuleID(allowEgressRid2, 2, 0, 0)
			Expect(rc).To(Equal(collector.RuleMatchSet))
			rc = data.AddRuleID(allowEgressRid2, 2, 0, 0)
			Expect(rc).To(Equal(collector.RuleMatchUnchanged))
		})
		It("should have ingress path length equal to 3", func() {
			Expect(data.IngressRuleTrace.Path()).To(HaveLen(3))
		})
		It("should have egress path length equal to 2 (path is contracted)", func() {
			Expect(data.EgressRuleTrace.Path()).To(HaveLen(2))
		})
		It("should have have ingress action set to allow", func() {
			Expect(data.IngressAction()).To(Equal(rules.RuleActionAllow))
		})
		It("should have have egress action set to allow", func() {
			Expect(data.EgressAction()).To(Equal(rules.RuleActionAllow))
		})
		Context("Adding an ingress rule tracepoint that conflicts", func() {
			BeforeEach(func() {
				rm := data.AddRuleID(denyIngressRid1, 1, 0, 0)
				Expect(rm).To(Equal(collector.RuleMatchIsDifferent))
			})
			It("should have path length unchanged and equal to 3", func() {
				Expect(len(data.IngressRuleTrace.Path())).To(Equal(3))
			})
			It("should have have action set to allow", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionAllow))
			})
		})
		Context("Replacing an ingress rule tracepoint that was conflicting", func() {
			BeforeEach(func() {
				data.ReplaceRuleID(denyIngressRid1, 1, 0, 0)
			})
			It("should have path length unchanged and equal to 2", func() {
				Expect(len(data.IngressRuleTrace.Path())).To(Equal(2))
			})
			It("should have action set to allow", func() {
				Expect(data.IngressAction()).To(Equal(rules.RuleActionDeny))
			})
		})
	})
})
