// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	. "github.com/projectcalico/calico/felix/calc"

	"reflect"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"fmt"

	"sort"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/hash"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	ipv4     int = 4
	protocol     = numorstring.ProtocolFromInt(123)
	cidr         = mustParseNet("10.0.0.0/16")
	ports        = []numorstring.Port{numorstring.SinglePort(10)}

	sel1   = "a == 'b'"
	sel1ID = selectorID(sel1)
	sel2   = "b == 'c'"
	sel3   = "has(foo3)"
	sel3ID = selectorID(sel3)
	sel4   = "d in {'a', 'b'}"
	sel4ID = selectorID(sel4)

	combinedSrcSelsOnlySelID = selectorID("(a == 'b') && !(has(foo3))")
	combinedDstSelsOnlySelID = selectorID("(b == 'c') && !(d in {'a', 'b'})")
)

var _ = DescribeTable("RuleScanner rule conversion should generate correct ParsedRule for",
	func(modelRule model.Rule, expectedParsedRule ParsedRule) {
		rs, ur := newHookedRulesScanner()
		profileKey := model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: "prof1"}}

		By("correctly translating InboundRules")
		profileRules := &model.ProfileRules{
			InboundRules:  []model.Rule{modelRule},
			OutboundRules: []model.Rule{},
		}
		rs.OnProfileActive(profileKey, profileRules)
		Expect(ur.activeRules).To(Equal(map[model.Key]*ParsedRules{
			profileKey: {
				InboundRules:  []*ParsedRule{&expectedParsedRule},
				OutboundRules: []*ParsedRule{},
			},
		}))

		By("correctly translating OutboundRules")
		profileRules = &model.ProfileRules{
			InboundRules:  []model.Rule{},
			OutboundRules: []model.Rule{modelRule},
		}
		rs.OnProfileActive(profileKey, profileRules)
		Expect(ur.activeRules).To(Equal(map[model.Key]*ParsedRules{
			profileKey: {
				InboundRules:  []*ParsedRule{},
				OutboundRules: []*ParsedRule{&expectedParsedRule},
			},
		}))

		rs.OnProfileInactive(profileKey)
		Expect(ur.activeRules).To(Equal(map[model.Key]*ParsedRules{}))

		By("correctly translating InboundRules in a policy")
		policyKey := model.PolicyKey{Name: "policy"}
		policy := &model.Policy{
			Namespace:     "namespace",
			InboundRules:  []model.Rule{modelRule},
			OutboundRules: []model.Rule{},
		}
		rs.OnPolicyActive(policyKey, policy)
		Expect(ur.activeRules).To(Equal(map[model.Key]*ParsedRules{
			policyKey: {
				Namespace:     "namespace",
				InboundRules:  []*ParsedRule{&expectedParsedRule},
				OutboundRules: []*ParsedRule{},
			},
		}))
		rs.OnPolicyInactive(policyKey)
		Expect(ur.activeRules).To(Equal(map[model.Key]*ParsedRules{}))
	},
	Entry("Empty rule", model.Rule{}, ParsedRule{}),

	// Basic pass-through fields.
	Entry("action", model.Rule{Action: "deny"}, ParsedRule{Action: "deny"}),
	Entry("IP version", model.Rule{IPVersion: &ipv4}, ParsedRule{IPVersion: &ipv4}),
	Entry("protocol", model.Rule{Protocol: &protocol}, ParsedRule{Protocol: &protocol}),
	Entry("source net", model.Rule{SrcNet: &cidr}, ParsedRule{SrcNets: []*net.IPNet{&cidr}}),
	Entry("dest net", model.Rule{DstNet: &cidr}, ParsedRule{DstNets: []*net.IPNet{&cidr}}),
	Entry("source Ports", model.Rule{SrcPorts: ports}, ParsedRule{SrcPorts: ports}),
	Entry("dest Ports", model.Rule{DstPorts: ports}, ParsedRule{DstPorts: ports}),
	Entry("!protocol", model.Rule{NotProtocol: &protocol}, ParsedRule{NotProtocol: &protocol}),
	Entry("!source net", model.Rule{NotSrcNet: &cidr}, ParsedRule{NotSrcNets: []*net.IPNet{&cidr}}),
	Entry("!dest net", model.Rule{NotDstNet: &cidr}, ParsedRule{NotDstNets: []*net.IPNet{&cidr}}),
	Entry("!source Ports", model.Rule{NotSrcPorts: ports}, ParsedRule{NotSrcPorts: ports}),
	Entry("!dest Ports", model.Rule{NotDstPorts: ports}, ParsedRule{NotDstPorts: ports}),

	Entry("OriginalSrcSelector", model.Rule{OriginalSrcSelector: "has(foo)"}, ParsedRule{OriginalSrcSelector: "has(foo)"}),
	Entry("OriginalSrcNamespaceSelector", model.Rule{OriginalSrcNamespaceSelector: "has(foo)"}, ParsedRule{OriginalSrcNamespaceSelector: "has(foo)"}),
	Entry("OriginalDstSelector", model.Rule{OriginalDstSelector: "has(foo)"}, ParsedRule{OriginalDstSelector: "has(foo)"}),
	Entry("OriginalDstNamespaceSelector", model.Rule{OriginalDstNamespaceSelector: "has(foo)"}, ParsedRule{OriginalDstNamespaceSelector: "has(foo)"}),
	Entry("OriginalNotSrcSelector", model.Rule{OriginalNotSrcSelector: "has(foo)"}, ParsedRule{OriginalNotSrcSelector: "has(foo)"}),
	Entry("OriginalNotDstSelector", model.Rule{OriginalNotDstSelector: "has(foo)"}, ParsedRule{OriginalNotDstSelector: "has(foo)"}),

	Entry("OriginalSrcServiceAccountNames", model.Rule{OriginalSrcServiceAccountNames: []string{"a"}}, ParsedRule{OriginalSrcServiceAccountNames: []string{"a"}}),
	Entry("OriginalDstServiceAccountNames", model.Rule{OriginalDstServiceAccountNames: []string{"a"}}, ParsedRule{OriginalDstServiceAccountNames: []string{"a"}}),
	Entry("OriginalSrcServiceAccountSelector", model.Rule{OriginalSrcServiceAccountSelector: "all()"}, ParsedRule{OriginalSrcServiceAccountSelector: "all()"}),
	Entry("OriginalDstServiceAccountSelector", model.Rule{OriginalDstServiceAccountSelector: "all()"}, ParsedRule{OriginalDstServiceAccountSelector: "all()"}),

	Entry("HTTPMatch", model.Rule{HTTPMatch: &model.HTTPMatch{Methods: []string{"GET", "HEAD"}, Paths: []v3.HTTPPath{
		{Exact: "/foo"},
		{Prefix: "/bar"},
	}}}, ParsedRule{HTTPMatch: &model.HTTPMatch{Methods: []string{"GET", "HEAD"}, Paths: []v3.HTTPPath{
		{Exact: "/foo"},
		{Prefix: "/bar"},
	}}}),

	Entry("Metadata",
		model.Rule{Metadata: &model.RuleMetadata{Annotations: map[string]string{"key": "value"}}},
		ParsedRule{Metadata: &model.RuleMetadata{Annotations: map[string]string{"key": "value"}}}),

	// Services.
	Entry("dest service",
		model.Rule{DstService: "svc", DstServiceNamespace: "default"},
		ParsedRule{
			DstIPPortSetIDs:             []string{"svc:Jhwii46PCMT5NlhWsUqZmv7al8TeHFbNQMhoVg"},
			OriginalDstService:          "svc",
			OriginalDstServiceNamespace: "default",
		}),
	Entry("src service",
		model.Rule{SrcService: "svc", SrcServiceNamespace: "default"},
		ParsedRule{
			SrcIPSetIDs:                 []string{"svcnoport:T03S_6hogdrGKrNFBcbKTFsH_uKwDHEo8JddOg"},
			OriginalSrcService:          "svc",
			OriginalSrcServiceNamespace: "default",
		}),

	// Selectors.
	Entry("source selector", model.Rule{SrcSelector: sel1}, ParsedRule{SrcIPSetIDs: []string{sel1ID}}),
	Entry("dest selector", model.Rule{DstSelector: sel1}, ParsedRule{DstIPSetIDs: []string{sel1ID}}),
	Entry("!source selector", model.Rule{NotSrcSelector: sel1}, ParsedRule{NotSrcIPSetIDs: []string{sel1ID}}),
	Entry("!dest selector", model.Rule{NotDstSelector: sel1}, ParsedRule{NotDstIPSetIDs: []string{sel1ID}}),

	Entry("only negative selectors",
		model.Rule{
			NotSrcSelector: sel3,
			NotDstSelector: sel4,
		},
		ParsedRule{
			// With only negative selectors, we can't combine them.
			NotSrcIPSetIDs: []string{sel3ID},
			NotDstIPSetIDs: []string{sel4ID},
		},
	),
	Entry("positive selectors should be combined with negative ones",
		model.Rule{
			SrcSelector:    sel1,
			DstSelector:    sel2,
			NotSrcSelector: sel3,
			NotDstSelector: sel4,
		},
		ParsedRule{
			// In this case, all the selectors can be squashed down into one that combines
			// them all.
			SrcIPSetIDs: []string{combinedSrcSelsOnlySelID},
			DstIPSetIDs: []string{combinedDstSelsOnlySelID},
		},
	),
)

var _ = Describe("ParsedRule", func() {
	It("should have correct fields relative to model.Rule", func() {
		// We expect all the fields to have the same name, except for
		// the selectors, which differ, and LogPrefix, which
		// is deprecated.
		prType := reflect.TypeOf(ParsedRule{})
		numPRFields := prType.NumField()
		prFields := set.New()

		// Build a set of ParsedRule fields, minus the IPSetIDs variants.
		for i := 0; i < numPRFields; i++ {
			name := prType.Field(i).Name
			if strings.Contains(name, "IPSetIDs") || strings.Contains(name, "IPPortSetIDs") {
				continue
			}
			if name == "OriginalDstService" || name == "OriginalDstServiceNamespace" || name == "OriginalSrcService" || name == "OriginalSrcServiceNamespace" {
				// These don't exist on the model.Rule, as there is no translation done
				// on the Service / ServiceNamespace fields that requires them.
				continue
			}
			prFields.Add(name)
		}

		// Build a set of model.Rule fields, excluding
		// those which aren't copied through to the ParsedRule.
		mrType := reflect.TypeOf(model.Rule{})
		numMRFields := mrType.NumField()
		mrFields := set.New()
		for i := 0; i < numMRFields; i++ {
			name := mrType.Field(i).Name
			if strings.Contains(name, "Tag") ||
				strings.Contains(name, "LogPrefix") ||
				(strings.Contains(name, "Selector") &&
					!strings.Contains(name, "Original") &&
					!strings.Contains(name, "Service")) {
				continue
			}
			if name == "DstService" || name == "DstServiceNamespace" || name == "SrcService" || name == "SrcServiceNamespace" {
				// Service name and namespace are rendered on the ParsedRule
				// as either IPPortIPSetIDs or IPSetIDs.
				continue
			}
			if strings.HasSuffix(name, "Net") {
				// Deprecated XXXNet fields.
				continue
			}
			mrFields.Add(name)
		}

		// Expect the two sets to match (minus the differences from above).
		Expect(prFields.Len()).To(BeNumerically(">", 0))
		Expect(prFields).To(Equal(mrFields))
	})
	It("should have correct fields relative to proto.Rule", func() {
		// We expect all the fields to have the same name, except for
		// ICMP and service account matches, which differ in structure.
		prType := reflect.TypeOf(ParsedRule{})
		numPRFields := prType.NumField()
		prFields := []string{}
		for i := 0; i < numPRFields; i++ {
			name := strings.ToLower(prType.Field(i).Name)
			if strings.Contains(name, "icmptype") ||
				strings.Contains(name, "icmpcode") ||
				strings.Contains(name, "serviceaccount") {
				// expected to differ.
				continue
			}
			if strings.HasSuffix(name, "nets") {
				// The ParsedRule Nets fields map to the proto-rule, repeated Net
				// fields.
				name = name[:len(name)-1]
			}
			prFields = append(prFields, name)
		}
		protoType := reflect.TypeOf(proto.Rule{})
		numMRFields := protoType.NumField()
		protoFields := []string{}
		for i := 0; i < numMRFields; i++ {
			name := strings.ToLower(protoType.Field(i).Name)
			if strings.Contains(name, "icmp") ||
				strings.Contains(name, "serviceaccount") {
				// expected to differ.
				continue
			}
			if strings.Contains(name, "ruleid") {
				// RuleId only in proto rule.
				continue
			}
			protoFields = append(protoFields, name)
		}
		Expect(len(prFields)).To(BeNumerically(">", 0))
		sort.Strings(prFields)
		sort.Strings(protoFields)
		Expect(prFields).To(Equal(protoFields))
	})
})

type scanUpdateRecorder struct {
	activeSelectors set.Set
	activeRules     map[model.Key]*ParsedRules
}

func (ur *scanUpdateRecorder) OnPolicyActive(key model.PolicyKey, rules *ParsedRules) {
	ur.activeRules[key] = rules
}
func (ur *scanUpdateRecorder) OnPolicyInactive(key model.PolicyKey) {
	delete(ur.activeRules, key)
}
func (ur *scanUpdateRecorder) OnProfileActive(key model.ProfileRulesKey, rules *ParsedRules) {
	ur.activeRules[key] = rules
}
func (ur *scanUpdateRecorder) OnProfileInactive(key model.ProfileRulesKey) {
	delete(ur.activeRules, key)
}

func (ur *scanUpdateRecorder) ipSetActive(ipSet *IPSetData) {
	if ipSet.Service != "" {
		// Not a selector-based set.
		return
	}
	ur.activeSelectors.Add(ipSet.Selector.String())
}

func (ur *scanUpdateRecorder) ipSetInactive(ipSet *IPSetData) {
	if ipSet.Service != "" {
		// Not a selector-based set.
		return
	}
	ur.activeSelectors.Discard(ipSet.Selector.String())
}

func newHookedRulesScanner() (*RuleScanner, *scanUpdateRecorder) {
	rs := NewRuleScanner()
	ur := &scanUpdateRecorder{
		activeSelectors: set.New(),
		activeRules:     make(map[model.Key]*ParsedRules),
	}
	rs.RulesUpdateCallbacks = ur
	rs.OnIPSetActive = ur.ipSetActive
	rs.OnIPSetInactive = ur.ipSetInactive
	return rs, ur
}

func ipSetIDForTag(tagID string) string {
	// Tags are now implemented as a has(tagName) selector:
	return hash.MakeUniqueID("s", fmt.Sprintf("has(%s)", tagID))
}
