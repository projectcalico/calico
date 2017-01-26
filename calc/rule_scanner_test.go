// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	. "github.com/projectcalico/felix/calc"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/selector"
	"reflect"
	"strings"
)

var (
	ipv4     int = 4
	protocol     = numorstring.ProtocolFromInt(123)
	cidr         = mustParseNet("10.0.0.0/16")
	ports        = []numorstring.Port{numorstring.SinglePort(10)}

	tag1   = "tag1"
	tag1ID = TagIPSetID(tag1)
	tag2   = "tag2"
	tag2ID = TagIPSetID(tag2)
	tag3   = "tag3"
	tag3ID = TagIPSetID(tag3)
	tag4   = "tag4"
	tag4ID = TagIPSetID(tag4)

	sel1   = "a == 'b'"
	sel1ID = selectorId(sel1)
	sel2   = "b == 'c'"
	sel2ID = selectorId(sel2)
	sel3   = "has(foo3)"
	sel3ID = selectorId(sel3)
	sel4   = "d in {'a', 'b'}"
	sel4ID = selectorId(sel4)
)

var _ = DescribeTable("RuleScanner rule conversion should generate correct ParsedRule for",
	func(modelRule model.Rule, expectedParsedRule ParsedRule) {
		rs, ur := newHookedRulesScanner()
		profileKey := model.ProfileRulesKey{model.ProfileKey{Name: "prof1"}}

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
	},
	Entry("Empty rule", model.Rule{}, ParsedRule{}),

	// Basic pass-through fields.
	Entry("action", model.Rule{Action: "deny"}, ParsedRule{Action: "deny"}),
	Entry("IP version", model.Rule{IPVersion: &ipv4}, ParsedRule{IPVersion: &ipv4}),
	Entry("protocol", model.Rule{Protocol: &protocol}, ParsedRule{Protocol: &protocol}),
	Entry("source net", model.Rule{SrcNet: &cidr}, ParsedRule{SrcNet: &cidr}),
	Entry("dest net", model.Rule{DstNet: &cidr}, ParsedRule{DstNet: &cidr}),
	Entry("source Ports", model.Rule{SrcPorts: ports}, ParsedRule{SrcPorts: ports}),
	Entry("dest Ports", model.Rule{DstPorts: ports}, ParsedRule{DstPorts: ports}),
	Entry("log prefix", model.Rule{LogPrefix: "foo"}, ParsedRule{LogPrefix: "foo"}),
	Entry("!protocol", model.Rule{NotProtocol: &protocol}, ParsedRule{NotProtocol: &protocol}),
	Entry("!source net", model.Rule{NotSrcNet: &cidr}, ParsedRule{NotSrcNet: &cidr}),
	Entry("!dest net", model.Rule{NotDstNet: &cidr}, ParsedRule{NotDstNet: &cidr}),
	Entry("!source Ports", model.Rule{NotSrcPorts: ports}, ParsedRule{NotSrcPorts: ports}),
	Entry("!dest Ports", model.Rule{NotDstPorts: ports}, ParsedRule{NotDstPorts: ports}),

	// Tags/Selectors.
	Entry("source tag", model.Rule{SrcTag: "tag1"}, ParsedRule{SrcIPSetIDs: []string{tag1ID}}),
	Entry("dest tag", model.Rule{DstTag: "tag1"}, ParsedRule{DstIPSetIDs: []string{tag1ID}}),
	Entry("source selector", model.Rule{SrcSelector: sel1}, ParsedRule{SrcIPSetIDs: []string{sel1ID}}),
	Entry("dest selector", model.Rule{DstSelector: sel1}, ParsedRule{DstIPSetIDs: []string{sel1ID}}),
	Entry("!source tag", model.Rule{NotSrcTag: "tag1"}, ParsedRule{NotSrcIPSetIDs: []string{tag1ID}}),
	Entry("!dest tag", model.Rule{NotDstTag: "tag1"}, ParsedRule{NotDstIPSetIDs: []string{tag1ID}}),
	Entry("!source selector", model.Rule{NotSrcSelector: sel1}, ParsedRule{NotSrcIPSetIDs: []string{sel1ID}}),
	Entry("!dest selector", model.Rule{NotDstSelector: sel1}, ParsedRule{NotDstIPSetIDs: []string{sel1ID}}),

	Entry("multiple tags/selectors",
		model.Rule{
			SrcTag:         tag1,
			DstTag:         tag2,
			SrcSelector:    sel1,
			DstSelector:    sel2,
			NotSrcTag:      tag3,
			NotDstTag:      tag4,
			NotSrcSelector: sel3,
			NotDstSelector: sel4,
		},
		ParsedRule{
			SrcIPSetIDs:    []string{tag1ID, sel1ID},
			DstIPSetIDs:    []string{tag2ID, sel2ID},
			NotSrcIPSetIDs: []string{tag3ID, sel3ID},
			NotDstIPSetIDs: []string{tag4ID, sel4ID},
		},
	),
)

var _ = Describe("ParsedRule", func() {
	It("should have correct fields relative to model.Rule", func() {
		// We expect all the fields to have the same name, except for
		// the selectors and tags, which differ.
		prType := reflect.TypeOf(ParsedRule{})
		numPRFields := prType.NumField()
		prFields := set.New()
		for i := 0; i < numPRFields; i++ {
			name := prType.Field(i).Name
			if strings.Index(name, "IPSetIDs") >= 0 {
				continue
			}
			prFields.Add(name)
		}
		mrType := reflect.TypeOf(model.Rule{})
		numMRFields := mrType.NumField()
		mrFields := set.New()
		for i := 0; i < numMRFields; i++ {
			name := mrType.Field(i).Name
			if strings.Index(name, "Tag") >= 0 ||
				strings.Index(name, "Selector") >= 0 {
				continue
			}
			mrFields.Add(name)
		}
		Expect(prFields.Len()).To(BeNumerically(">", 0))
		Expect(prFields).To(Equal(mrFields))
	})
	It("should have correct fields relative to proto.Rule", func() {
		// We expect all the fields to have the same name, except for
		// ICMP, which differ in structure.
		prType := reflect.TypeOf(ParsedRule{})
		numPRFields := prType.NumField()
		prFields := set.New()
		for i := 0; i < numPRFields; i++ {
			name := strings.ToLower(prType.Field(i).Name)
			if strings.Index(name, "icmptype") >= 0 ||
				strings.Index(name, "icmpcode") >= 0 {
				// ICMP fields expected to differ.
				continue
			}
			prFields.Add(name)
		}
		protoType := reflect.TypeOf(proto.Rule{})
		numMRFields := protoType.NumField()
		protoFields := set.New()
		for i := 0; i < numMRFields; i++ {
			name := strings.ToLower(protoType.Field(i).Name)
			if strings.Contains(name, "icmp") {
				// ICMP fields expected to differ.
				continue
			}
			if strings.Contains(name, "ruleid") {
				// RuleId only in proto rule.
				continue
			}
			protoFields.Add(name)
		}
		Expect(prFields.Len()).To(BeNumerically(">", 0))
		Expect(prFields).To(Equal(protoFields))
	})
})

type scanUpdateRecorder struct {
	activeSelectors set.Set
	activeTags      set.Set
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

func (ur *scanUpdateRecorder) tagActive(tag string) {
	ur.activeTags.Add(tag)
}

func (ur *scanUpdateRecorder) tagInactive(tag string) {
	ur.activeTags.Discard(tag)
}

func (ur *scanUpdateRecorder) selectorActive(sel selector.Selector) {
	ur.activeSelectors.Add(sel.String())
}

func (ur *scanUpdateRecorder) selectorInactive(sel selector.Selector) {
	ur.activeSelectors.Discard(sel.String())
}

func newHookedRulesScanner() (*RuleScanner, *scanUpdateRecorder) {
	rs := NewRuleScanner()
	ur := &scanUpdateRecorder{
		activeSelectors: set.New(),
		activeTags:      set.New(),
		activeRules:     make(map[model.Key]*ParsedRules),
	}
	rs.RulesUpdateCallbacks = ur
	rs.OnTagActive = ur.tagActive
	rs.OnTagInactive = ur.tagInactive
	rs.OnSelectorActive = ur.selectorActive
	rs.OnSelectorInactive = ur.selectorInactive
	return rs, ur
}
