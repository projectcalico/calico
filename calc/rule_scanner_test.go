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

	"reflect"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"fmt"

	"sort"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/hash"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/set"
)

var (
	ipv4     int = 4
	protocol     = numorstring.ProtocolFromInt(123)
	cidr         = mustParseNet("10.0.0.0/16")
	ports        = []numorstring.Port{numorstring.SinglePort(10)}

	tag1   = "tag1"
	tag1ID = ipSetIDForTag(tag1)
	tag2   = "tag2"
	tag3   = "tag3"
	tag3ID = ipSetIDForTag(tag3)
	tag4   = "tag4"
	tag4ID = ipSetIDForTag(tag4)

	sel1   = "a == 'b'"
	sel1ID = selectorID(sel1)
	sel2   = "b == 'c'"
	sel3   = "has(foo3)"
	sel3ID = selectorID(sel3)
	sel4   = "d in {'a', 'b'}"
	sel4ID = selectorID(sel4)

	combinedSrcSelID         = selectorID("(((a == 'b') && has(tag1)) && !(has(foo3))) && !(has(tag3))")
	combinedDstSelID         = selectorID("(((b == 'c') && has(tag2)) && !(d in {'a', 'b'})) && !(has(tag4))")
	combinedSrcTagsOnlySelID = selectorID("(has(tag1)) && !(has(tag3))")
	combinedDstTagsOnlySelID = selectorID("(has(tag2)) && !(has(tag4))")
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

	// Tags/Selectors.
	Entry("source tag", model.Rule{SrcTag: "tag1"}, ParsedRule{SrcIPSetIDs: []string{tag1ID}}),
	Entry("dest tag", model.Rule{DstTag: "tag1"}, ParsedRule{DstIPSetIDs: []string{tag1ID}}),
	Entry("source selector", model.Rule{SrcSelector: sel1}, ParsedRule{SrcIPSetIDs: []string{sel1ID}}),
	Entry("dest selector", model.Rule{DstSelector: sel1}, ParsedRule{DstIPSetIDs: []string{sel1ID}}),
	Entry("!source tag", model.Rule{NotSrcTag: "tag1"}, ParsedRule{NotSrcIPSetIDs: []string{tag1ID}}),
	Entry("!dest tag", model.Rule{NotDstTag: "tag1"}, ParsedRule{NotDstIPSetIDs: []string{tag1ID}}),
	Entry("!source selector", model.Rule{NotSrcSelector: sel1}, ParsedRule{NotSrcIPSetIDs: []string{sel1ID}}),
	Entry("!dest selector", model.Rule{NotDstSelector: sel1}, ParsedRule{NotDstIPSetIDs: []string{sel1ID}}),

	Entry("fully-loaded tags/selectors should be combined",
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
			// In this case, all the selectors and tags can be squashed down into one that combines
			// them all.
			SrcIPSetIDs: []string{combinedSrcSelID},
			DstIPSetIDs: []string{combinedDstSelID},
		},
	),
	Entry("only negative tags/selectors",
		model.Rule{
			NotSrcTag:      tag3,
			NotDstTag:      tag4,
			NotSrcSelector: sel3,
			NotDstSelector: sel4,
		},
		ParsedRule{
			// With only negative tags/selectors, we can't combine them.
			NotSrcIPSetIDs: []string{sel3ID, tag3ID},
			NotDstIPSetIDs: []string{sel4ID, tag4ID},
		},
	),
	Entry("only negative tags",
		model.Rule{
			NotSrcTag: tag3,
			NotDstTag: tag4,
		},
		ParsedRule{
			// With only negative tags/selectors, we can't combine them.
			NotSrcIPSetIDs: []string{tag3ID},
			NotDstIPSetIDs: []string{tag4ID},
		},
	),
	Entry("only negative selectors",
		model.Rule{
			NotSrcSelector: sel3,
			NotDstSelector: sel4,
		},
		ParsedRule{
			// With only negative tags/selectors, we can't combine them.
			NotSrcIPSetIDs: []string{sel3ID},
			NotDstIPSetIDs: []string{sel4ID},
		},
	),
	Entry("positive tags should be combined with negative ones",
		model.Rule{
			SrcTag:    tag1,
			DstTag:    tag2,
			NotSrcTag: tag3,
			NotDstTag: tag4,
		},
		ParsedRule{
			// In this case, all the selectors and tags can be squashed down into one that combines
			// them all.
			SrcIPSetIDs: []string{combinedSrcTagsOnlySelID},
			DstIPSetIDs: []string{combinedDstTagsOnlySelID},
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
			// In this case, all the selectors and tags can be squashed down into one that combines
			// them all.
			SrcIPSetIDs: []string{combinedSrcSelsOnlySelID},
			DstIPSetIDs: []string{combinedDstSelsOnlySelID},
		},
	),
)

var _ = Describe("ParsedRule", func() {
	It("should have correct fields relative to model.Rule", func() {
		// We expect all the fields to have the same name, except for
		// the selectors and tags, which differ, and LogPrefix, which
		// is deprecated.
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
				strings.Index(name, "LogPrefix") >= 0 ||
				strings.Index(name, "Selector") >= 0 {
				continue
			}
			if strings.HasSuffix(name, "Net") {
				// Deprecated XXXNet fields.
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
		prFields := []string{}
		for i := 0; i < numPRFields; i++ {
			name := strings.ToLower(prType.Field(i).Name)
			if strings.Index(name, "icmptype") >= 0 ||
				strings.Index(name, "icmpcode") >= 0 {
				// ICMP fields expected to differ.
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
			if strings.Contains(name, "icmp") {
				// ICMP fields expected to differ.
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
	ur.activeSelectors.Add(ipSet.Selector.String())
}

func (ur *scanUpdateRecorder) ipSetInactive(ipSet *IPSetData) {
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
