// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package rules_test

import (
	. "github.com/projectcalico/felix/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/ipsets"
	. "github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
)

var _ = Describe("Endpoints", func() {
	var rrConfigNormal = Config{
		IPIPEnabled:          true,
		IPIPTunnelAddress:    nil,
		IPSetConfigV4:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
		IPSetConfigV6:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
		IptablesMarkAccept:   0x8,
		IptablesMarkNextTier: 0x10,
	}

	var renderer RuleRenderer
	BeforeEach(func() {
		renderer = NewRenderer(rrConfigNormal)
	})

	It("should render a minimal workload endpoint", func() {
		var minimalEndpoint = proto.WorkloadEndpoint{
			Name: "cali1234",
		}
		Expect(renderer.WorkloadEndpointToIptablesChains(nil, &minimalEndpoint)).To(Equal([]*Chain{
			{
				Name: "cali-tw-cali1234",
				Rules: []Rule{
					{Action: ClearMarkAction{Mark: 0x8}},
					{Action: DropAction{},
						Comment: "Drop if no profiles matched"},
				},
			},
			{
				Name: "cali-fw-cali1234",
				Rules: []Rule{
					{Action: ClearMarkAction{Mark: 0x8}},
					{Action: DropAction{},
						Comment: "Drop if no profiles matched"},
				},
			},
		}))
	})

	It("should render a fully-loaded workload endpoint", func() {
		var endpoint = proto.WorkloadEndpoint{
			Name: "cali1234",
			Tiers: []*proto.TierInfo{
				{Name: "tier1", Policies: []string{"a", "b"}},
				{Name: "tier2", Policies: []string{"c", "d"}},
			},
			ProfileIds: []string{"prof1", "prof2"},
		}
		Expect(renderer.WorkloadEndpointToIptablesChains(nil, &endpoint)).To(Equal([]*Chain{
			{
				Name: "cali-tw-cali1234",
				Rules: []Rule{
					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of tier tier1",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-tier1/a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-tier1/b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Comment: "Start of tier tier2",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-tier2/c"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-tier2/d"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-pi-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-pi-prof2"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},

					{Action: DropAction{},
						Comment: "Drop if no profiles matched"},
				},
			},
			{
				Name: "cali-fw-cali1234",
				Rules: []Rule{
					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of tier tier1",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-tier1/a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-tier1/b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Comment: "Start of tier tier2",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-tier2/c"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-tier2/d"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-po-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-po-prof2"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},

					{Action: DropAction{},
						Comment: "Drop if no profiles matched"},
				},
			},
		}))
	})

	It("should render a host endpoint", func() {
		var endpoint = proto.HostEndpoint{
			Name: "cali1234",
			Tiers: []*proto.TierInfo{
				{Name: "tier1", Policies: []string{"a", "b"}},
			},
			// Untracked policy should be ignored for filter table.
			UntrackedTiers: []*proto.TierInfo{
				{Name: "tier2", Policies: []string{"c"}},
			},
			ProfileIds: []string{"prof1", "prof2"},
		}
		Expect(renderer.HostEndpointToFilterChains("eth0", &endpoint)).To(Equal([]*Chain{
			{
				Name: "cali-th-eth0",
				Rules: []Rule{
					// Host endpoints get extra failsafe rules.
					{Action: JumpAction{Target: "cali-failsafe-out"}},

					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of tier tier1",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-tier1/a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-tier1/b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-po-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-po-prof2"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},

					{Action: DropAction{},
						Comment: "Drop if no profiles matched"},
				},
			},
			{
				Name: "cali-fh-eth0",
				Rules: []Rule{
					// Host endpoints get extra failsafe rules.
					{Action: JumpAction{Target: "cali-failsafe-in"}},

					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of tier tier1",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-tier1/a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-tier1/b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-pi-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-pi-prof2"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},

					{Action: DropAction{},
						Comment: "Drop if no profiles matched"},
				},
			},
		}))
	})

	It("should render host endpoint raw chains with untracked policies", func() {
		var endpoint = proto.HostEndpoint{
			Name: "cali1234",
			// Normal policy should be ignored in raw table.
			Tiers: []*proto.TierInfo{
				{Name: "tier1", Policies: []string{"a", "b"}},
			},
			UntrackedTiers: []*proto.TierInfo{
				{Name: "tier2", Policies: []string{"c"}},
			},
			ProfileIds: []string{"prof1", "prof2"},
		}
		Expect(renderer.HostEndpointToRawChains("eth0", &endpoint)).To(Equal([]*Chain{
			{
				Name: "cali-th-eth0",
				Rules: []Rule{
					// Host endpoints get extra failsafe rules.
					{Action: JumpAction{Target: "cali-failsafe-out"}},

					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of tier tier2",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-tier2/c"}},
					// Extra NOTRACK action before returning in raw table.
					{Match: Match().MarkSet(0x8),
						Action: NoTrackAction{}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},

					// No drop actions or profiles in raw table.
				},
			},
			{
				Name: "cali-fh-eth0",
				Rules: []Rule{
					// Host endpoints get extra failsafe rules.
					{Action: JumpAction{Target: "cali-failsafe-in"}},

					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of tier tier2",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-tier2/c"}},
					// Extra NOTRACK action before returning in raw table.
					{Match: Match().MarkSet(0x8),
						Action: NoTrackAction{}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},

					// No drop actions or profiles in raw table.
				},
			},
		}))
	})
})
