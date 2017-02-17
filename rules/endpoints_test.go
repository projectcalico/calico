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
)

var _ = Describe("Endpoints", func() {
	var rrConfigNormal = Config{
		IPIPEnabled:        true,
		IPIPTunnelAddress:  nil,
		IPSetConfigV4:      ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
		IPSetConfigV6:      ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
		IptablesMarkAccept: 0x8,
		IptablesMarkPass:   0x10,
	}

	var renderer RuleRenderer
	BeforeEach(func() {
		renderer = NewRenderer(rrConfigNormal)
	})

	It("should render a minimal workload endpoint", func() {
		Expect(renderer.WorkloadEndpointToIptablesChains("cali1234", true, nil, nil)).To(Equal([]*Chain{
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

	It("should render a disabled workload endpoint", func() {
		Expect(renderer.WorkloadEndpointToIptablesChains("cali1234", false, nil, nil)).To(Equal([]*Chain{
			{
				Name: "cali-tw-cali1234",
				Rules: []Rule{
					{Action: DropAction{},
						Comment: "Endpoint admin disabled"},
				},
			},
			{
				Name: "cali-fw-cali1234",
				Rules: []Rule{
					{Action: DropAction{},
						Comment: "Endpoint admin disabled"},
				},
			},
		}))
	})

	It("should render a fully-loaded workload endpoint", func() {
		Expect(renderer.WorkloadEndpointToIptablesChains(
			"cali1234",
			true,
			[]string{"a", "b"},
			[]string{"prof1", "prof2"},
		)).To(Equal([]*Chain{
			{
				Name: "cali-tw-cali1234",
				Rules: []Rule{
					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of policies",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-pri-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-pri-prof2"}},
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

					{Comment: "Start of policies",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-pro-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-pro-prof2"}},
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
		Expect(renderer.HostEndpointToFilterChains("eth0", []string{"a", "b"}, []string{"prof1", "prof2"})).To(Equal([]*Chain{
			{
				Name: "cali-th-eth0",
				Rules: []Rule{
					// Host endpoints get extra failsafe rules.
					{Action: JumpAction{Target: "cali-failsafe-out"}},

					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of policies",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-pro-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-pro-prof2"}},
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

					{Comment: "Start of policies",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-a"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-b"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if policy accepted"},
					{Match: Match().MarkClear(0x10),
						Action:  DropAction{},
						Comment: "Drop if no policies passed packet"},

					{Action: JumpAction{Target: "cali-pri-prof1"}},
					{Match: Match().MarkSet(0x8),
						Action:  ReturnAction{},
						Comment: "Return if profile accepted"},
					{Action: JumpAction{Target: "cali-pri-prof2"}},
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
		Expect(renderer.HostEndpointToRawChains("eth0", []string{"c"})).To(Equal([]*Chain{
			{
				Name: "cali-th-eth0",
				Rules: []Rule{
					// Host endpoints get extra failsafe rules.
					{Action: JumpAction{Target: "cali-failsafe-out"}},

					{Action: ClearMarkAction{Mark: 0x8}},

					{Comment: "Start of policies",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-po-c"}},
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

					{Comment: "Start of policies",
						Action: ClearMarkAction{Mark: 0x10}},
					{Match: Match().MarkClear(0x10),
						Action: JumpAction{Target: "cali-pi-c"}},
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
