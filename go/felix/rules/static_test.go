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
	. "github.com/projectcalico/felix/go/felix/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/felix/go/felix/iptables"
)

var _ = Describe("Static", func() {
	var rr RuleRenderer
	var config Config
	BeforeEach(func() {
		config = Config{
			WorkloadIfacePrefixes: []string{"cali"},
		}
	})
	JustBeforeEach(func() {
		rr = NewRenderer(config)
	})

	Describe("with default config", func() {
		It("should render the forward chain correctly", func() {
			Expect(rr.StaticFilterForwardChains()).To(Equal([]*Chain{{
				Name: "cali-FORWARD",
				Rules: []Rule{
					// conntrack rules.
					{Match: Match().ConntrackState("INVALID"),
						Action: DropAction{}},
					{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: AcceptAction{}},

					// Per-prefix workload jump rules.
					{Match: Match().InInterface("cali+"),
						Action: JumpAction{Target: ChainFromWorkloadDispatch}},
					{Match: Match().OutInterface("cali+"),
						Action: JumpAction{Target: ChainToWorkloadDispatch}},

					// Accept if workload policy matched.
					{Match: Match().InInterface("cali+"),
						Action: AcceptAction{}},
					{Match: Match().OutInterface("cali+"),
						Action: AcceptAction{}},

					// Non-workload through-traffic, pass to host endpoint chains.
					{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
					{Action: JumpAction{Target: ChainDispatchToHostEndpoint}},
				},
			}}))
		})
	})

	Describe("with drop override and multiple prefixes", func() {
		BeforeEach(func() {
			config = Config{
				WorkloadIfacePrefixes: []string{"cali", "tap"},
				ActionOnDrop:          "ACCEPT",
			}
		})

		It("should render the forward chain honouring muliple prefixes and action", func() {
			Expect(rr.StaticFilterForwardChains()).To(Equal([]*Chain{{
				Name: "cali-FORWARD",
				Rules: []Rule{
					// conntrack rules.
					{Match: Match().ConntrackState("INVALID"),
						Action: AcceptAction{}},
					{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: AcceptAction{}},

					// Per-prefix workload jump rules.
					{Match: Match().InInterface("cali+"),
						Action: JumpAction{Target: ChainFromWorkloadDispatch}},
					{Match: Match().OutInterface("cali+"),
						Action: JumpAction{Target: ChainToWorkloadDispatch}},
					{Match: Match().InInterface("tap+"),
						Action: JumpAction{Target: ChainFromWorkloadDispatch}},
					{Match: Match().OutInterface("tap+"),
						Action: JumpAction{Target: ChainToWorkloadDispatch}},

					// Accept if workload policy matched.
					{Match: Match().InInterface("cali+"),
						Action: AcceptAction{}},
					{Match: Match().OutInterface("cali+"),
						Action: AcceptAction{}},
					{Match: Match().InInterface("tap+"),
						Action: AcceptAction{}},
					{Match: Match().OutInterface("tap+"),
						Action: AcceptAction{}},

					// Non-workload through-traffic, pass to host endpoint chains.
					{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
					{Action: JumpAction{Target: ChainDispatchToHostEndpoint}},
				},
			}}))
		})
	})
})
