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

package iptables_test

import (
	. "github.com/projectcalico/felix/go/felix/iptables"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/rules"
)

var _ = Describe("Table with an empty dataplane", func() {
	var dataplane *mockDataplane
	var table *Table
	BeforeEach(func() {
		dataplane = newMockDataplane("filter", map[string][]string{
			"FORWARD": {},
			"INPUT":   {},
			"OUTPUT":  {},
		})
		table = NewTableWithShims(
			"filter",
			4,
			rules.AllHistoricChainNamePrefixes,
			rules.RuleHashPrefix,
			"",
			dataplane.newCmd,
		)
	})

	It("Should defer updates until Apply is called", func() {
		table.SetRuleInsertions("FORWARD", []Rule{
			{Action: DropAction{}},
		})
		table.UpdateChains([]*Chain{
			{Name: "cali-foobar", Rules: []Rule{{Action: AcceptAction{}}}},
		})
		Expect(len(dataplane.Cmds)).To(BeZero())
		table.Apply()
		Expect(len(dataplane.Cmds)).NotTo(BeZero())
	})

	It("Should insert", func() {
		table.SetRuleInsertions("FORWARD", []Rule{
			{Action: DropAction{}},
		})
		table.Apply()
		Expect(dataplane.Chains).To(Equal(map[string][]string{
			"FORWARD": {"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP"},
			"INPUT":   {},
			"OUTPUT":  {},
		}))
	})
})
