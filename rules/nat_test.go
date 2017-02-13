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

var _ = Describe("NAT", func() {
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

	It("should render rules when active", func() {
		Expect(renderer.NATOutgoingChain(true, 4)).To(Equal(&Chain{
			Name: "cali-nat-outgoing",
			Rules: []Rule{
				{
					Action: MasqAction{},
					Match: Match().
						SourceIPSet("cali4-masq-ipam-pools").
						NotDestIPSet("cali4-all-ipam-pools"),
				},
			},
		}))
	})
	It("should render nothing when inactive", func() {
		Expect(renderer.NATOutgoingChain(false, 4)).To(Equal(&Chain{
			Name:  "cali-nat-outgoing",
			Rules: nil,
		}))
	})
})
