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

package rules_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("NFLOG prefix construction tests", func() {
	DescribeTable(
		"CalculateNFLOGPrefixStr should return correct result",
		func(action RuleAction, owner RuleOwnerType, dir RuleDir, idx int, name string, expected string, expectHash bool) {
			actual := CalculateNFLOGPrefixStr(action, owner, dir, idx, name)
			Expect(actual).To(Equal(expected), actual)
			if expectHash {
				Expect(len(actual)).To(Equal(63))
			} else {
				Expect(len(actual)).To(BeNumerically("<", 63))
			}
		},
		Entry(
			"Short NP name - will not hash",
			RuleActionAllow, RuleOwnerTypePolicy, RuleDirIngress, 0,
			"namespace1/default.policy",
			"API0|namespace1/default.policy", false,
		),
		Entry(
			"Short profile name - will not hash",
			RuleActionPass, RuleOwnerTypeProfile, RuleDirEgress, 999,
			"short.profile.name",
			"PRE999|short.profile.name", false,
		),
		Entry(
			"Policy name makes raw prefix 62 bytes - will not hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirEgress, 88,
			"01234567890123456789012345678901234567890123456789012345",
			"DPE88|01234567890123456789012345678901234567890123456789012345", false,
		),
		Entry(
			"Policy name makes raw prefix 63 bytes - will hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirIngress, 88,
			"012345678901234567890123456789012345678901234567890123456",
			"DPI88|0123_S7GBfc7R7_4bzrXpbzglqoJrRG_UxIP0CuYjRWshz_7890123456", true,
		),
		Entry(
			"Very long GNP name - will hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirEgress, 1,
			"quite-a-long-namespace/quite-a-long-tier-name.quite-a-long-policy-name",
			"DPE1|quite_nnW4FYptgISH4G3jdI6KJWVcEx19s0BDp2On0wVAY_olicy-name", true,
		),
		Entry(
			"A similar (but different) very long GNP name - will hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirEgress, 2,
			"quite-a-long-namespace/quite-a-long-tier-name.quite-a-long-policy-name2",
			"DPE2|quite_1G46uquk9ypeSpt4I-AIn1FSwWxCefDd8GEcuoxHP_licy-name2", true,
		),
	)

	DescribeTable(
		"CalculateEndOfTierDropNFLOGPrefixStr should return correct result",
		func(dir RuleDir, tier string, expected string, expectHash bool) {
			actual := CalculateEndOfTierDropNFLOGPrefixStr(dir, tier)
			Expect(actual).To(Equal(expected), actual)
			if expectHash {
				Expect(len(actual)).To(Equal(63))
			} else {
				Expect(len(actual)).To(BeNumerically("<", 63))
			}
		},
		Entry(
			"Short tier name - will not hash",
			RuleDirEgress, "tier-1",
			"DPE|tier-1", false,
		),
		Entry(
			"Tier name makes raw prefix 62 bytes - will not hash",
			RuleDirIngress, "tier-01234567890123456789012345678901234567890123456789012",
			"DPI|tier-01234567890123456789012345678901234567890123456789012", false,
		),
		Entry(
			"Tier name makes raw prefix 63 bytes - will hash",
			RuleDirIngress, "tier-012345678901234567890123456789012345678901234567890123",
			"DPI|tier-0_phEfG4Vhbq2xh4TQsePNa2X9YRj5peCVw1FgaNSbd_4567890123", true,
		),
	)

	DescribeTable(
		"CalculateNoMatchProfileNFLOGPrefixStr should return correct result",
		func(dir RuleDir, expected string) {
			actual := CalculateNoMatchProfileNFLOGPrefixStr(dir)
			Expect(actual).To(Equal(expected), actual)
		},
		Entry(
			"Ingress",
			RuleDirIngress, "DRI",
		),
		Entry(
			"Egress",
			RuleDirEgress, "DRE",
		),
	)
})
