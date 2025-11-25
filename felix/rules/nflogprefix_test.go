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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

var (
	// 62 characters with XXX0|gnp/ prefixed.
	chars62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// 63 characters with XXX0|gnp/ prefixed.
	chars63 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0"
)

var _ = Describe("NFLOG prefix construction tests", func() {
	DescribeTable(
		"CalculateNFLOGPrefixStr should return correct result",
		func(action RuleAction, owner RuleOwnerType, dir RuleDir, idx int, name types.IDMaker, expected string, expectHash bool) {
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
			types.PolicyID{Name: "default.policy", Namespace: "namespace1", Kind: v3.KindNetworkPolicy},
			"API0|np/namespace1/default.policy",
			false,
		),
		Entry(
			"Short profile name - will not hash",
			RuleActionPass, RuleOwnerTypeProfile, RuleDirEgress, 999,
			types.ProfileID{Name: "short.profile.name"},
			"PRE999|short.profile.name", false,
		),
		Entry(
			"Policy name makes raw prefix 62 bytes - will not hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirEgress, 88,
			types.PolicyID{Name: chars62, Kind: v3.KindGlobalNetworkPolicy},
			fmt.Sprintf("DPE88|gnp/%s", chars62), false,
		),
		Entry(
			"Policy name makes raw prefix 63 bytes - will hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirIngress, 88,
			types.PolicyID{Name: chars63, Kind: v3.KindGlobalNetworkPolicy},
			"DPI88|gnp/_12IXaBPahNM7a7dZhI8zg6PStmHsgneYaax8LVSIq_RSTUVWXYZ0", true,
		),
		Entry(
			"Very long GNP name - will hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirEgress, 1,
			types.PolicyID{Name: "this-is-still-quite-a-long-tier-name-even-though-its-not-required.quite-a-long-policy-name", Kind: v3.KindGlobalNetworkPolicy},
			"DPE1|gnp/t_FSGxA9eGa6t_A5Rj2agPvl4aq8-eohq0An6xEW4n7_olicy-name", true,
		),
		Entry(
			"A similar (but different) very long GNP name - will hash",
			RuleActionDeny, RuleOwnerTypePolicy, RuleDirEgress, 2,
			types.PolicyID{Name: "this-is-still-quite-a-long-tier-name-even-though-its-not-required.quite-a-long-policy-name2", Kind: v3.KindGlobalNetworkPolicy},
			"DPE2|gnp/t_G4MaamO0BQNQg8Ibyy-r9qg2HIK8-7EaPOVzsy5Nv_licy-name2", true,
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
