// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

package names_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = DescribeTable("Parse Tiered policy name",
	func(policy string, expectError bool, expectedTier string) {
		tier, err := names.TierFromPolicyName(policy)
		if expectError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
			Expect(tier).To(Equal(expectedTier))
		}
	},
	Entry("Empty policy name", "", true, ""),
	Entry("K8s network policy", "knp.default.foopolicy", false, "default"),
	Entry("K8s cluster network policy (admin tier)", "kcnp.kube-admin.barpolicy", false, "kube-admin"),
	Entry("K8s cluster network policy (baseline tier)", "kcnp.kube-baseline.barpolicy", false, "kube-baseline"),
	Entry("Policy name without tier", "foopolicy", false, "default"),
	Entry("Correct tiered policy name", "baztier.foopolicy", false, "baztier"),
	Entry("OpenStack-derived policy name", "ossg.default.19bed2d3-12fc-4cc0-92d7-bea430a28a85", false, "default"),
)

var _ = DescribeTable("Backend Tiered policy name",
	func(policy, tier string, expectError bool, expectedTpn string) {
		tpn, err := names.BackendTieredPolicyName(policy, tier)
		if expectError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
			Expect(tpn).To(Equal(expectedTpn))
		}
	},
	Entry("Empty policy name", "", "foo", true, ""),
	Entry("Empty tier spec with correctly formatted name", "footier.bazpolicy", "", true, ""),
	Entry("Tier spec present with incorrectly formatted name", "bazpolicy", "footier", true, ""),
	Entry("Correcty formatted tiered policy name but not matching tier spec", "footier.bazpolicy", "baztier", true, ""),
	Entry("K8s Network Policy and empty tier", "knp.default.foobar", "", false, "knp.default.foobar"),
	Entry("K8s Cluster Network Policy (admin tier) and empty tier", "kcnp.kube-admin.foobar", "", false, "kcnp.kube-admin.foobar"),
	Entry("K8s Cluster Network Policy (baseline tier) and empty tier", "kcnp.kube-baseline.foobar", "", false, "kcnp.kube-baseline.foobar"),
	Entry("Network Policy and empty tier", "foobar", "", false, "default.foobar"),
	Entry("Matching tier spec and correctly formatted tiered policy name", "footier.bazpolicy", "footier", false, "footier.bazpolicy"),
)

var _ = DescribeTable("Tiered policy name",
	func(policy, expectedTpn string) {
		tpn := names.TieredPolicyName(policy)
		Expect(tpn).To(Equal(expectedTpn))
	},
	Entry("Empty policy name", "", ""),
	Entry("Correctly formatted name", "footier.bazpolicy", "footier.bazpolicy"),
	Entry("Policy in default tier", "bazpolicy", "default.bazpolicy"),
	Entry("Policy in default tier with prefix", "default.bazpolicy", "default.bazpolicy"),
	Entry("K8s network policy", "knp.default.bazpolicy", "knp.default.bazpolicy"),
	Entry("K8s cluster network policy (admin tier)", "kcnp.kube-admin.foopolicy", "kcnp.kube-admin.foopolicy"),
	Entry("K8s cluster network policy (baseline tier)", "kcnp.kube-baseline.foopolicy", "kcnp.kube-baseline.foopolicy"),
)

var _ = DescribeTable("Client Tiered policy name",
	func(policy string, expectError bool, expectedTpn string) {
		tpn, err := names.ClientTieredPolicyName(policy)
		if expectError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
			Expect(tpn).To(Equal(expectedTpn))
		}
	},
	Entry("Empty policy name", "foo", true, ""),
	Entry("Incorrectly formatted name", "bazpolicy", true, ""),
	Entry("Correctly formatted name", "footier.bazpolicy", false, "footier.bazpolicy"),
	Entry("Default tier", "default.bazpolicy", false, "bazpolicy"),
	Entry("K8s Network Policy", "knp.default.bazpolicy", false, "knp.default.bazpolicy"),
	Entry("K8s Cluster Network Policy (admin tier)", "kcnp.kube-admin.bazpolicy", false, "kcnp.kube-admin.bazpolicy"),
	Entry("K8s Cluster Network Policy (baseline tier)", "kcnp.kube-baseline.bazpolicy", false, "kcnp.kube-baseline.bazpolicy"),
)
