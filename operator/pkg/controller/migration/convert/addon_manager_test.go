// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package convert

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("addon manager", func() {
	addonMgrLabel := map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"}

	It("should succeed if addon manager isn't denoted", func() {
		comps := emptyComponents()
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).ToNot(HaveOccurred())
	})
	It("should fail if calico-node is managed by addon-manager", func() {
		comps := emptyComponents()
		comps.node.Labels = addonMgrLabel
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).To(HaveOccurred())
	})
	It("should fail if kube-controllers is managed by addon-manager", func() {
		comps := emptyComponents()
		comps.kubeControllers.Labels = addonMgrLabel
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).To(HaveOccurred())
	})
	It("should fail if typha is managed by addon-manager", func() {
		comps := emptyComponents()
		comps.typha.Labels = addonMgrLabel
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).To(HaveOccurred())
	})
})
