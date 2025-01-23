// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

package updateprocessors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
)

var _ = Describe("Test the StagedKubernetesNetworkPolicy update processor", func() {
	name1 := "name1"
	ns1 := "namespace1"

	v3StagedKubernetesNetworkPolicyKey1 := model.ResourceKey{
		Kind:      apiv3.KindStagedKubernetesNetworkPolicy,
		Name:      name1,
		Namespace: ns1,
	}

	v1StagedKubernetesNetworkPolicyKey1 := model.PolicyKey{
		Name: ns1 + "/" + model.PolicyNamePrefixStaged + "knp.default." + name1,
		Tier: "default",
	}

	It("should handle conversion of valid StagedKubernetesNetworkPolicy", func() {
		up := updateprocessors.NewStagedKubernetesNetworkPolicyUpdateProcessor()

		By("converting a StagedKubernetesNetworkPolicy with minimum configuration")
		res := apiv3.NewStagedKubernetesNetworkPolicy()
		res.Name = name1
		res.Namespace = ns1
		res.Spec.StagedAction = apiv3.StagedActionSet

		expectedOrder := float64(1000)
		kvps, err := up.Process(&model.KVPair{
			Key:      v3StagedKubernetesNetworkPolicyKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1StagedKubernetesNetworkPolicyKey1,
			Value: &model.Policy{
				Namespace:      ns1,
				Selector:       "(projectcalico.org/orchestrator == 'k8s') && projectcalico.org/namespace == 'namespace1'",
				ApplyOnForward: false,
				StagedAction:   &res.Spec.StagedAction,
				Order:          &expectedOrder,
				Types:          []string{"ingress"},
			},
			Revision: "abcde",
		}))
	})

})
