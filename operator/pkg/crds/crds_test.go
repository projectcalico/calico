// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package crds

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
)

// The real test here is simply calling these functions will result in a panic if any of the CRDs cannot be parsed

var _ = Describe("test crds pkg", func() {
	for _, v3 := range []bool{true, false} {
		It(fmt.Sprintf("can parse Calico CRDs (v3=%t)", v3), func() {
			Expect(func() { Expect(getCalicoCRDSource(v3)).ToNot(BeEmpty()) }).ToNot(Panic())
		})

		It(fmt.Sprintf("can get all CRDS used with Calico (v3=%t)", v3), func() {
			Expect(func() { Expect(GetCRDs(opv1.Calico, v3)).ToNot(BeEmpty()) }).ToNot(Panic())
		})

		It("gets the operator's own CRDs for Enterprise, whose others are registered elsewhere", func() {
			enterpriseCRDs = nil
			crds := GetCRDs(opv1.CalicoEnterprise, v3)
			Expect(crds).ToNot(BeEmpty())

			crdNames := map[string]bool{}
			for _, crd := range crds {
				crdNames[crd.Name] = true
			}
			Expect(crdNames).To(HaveKey("logstorages.operator.tigera.io"))
			Expect(crdNames).ToNot(HaveKey("wafpolicies.applicationlayer.projectcalico.org"))
		})

		It(fmt.Sprintf("includes K8s policy CRDs for Calico (v3=%t)", v3), func() {
			calicoCRDs = nil
			crds := GetCRDs(opv1.Calico, v3)
			crdNames := map[string]bool{}
			for _, crd := range crds {
				crdNames[crd.Name] = true
			}
			Expect(crdNames).To(HaveKey("clusternetworkpolicies.policy.networking.k8s.io"))
		})

		It(fmt.Sprintf("includes the CRDs a variant registers (v3=%t)", v3), func() {
			RegisterVariantCRDs(opv1.CalicoEnterprise, func(bool) map[string][]byte {
				return map[string][]byte{"waf_0": []byte(wafPolicyCRD)}
			})
			DeferCleanup(func() {
				variantCRDs = map[opv1.ProductVariant][]CRDSource{}
				enterpriseCRDs = nil
			})

			crdNames := map[string]bool{}
			for _, crd := range GetCRDs(opv1.CalicoEnterprise, v3) {
				crdNames[crd.Name] = true
			}
			Expect(crdNames).To(HaveKey("wafpolicies.applicationlayer.projectcalico.org"))
		})
	}

	It("can parse Operator CRDs used with calico", func() {
		Expect(func() { Expect(getOperatorCRDSource(opv1.Calico)).ToNot(BeEmpty()) }).ToNot(Panic())
	})

	It("can parse Operator CRDs used with Enterprise", func() {
		Expect(func() { Expect(getOperatorCRDSource(opv1.CalicoEnterprise)).ToNot(BeEmpty()) }).ToNot(Panic())
	})

	It("installs GatewayAPI CRD with Calico OSS", func() {
		Expect(getOperatorCRDSource(opv1.Calico)).To(HaveKey(ContainSubstring("gatewayapis")))
	})
})

const wafPolicyCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: wafpolicies.applicationlayer.projectcalico.org
spec:
  group: applicationlayer.projectcalico.org
  names:
    kind: WAFPolicy
    listKind: WAFPolicyList
    plural: wafpolicies
    singular: wafpolicy
  scope: Namespaced
  versions:
    - name: v3
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
`
