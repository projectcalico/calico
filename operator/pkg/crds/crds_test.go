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
	_ "embed"
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
)

//go:embed calico_operator_crds.txt
var calicoOperatorCRDList string

// The real test here is simply calling these functions will result in a panic if any of the CRDs cannot be parsed

var _ = Describe("test crds pkg", func() {
	for _, v3 := range []bool{true, false} {
		It(fmt.Sprintf("can parse Calico CRDs (v3=%t)", v3), func() {
			Expect(func() { Expect(getCalicoCRDSource(v3)).ToNot(BeEmpty()) }).ToNot(Panic())
		})

		It(fmt.Sprintf("can get all CRDS used with Calico (v3=%t)", v3), func() {
			Expect(func() { Expect(GetCRDs(opv1.Calico, v3)).ToNot(BeEmpty()) }).ToNot(Panic())
		})

		It(fmt.Sprintf("includes K8s policy CRDs for Calico (v3=%t)", v3), func() {
			clear(crdCache)
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
				clear(crdCache)
			})

			crdNames := map[string]bool{}
			for _, crd := range GetCRDs(opv1.CalicoEnterprise, v3) {
				crdNames[crd.Name] = true
			}
			Expect(crdNames).To(HaveKey("wafpolicies.applicationlayer.projectcalico.org"))
		})
	}

	It("can parse the operator's own CRDs", func() {
		Expect(func() { Expect(getOperatorCRDSource()).ToNot(BeEmpty()) }).ToNot(Panic())
	})

	It("installs GatewayAPI CRD with Calico OSS", func() {
		Expect(getOperatorCRDSource()).To(HaveKey(ContainSubstring("gatewayapis")))
	})

	// manifests/generate.sh folds the operator CRDs into the bundles from this list,
	// so a CRD the operator installs but the list omits never reaches the manifests.
	It("ships exactly the operator CRDs calico_operator_crds.txt lists", func() {
		listed := map[string]bool{}
		for _, line := range strings.Split(calicoOperatorCRDList, "\n") {
			if name := strings.TrimSpace(line); name != "" && !strings.HasPrefix(name, "#") {
				listed[name] = true
			}
		}

		entries, err := os.ReadDir("operator")
		Expect(err).NotTo(HaveOccurred())
		onDisk := map[string]bool{}
		for _, e := range entries {
			onDisk[e.Name()] = true
		}

		Expect(onDisk).To(Equal(listed))
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
