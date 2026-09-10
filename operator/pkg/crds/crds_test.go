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
	"os"
	"strings"
	"testing/fstest"

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
		Expect(func() { Expect(getOperatorCRDSource(opv1.Calico)).ToNot(BeEmpty()) }).ToNot(Panic())
	})

	// A build serving another variant generates that variant's operator CRDs into
	// the same directory, so a Calico install has to be trimmed back to its own.
	It("gives a Calico install only the operator CRDs it ships", func() {
		files := fstest.MapFS{
			"operator.tigera.io_installations.yaml": {Data: []byte("kind: CustomResourceDefinition")},
			"operator.tigera.io_logstorages.yaml":   {Data: []byte("kind: CustomResourceDefinition")},
		}
		keep := func(name string) bool { return calicoOperatorCRDs[name] }

		docs := readCRDs(files, "test", keep)
		Expect(docs).To(HaveKey("operator.tigera.io_installations.yaml_0"))
		Expect(docs).NotTo(HaveKey("operator.tigera.io_logstorages.yaml_0"))
	})

	It("gives another variant every operator CRD its build generated", func() {
		files := fstest.MapFS{
			"operator.tigera.io_installations.yaml": {Data: []byte("kind: CustomResourceDefinition")},
			"operator.tigera.io_logstorages.yaml":   {Data: []byte("kind: CustomResourceDefinition")},
		}

		docs := readCRDs(files, "test", func(string) bool { return true })
		Expect(docs).To(HaveLen(2))
	})

	It("installs GatewayAPI CRD with Calico OSS", func() {
		Expect(getOperatorCRDSource(opv1.Calico)).To(HaveKey(ContainSubstring("gatewayapis")))
	})

	// manifests/generate.sh reads calico_operator_crds.txt and copies each file it
	// names, so a listed file that is not on disk breaks manifest generation.
	It("has every operator CRD calico_operator_crds.txt lists", func() {
		entries, err := os.ReadDir("operator")
		Expect(err).NotTo(HaveOccurred())
		onDisk := map[string]bool{}
		for _, e := range entries {
			onDisk[e.Name()] = true
		}

		for name := range calicoOperatorCRDs {
			Expect(onDisk).To(HaveKey(name))
		}
	})

	It("installs exactly those on Calico, whatever else the build generated", func() {
		installed := map[string]bool{}
		for key := range getOperatorCRDSource(opv1.Calico) {
			// readCRDs keys each YAML document as "<file>_<index>".
			installed[key[:strings.LastIndex(key, "_")]] = true
		}
		Expect(installed).To(Equal(calicoOperatorCRDs))
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
