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

	opv1 "github.com/tigera/operator/api/v1"
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

		It("can get all CRDS used with Enterprise", func() {
			Expect(func() { Expect(GetCRDs(opv1.CalicoEnterprise, v3)).ToNot(BeEmpty()) }).ToNot(Panic())
		})

		It("can parse Enterprise CRDs", func() {
			Expect(func() { Expect(getEnterpriseCRDSource(v3)).ToNot(BeEmpty()) }).ToNot(Panic())
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

		It(fmt.Sprintf("includes K8s policy CRDs for Enterprise (v3=%t)", v3), func() {
			enterpriseCRDs = nil
			crds := GetCRDs(opv1.CalicoEnterprise, v3)
			crdNames := map[string]bool{}
			for _, crd := range crds {
				crdNames[crd.Name] = true
			}
			Expect(crdNames).To(HaveKey("adminnetworkpolicies.policy.networking.k8s.io"))
			Expect(crdNames).To(HaveKey("baselineadminnetworkpolicies.policy.networking.k8s.io"))
		})

		It(fmt.Sprintf("includes applicationlayer WAF CRDs for Enterprise in both CRD modes (v3=%t)", v3), func() {
			enterpriseCRDs = nil
			crds := GetCRDs(opv1.CalicoEnterprise, v3)
			crdNames := map[string]bool{}
			for _, crd := range crds {
				crdNames[crd.Name] = true
			}
			// The applicationlayer.projectcalico.org group is CRD-only (not served by the
			// aggregated apiserver) and has a single v3 schema, so its CRDs must install in
			// both v1-CRD and v3-CRD modes - otherwise gateway WAF is unusable on standard
			// apiserver-backed installs.
			Expect(crdNames).To(HaveKey("wafpolicies.applicationlayer.projectcalico.org"))
			Expect(crdNames).To(HaveKey("globalwafpolicies.applicationlayer.projectcalico.org"))
			Expect(crdNames).To(HaveKey("wafplugins.applicationlayer.projectcalico.org"))
			Expect(crdNames).To(HaveKey("globalwafplugins.applicationlayer.projectcalico.org"))
			Expect(crdNames).To(HaveKey("wafvalidationpolicies.applicationlayer.projectcalico.org"))
			Expect(crdNames).To(HaveKey("globalwafvalidationpolicies.applicationlayer.projectcalico.org"))
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
