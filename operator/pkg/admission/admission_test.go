// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package admission

import (
	"testing/fstest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
)

var _ = Describe("MutatingAdmissionPolicies", func() {
	Describe("GetMutatingAdmissionPolicies", func() {
		It("returns Calico v1beta1 MAPs when v3=true", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1Beta1)
			Expect(objs).To(HaveLen(6))

			var mapCount, mapbCount int
			for _, obj := range objs {
				switch obj.(type) {
				case *admissionv1beta1.MutatingAdmissionPolicy:
					mapCount++
				case *admissionv1beta1.MutatingAdmissionPolicyBinding:
					mapbCount++
				}
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
			}
			Expect(mapCount).To(Equal(3))
			Expect(mapbCount).To(Equal(3))
		})

		It("returns Calico v1 MAPs when discovered version is v1", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1)
			Expect(objs).To(HaveLen(6))

			var mapCount, mapbCount int
			for _, obj := range objs {
				switch o := obj.(type) {
				case *admissionregistrationv1.MutatingAdmissionPolicy:
					mapCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1))
				case *admissionregistrationv1.MutatingAdmissionPolicyBinding:
					mapbCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1))
				}
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
			}
			Expect(mapCount).To(Equal(3))
			Expect(mapbCount).To(Equal(3))
		})

		It("returns Calico v1alpha1 MAPs when discovered version is v1alpha1", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1Alpha1)
			Expect(objs).To(HaveLen(6))

			var mapCount, mapbCount int
			for _, obj := range objs {
				switch o := obj.(type) {
				case *admissionregistrationv1alpha1.MutatingAdmissionPolicy:
					mapCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1Alpha1))
				case *admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding:
					mapbCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1Alpha1))
				}
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
			}
			Expect(mapCount).To(Equal(3))
			Expect(mapbCount).To(Equal(3))
		})

		It("returns the policies a variant registers", func() {
			RegisterVariantPolicies(opv1.CalicoEnterprise, fstest.MapFS{
				"policy.yaml": &fstest.MapFile{Data: []byte(enterpriseMAP)},
			})
			DeferCleanup(func() { RegisterVariantPolicies(opv1.CalicoEnterprise, nil) })

			objs := GetMutatingAdmissionPolicies(opv1.CalicoEnterprise, PolicySetV3CRDs, VersionV1)
			Expect(objs).To(HaveLen(1))
			Expect(objs[0].GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
		})

		It("returns nothing for a variant whose policies this build does not ship", func() {
			Expect(GetMutatingAdmissionPolicies(opv1.CalicoEnterprise, PolicySetV3CRDs, VersionV1)).To(BeEmpty())
		})

		It("labels each one managed and in the v3 CRD set", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1)
			Expect(objs).NotTo(BeEmpty())
			for _, obj := range objs {
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
				Expect(obj.GetLabels()).To(HaveKeyWithValue(PolicySetLabel, string(PolicySetV3CRDs)))
			}
		})

		It("returns empty when apiVersion is empty", func() {
			Expect(GetMutatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, "")).To(BeEmpty())
		})

		It("parses MAP names correctly", func() {
			objs := GetMutatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1)
			for _, obj := range objs {
				Expect(obj.GetName()).ToNot(BeEmpty())
			}
		})
	})

	Describe("GetValidatingAdmissionPolicies", func() {
		It("returns Calico v1 VAPs when discovered version is v1", func() {
			objs := GetValidatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1)
			Expect(objs).To(HaveLen(2))

			var vapCount, vapbCount int
			for _, obj := range objs {
				switch o := obj.(type) {
				case *admissionregistrationv1.ValidatingAdmissionPolicy:
					vapCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1))
				case *admissionregistrationv1.ValidatingAdmissionPolicyBinding:
					vapbCount++
					Expect(o.APIVersion).To(Equal(APIGroup + "/" + VersionV1))
				}
				Expect(obj.GetName()).ToNot(BeEmpty())
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedVAPLabel, ManagedVAPLabelValue))
			}
			Expect(vapCount).To(Equal(1))
			Expect(vapbCount).To(Equal(1))
		})

		It("returns Calico v1beta1 VAPs when discovered version is v1beta1", func() {
			objs := GetValidatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1Beta1)
			Expect(objs).To(HaveLen(2))

			var vapCount, vapbCount int
			for _, obj := range objs {
				switch obj.(type) {
				case *admissionv1beta1.ValidatingAdmissionPolicy:
					vapCount++
				case *admissionv1beta1.ValidatingAdmissionPolicyBinding:
					vapbCount++
				}
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedVAPLabel, ManagedVAPLabelValue))
			}
			Expect(vapCount).To(Equal(1))
			Expect(vapbCount).To(Equal(1))
		})

		It("returns Calico v1alpha1 VAPs when discovered version is v1alpha1", func() {
			objs := GetValidatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1Alpha1)
			Expect(objs).To(HaveLen(2))

			var vapCount, vapbCount int
			for _, obj := range objs {
				switch obj.(type) {
				case *admissionregistrationv1alpha1.ValidatingAdmissionPolicy:
					vapCount++
				case *admissionregistrationv1alpha1.ValidatingAdmissionPolicyBinding:
					vapbCount++
				}
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedVAPLabel, ManagedVAPLabelValue))
			}
			Expect(vapCount).To(Equal(1))
			Expect(vapbCount).To(Equal(1))
		})

		It("returns nothing for a variant whose policies this build does not ship", func() {
			Expect(GetValidatingAdmissionPolicies(opv1.CalicoEnterprise, PolicySetV3CRDs, VersionV1)).To(BeEmpty())
		})

		It("labels each one managed and in the v3 CRD set", func() {
			objs := GetValidatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1)
			Expect(objs).NotTo(BeEmpty())
			for _, obj := range objs {
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedVAPLabel, ManagedVAPLabelValue))
				Expect(obj.GetLabels()).To(HaveKeyWithValue(PolicySetLabel, string(PolicySetV3CRDs)))
			}
		})

		It("returns empty when apiVersion is empty", func() {
			Expect(GetValidatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, "")).To(BeEmpty())
		})
	})

	Describe("GetMutatingAdmissionPolicies for the CNI annotation set", func() {
		for _, version := range []string{VersionV1, VersionV1Beta1, VersionV1Alpha1} {
			It("returns the policy that strips the CNI annotations at "+version, func() {
				objs := GetMutatingAdmissionPolicies(opv1.Calico, PolicySetCNIAnnotations, version)
				Expect(objs).To(HaveLen(2))

				var mapCount, mapbCount int
				for _, obj := range objs {
					switch {
					case IsPolicyKind(obj):
						mapCount++
					case IsBindingKind(obj):
						mapbCount++
					}
					Expect(obj.GetName()).To(Equal("strip-cni-annotations.projectcalico.org"))
					Expect(obj.GetObjectKind().GroupVersionKind().Version).To(Equal(version))
					Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedMAPLabel, ManagedMAPLabelValue))
					Expect(obj.GetLabels()).To(HaveKeyWithValue(PolicySetLabel, string(PolicySetCNIAnnotations)))
				}
				Expect(mapCount).To(Equal(1))
				Expect(mapbCount).To(Equal(1))
			})
		}

		It("does not return it among the v3 policies", func() {
			for _, obj := range GetMutatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1) {
				Expect(obj.GetName()).NotTo(Equal("strip-cni-annotations.projectcalico.org"))
			}
		})

		It("returns empty when apiVersion is empty", func() {
			Expect(GetMutatingAdmissionPolicies(opv1.Calico, PolicySetCNIAnnotations, "")).To(BeEmpty())
		})
	})

	Describe("GetValidatingAdmissionPolicies for the CNI annotation set", func() {
		It("returns the CNI annotation policies, labeled apart from the v3 ones", func() {
			objs := GetValidatingAdmissionPolicies(opv1.Calico, PolicySetCNIAnnotations, VersionV1)
			Expect(objs).To(HaveLen(2))

			var vapCount, vapbCount int
			for _, obj := range objs {
				switch obj.(type) {
				case *admissionregistrationv1.ValidatingAdmissionPolicy:
					vapCount++
				case *admissionregistrationv1.ValidatingAdmissionPolicyBinding:
					vapbCount++
				}
				Expect(obj.GetName()).To(Equal("protect-cni-annotations.projectcalico.org"))
				Expect(obj.GetLabels()).To(HaveKeyWithValue(ManagedVAPLabel, ManagedVAPLabelValue))
				Expect(obj.GetLabels()).To(HaveKeyWithValue(PolicySetLabel, string(PolicySetCNIAnnotations)))
			}
			Expect(vapCount).To(Equal(1))
			Expect(vapbCount).To(Equal(1))
		})

		It("does not return them among the v3 policies", func() {
			for _, obj := range GetValidatingAdmissionPolicies(opv1.Calico, PolicySetV3CRDs, VersionV1) {
				Expect(obj.GetName()).NotTo(Equal("protect-cni-annotations.projectcalico.org"))
			}
		})

		It("returns nothing for a variant that registers none", func() {
			RegisterVariantPolicies(opv1.CalicoEnterprise, fstest.MapFS{
				"policy.yaml": &fstest.MapFile{Data: []byte(enterpriseMAP)},
			})
			DeferCleanup(func() { RegisterVariantPolicies(opv1.CalicoEnterprise, nil) })

			Expect(GetValidatingAdmissionPolicies(opv1.CalicoEnterprise, PolicySetCNIAnnotations, VersionV1)).To(BeEmpty())
		})

		It("returns empty when apiVersion is empty", func() {
			Expect(GetValidatingAdmissionPolicies(opv1.Calico, PolicySetCNIAnnotations, "")).To(BeEmpty())
		})
	})
})

const enterpriseMAP = `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: test-policy
spec:
  matchConstraints:
    resourceRules: []
`
