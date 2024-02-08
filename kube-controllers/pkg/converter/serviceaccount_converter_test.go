// Copyright (c) 2018,2021 Tigera, Inc. All rights reserved.
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

package converter_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"

	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

var _ = Describe("ServiceAccount conversion tests", func() {

	saConverter := converter.NewServiceAccountConverter()

	It("should parse a Service Account to a Profile", func() {
		sa := k8sapi.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "serviceaccount",
				Labels: map[string]string{
					"foo.org/bar": "baz",
					"roger":       "rabbit",
				},
				Annotations: map[string]string{},
			},
		}

		p, err := saConverter.Convert(&sa)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		expectedName := "ksa.default.serviceaccount"
		actualName := p.(api.Profile).Name
		By("returning a Calico profile with the expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})

		inboundRules := p.(api.Profile).Spec.Ingress
		outboundRules := p.(api.Profile).Spec.Egress
		By("returning a Calico profile with the correct number of rules", func() {
			Expect(len(inboundRules)).To(Equal(0))
			Expect(len(outboundRules)).To(Equal(0))
		})

		labels := p.(api.Profile).Spec.LabelsToApply
		By("returning a Calico profile with the correct labels to apply", func() {
			Expect(labels["pcsa.foo.org/bar"]).To(Equal("baz"))
			Expect(labels["pcsa.roger"]).To(Equal("rabbit"))
		})
	})

	It("should parse a ServiceAccount to a Profile with no labels", func() {
		sa := k8sapi.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "serviceaccount",
				Annotations: map[string]string{},
			},
		}
		p, err := saConverter.Convert(&sa)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Ensure correct profile name
		expectedName := "ksa.default.serviceaccount"
		actualName := p.(api.Profile).Name
		By("returning a Calico profile with the expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})

		// Ensure rules are correct for profile.
		inboundRules := p.(api.Profile).Spec.Ingress
		outboundRules := p.(api.Profile).Spec.Egress
		By("returning a Calico profile with the correct rules", func() {
			Expect(len(inboundRules)).To(Equal(0))
			Expect(len(outboundRules)).To(Equal(0))
		})

		labels := p.(api.Profile).Spec.LabelsToApply
		By("returning a Calico profile with no labels to apply", func() {
			Expect(len(labels)).To(Equal(1))
		})
	})

	It("should parse a ServiceAccount in a namespace to a Profile", func() {
		sa := k8sapi.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "serviceaccount",
				Namespace:   "foo",
				Annotations: map[string]string{},
			},
		}
		p, err := saConverter.Convert(&sa)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Ensure correct profile name
		expectedName := "ksa.foo.serviceaccount"
		actualName := p.(api.Profile).Name
		By("returning a Calico profile with the expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})

		// Ensure rules are correct for profile.
		inboundRules := p.(api.Profile).Spec.Ingress
		outboundRules := p.(api.Profile).Spec.Egress
		By("returning a Calico profile with the correct rules", func() {
			Expect(len(inboundRules)).To(Equal(0))
			Expect(len(outboundRules)).To(Equal(0))
		})

		labels := p.(api.Profile).Spec.LabelsToApply
		By("returning a Calico profile with no labels to apply", func() {
			Expect(len(labels)).To(Equal(1))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown conversion", func() {
		sa := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: &k8sapi.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "serviceaccount",
					Annotations: map[string]string{},
				},
			},
		}
		p, err := saConverter.Convert(sa)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Ensure correct profile name
		expectedName := "ksa.default.serviceaccount"
		actualName := p.(api.Profile).Name
		By("returning a Calico profile with expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown with non-ServiceAccount Obj", func() {
		sa := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: "just a string",
		}

		_, err := saConverter.Convert(sa)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should handle invalid object conversion", func() {
		sa := "just a string"

		_, err := saConverter.Convert(sa)
		By("not generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should generate the right key for a Profile", func() {
		profileName := "ksa.default.serviceaccount"
		profile := api.Profile{
			ObjectMeta: metav1.ObjectMeta{
				Name: profileName,
			},
			Spec: api.ProfileSpec{},
		}

		// Get key of profile
		key := saConverter.GetKey(profile)
		By("returning the profile's name as its key", func() {
			Expect(key).To(Equal(profileName))
		})

		By("parsing the returned key back into component fields", func() {
			sa, name := saConverter.DeleteArgsFromKey(key)
			Expect(sa).To(Equal(""))
			Expect(name).To(Equal("ksa.default.serviceaccount"))
		})

	})
})
