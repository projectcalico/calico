// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"

	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

var _ = Describe("Namespace conversion tests", func() {

	nsConverter := converter.NewNamespaceConverter()

	It("should parse a Namespace to a Profile", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Labels: map[string]string{
					"foo.org/bar": "baz",
					"roger":       "rabbit",
				},
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := nsConverter.Convert(&ns)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		expectedName := "kns.default"
		actualName := p.(api.Profile).Name
		By("returning a Calico profile with the expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})

		inboundRules := p.(api.Profile).Spec.Ingress
		outboundRules := p.(api.Profile).Spec.Egress
		By("returning a Calico profile with the correct number of rules", func() {
			Expect(len(inboundRules)).To(Equal(1))
			Expect(len(outboundRules)).To(Equal(1))
		})

		By("returning a Calico profile with rules set to allow", func() {
			Expect(inboundRules[0]).To(Equal(api.Rule{Action: api.Allow}))
			Expect(outboundRules[0]).To(Equal(api.Rule{Action: api.Allow}))
		})

		labels := p.(api.Profile).Spec.LabelsToApply
		By("returning a Calico profile with the correct labels to apply", func() {
			Expect(labels["pcns.foo.org/bar"]).To(Equal("baz"))
			Expect(labels["pcns.roger"]).To(Equal("rabbit"))
		})
	})

	It("should parse a Namespace to a Profile with no labels", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "default",
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}
		p, err := nsConverter.Convert(&ns)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Ensure correct profile name
		expectedName := "kns.default"
		actualName := p.(api.Profile).Name
		By("returning a Calico profile with the expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})

		// Ensure rules are correct for profile.
		inboundRules := p.(api.Profile).Spec.Ingress
		outboundRules := p.(api.Profile).Spec.Egress
		By("returning a Calico profile with the correct rules", func() {
			Expect(len(inboundRules)).To(Equal(1))
			Expect(len(outboundRules)).To(Equal(1))
		})

		By("returning a Calico profile with rules set to allow", func() {
			Expect(inboundRules[0]).To(Equal(api.Rule{Action: api.Allow}))
			Expect(outboundRules[0]).To(Equal(api.Rule{Action: api.Allow}))
		})

		labels := p.(api.Profile).Spec.LabelsToApply
		By("returning a Calico profile with no labels to apply", func() {
			Expect(len(labels)).To(Equal(1))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown conversion", func() {
		ns := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: &k8sapi.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "default",
					Annotations: map[string]string{},
				},
				Spec: k8sapi.NamespaceSpec{},
			},
		}
		p, err := nsConverter.Convert(ns)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Ensure correct profile name
		expectedName := "kns.default"
		actualName := p.(api.Profile).Name
		By("returning a Calico profile with expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown with non-Namespace Obj", func() {
		ns := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: "just a string",
		}

		_, err := nsConverter.Convert(ns)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should handle invalid object conversion", func() {
		ns := "just a string"

		_, err := nsConverter.Convert(ns)
		By("not generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should generate the right key for a Profile", func() {
		profileName := "kns.default"
		profile := api.Profile{
			ObjectMeta: metav1.ObjectMeta{
				Name: profileName,
			},
			Spec: api.ProfileSpec{},
		}

		// Get key of profile
		key := nsConverter.GetKey(profile)
		By("returning the profile's name as its key", func() {
			Expect(key).To(Equal(profileName))
		})

		By("parsing the returned key back into component fields", func() {
			ns, name := nsConverter.DeleteArgsFromKey(key)
			Expect(ns).To(Equal(""))
			Expect(name).To(Equal("kns.default"))
		})

	})
})
