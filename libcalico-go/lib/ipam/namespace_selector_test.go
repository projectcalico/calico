// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

package ipam

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("SelectsNamespace", func() {
	Context("when namespaceSelector is empty", func() {
		It("should return true for any namespace", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: "",
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: map[string]string{"region": "east"},
				},
			}
			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeTrue())
		})
	})

	Context("when namespaceSelector matches namespace labels", func() {
		It("should return true for matching labels", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "east"`,
				},
			}

			namespaceLabels := map[string]string{
				"region":      "east",
				"environment": "production",
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: namespaceLabels,
				},
			}
			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeTrue())
		})

		It("should return true for complex selector expressions", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "east" && environment == "production"`,
				},
			}

			namespaceLabels := map[string]string{
				"region":      "east",
				"environment": "production",
				"team":        "backend",
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: namespaceLabels,
				},
			}
			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeTrue())
		})

		It("should support 'in' operator", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region in {"east", "west"}`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: map[string]string{"region": "west"},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeTrue())
		})

		It("should support 'has' operator", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `has(region)`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"region":      "east",
						"environment": "production",
					},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeTrue())
		})
	})

	Context("when namespaceSelector does not match namespace labels", func() {
		It("should return false for non-matching labels", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "east"`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"region":      "west",
						"environment": "production",
					},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeFalse())
		})

		It("should return false when required label is missing", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "east"`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: map[string]string{"environment": "production"},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeFalse())
		})

		It("should return false for empty namespace labels", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "east"`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: map[string]string{},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeFalse())
		})

		It("should return false for nil namespace labels", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "east"`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: nil,
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeFalse())
		})
	})

	Context("when namespaceSelector has invalid syntax", func() {
		It("should return an error for malformed selector", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == `,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: map[string]string{"region": "east"},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).To(HaveOccurred())
			Expect(matches).To(BeFalse())
		})

		It("should return an error for invalid operator", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region === "east"`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: map[string]string{"region": "east"},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).To(HaveOccurred())
			Expect(matches).To(BeFalse())
		})
	})

	Context("edge cases", func() {
		It("should handle empty namespace name", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "east"`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "",
					Labels: map[string]string{"region": "east"},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeTrue())
		})

		It("should handle special characters in label values", func() {
			pool := v3.IPPool{
				Spec: v3.IPPoolSpec{
					NamespaceSelector: `region == "us-east-1"`,
				},
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test-namespace",
					Labels: map[string]string{"region": "us-east-1"},
				},
			}

			matches, err := SelectsNamespace(pool, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(matches).To(BeTrue())
		})
	})
})
