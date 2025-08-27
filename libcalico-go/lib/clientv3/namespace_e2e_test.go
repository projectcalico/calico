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

package clientv3_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("Namespace tests (Kubernetes only)", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	var c clientv3.Interface

	BeforeEach(func() {
		var err error
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("Basic CRUD operations", func() {
		It("should get an existing namespace", func() {
			ns, err := c.Namespaces().Get(ctx, "default", options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(ns).NotTo(BeNil())
			Expect(ns.Name).To(Equal("default"))
		})

		It("should create a new namespace", func() {
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace-" + time.Now().Format("20060102150405"),
					Labels: map[string]string{
						"test-label": "test-value",
					},
					Annotations: map[string]string{
						"test-annotation": "test-annotation-value",
					},
				},
			}

			ns, err := c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(ns).NotTo(BeNil())
			Expect(ns.Name).To(Equal(newNamespace.Name))
			Expect(ns.ObjectMeta.Labels["test-label"]).To(Equal("test-value"))
			Expect(ns.ObjectMeta.Annotations["test-annotation"]).To(Equal("test-annotation-value"))
			Expect(ns.Status.Phase).To(Equal(corev1.NamespaceActive))
		})

		It("should update an existing namespace", func() {
			// Create namespace first
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "update-test-" + time.Now().Format("20060102150405"),
					Labels: map[string]string{
						"initial-label": "initial-value",
					},
				},
			}

			ns, err := c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Update the namespace
			ns.ObjectMeta.Labels["updated-label"] = "updated-value"
			ns.ObjectMeta.Annotations = map[string]string{
				"updated-annotation": "updated-annotation-value",
			}

			updatedNs, err := c.Namespaces().Update(ctx, ns, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedNs).NotTo(BeNil())
			Expect(updatedNs.ObjectMeta.Labels["initial-label"]).To(Equal("initial-value"))
			Expect(updatedNs.ObjectMeta.Labels["updated-label"]).To(Equal("updated-value"))
			Expect(updatedNs.ObjectMeta.Annotations["updated-annotation"]).To(Equal("updated-annotation-value"))
		})

		It("should delete a namespace", func() {
			// Create namespace to delete
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "delete-test-" + time.Now().Format("20060102150405"),
				},
			}

			ns, err := c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Delete the namespace
			deletedNs, err := c.Namespaces().Delete(ctx, ns.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(deletedNs).NotTo(BeNil())
			Expect(deletedNs.Name).To(Equal(ns.Name))

			// Verify deletion - wait for deletion to complete
			Eventually(func() error {
				_, err := c.Namespaces().Get(ctx, ns.Name, options.GetOptions{})
				return err
			}, "10s", "1s").Should(HaveOccurred())

			// Check for any error indicating not found
			_, err = c.Namespaces().Get(ctx, ns.Name, options.GetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Or(
				ContainSubstring("not found"),
				ContainSubstring("NotFound"),
				ContainSubstring("does not exist"),
			))
		})

		It("should list namespaces", func() {
			nsList, err := c.Namespaces().List(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(nsList).NotTo(BeNil())

			Expect(len(nsList.Items)).To(BeNumerically(">=", 1))

			// Check that default namespace is in the list
			defaultFound := false
			for _, ns := range nsList.Items {
				if ns.Name == "default" {
					defaultFound = true
					break
				}
			}
			Expect(defaultFound).To(BeTrue())
		})
	})

	Context("Error handling", func() {
		It("should error when creating namespace with no name", func() {
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					// No name specified
				},
			}

			_, err := c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("name"))
		})

		It("should error when creating duplicate namespace", func() {
			name := "duplicate-test-" + time.Now().Format("20060102150405")
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			}

			// Create first time
			ns, err := c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(ns).NotTo(BeNil())

			// Try to create again
			_, err = c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("already exists"))
		})

		It("should error when updating non-existent namespace", func() {
			nonExistentNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "non-existent-" + time.Now().Format("20060102150405"),
				},
			}

			_, err := c.Namespaces().Update(ctx, nonExistentNamespace, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("should error when deleting non-existent namespace", func() {
			nonExistentName := "non-existent-" + time.Now().Format("20060102150405")
			_, err := c.Namespaces().Delete(ctx, nonExistentName, options.DeleteOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})

		It("should error when getting non-existent namespace", func() {
			nonExistentNS := "non-existent-" + time.Now().Format("20060102150405")
			_, err := c.Namespaces().Get(ctx, nonExistentNS, options.GetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not found"))
		})
	})

	Context("Advanced operations", func() {
		It("should handle ResourceVersion conflicts", func() {
			// Create namespace
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "resource-version-test-" + time.Now().Format("20060102150405"),
					Labels: map[string]string{
						"initial": "value",
					},
				},
			}

			ns, err := c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Get current version
			currentNs, err := c.Namespaces().Get(ctx, ns.Name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Update with correct version
			currentNs.ObjectMeta.Labels["updated"] = "value"
			updatedNs, err := c.Namespaces().Update(ctx, currentNs, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedNs.ObjectMeta.Labels["updated"]).To(Equal("value"))

			// Try to update with outdated version
			outdatedNs := currentNs.DeepCopy()
			outdatedNs.ObjectMeta.Labels["conflict"] = "value"
			_, err = c.Namespaces().Update(ctx, outdatedNs, options.SetOptions{})
			Expect(err).To(HaveOccurred())
			// Check for various conflict error messages
			Expect(err.Error()).To(Or(
				ContainSubstring("conflict"),
				ContainSubstring("modified"),
				ContainSubstring("version"),
				ContainSubstring("Operation cannot be fulfilled"),
			))
		})

		It("should handle namespace with finalizers", func() {
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "finalizer-test-" + time.Now().Format("20060102150405"),
				},
				Spec: corev1.NamespaceSpec{
					Finalizers: []corev1.FinalizerName{
						"kubernetes",
					},
				},
			}

			ns, err := c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(ns.Spec.Finalizers).To(ContainElement(corev1.FinalizerName("kubernetes")))

			// Remove finalizers
			ns.Spec.Finalizers = []corev1.FinalizerName{}
			updatedNs, err := c.Namespaces().Update(ctx, ns, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			// Note: Kubernetes may not allow removing all finalizers immediately
			// Just verify the update succeeded
			Expect(updatedNs).NotTo(BeNil())
			Expect(updatedNs.Name).To(Equal(ns.Name))
		})

		It("should handle context cancellation", func() {
			cancelledCtx, cancel := context.WithCancel(ctx)
			cancel()

			_, err := c.Namespaces().Get(cancelledCtx, "default", options.GetOptions{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("context canceled"))
		})
	})

	Context("List operations", func() {
		It("should list with field selector", func() {
			nsList, err := c.Namespaces().List(ctx, options.ListOptions{
				Name: "default",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nsList.Items)).To(Equal(1))
			Expect(nsList.Items[0].Name).To(Equal("default"))
		})

		It("should return empty list for non-existent filter", func() {
			nonExistentNS := "non-existent-" + time.Now().Format("20060102150405")
			nsList, err := c.Namespaces().List(ctx, options.ListOptions{
				Name: nonExistentNS,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nsList.Items)).To(Equal(0))
		})
	})
})

// Test non-Kubernetes datastore behavior
var _ = testutils.E2eDatastoreDescribe("Namespace tests (non-Kubernetes datastores)", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	var c clientv3.Interface

	BeforeEach(func() {
		var err error
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should return error for all namespace operations on non-Kubernetes datastore", func() {
		expectedError := "namespace access is only available when using Kubernetes datastore"

		// Test Get
		_, err := c.Namespaces().Get(ctx, "default", options.GetOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal(expectedError))

		// Test List
		_, err = c.Namespaces().List(ctx, options.ListOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal(expectedError))

		// Test Create
		newNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-namespace",
			},
		}
		_, err = c.Namespaces().Create(ctx, newNamespace, options.SetOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal(expectedError))

		// Test Update
		_, err = c.Namespaces().Update(ctx, newNamespace, options.SetOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal(expectedError))

		// Test Delete
		_, err = c.Namespaces().Delete(ctx, "test-namespace", options.DeleteOptions{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal(expectedError))
	})
})
