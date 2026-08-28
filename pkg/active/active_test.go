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

package active

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("test active pkg", func() {
	var (
		c      client.Client
		ctx    context.Context
		scheme *runtime.Scheme
	)

	BeforeEach(func() {
		// Create a Kubernetes client.
		scheme = runtime.NewScheme()
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(corev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(apps.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
	})

	Context("GetActiveConfigMap", func() {
		It("should not error with no ConfigMap", func() {
			cm, err := GetActiveConfigMap(c)
			Expect(err).To(BeNil())
			Expect(cm).To(BeNil())
		})

		It("should retrieve ConfigMap", func() {
			dataMap := map[string]string{"test-key": "test-data"}
			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ActiveConfigMapName,
					Namespace: common.CalicoNamespace,
				},
				Data: dataMap,
			})).ShouldNot(HaveOccurred())
			cm, err := GetActiveConfigMap(c)
			Expect(err).To(BeNil())
			Expect(cm).ToNot(BeNil())
			Expect(cm.Data).To(Equal(dataMap))
		})
	})
	Context("IsThisOperatorActive", func() {
		It("should be active if map is nil", func() {
			active, ns := IsThisOperatorActive(nil)
			Expect(active).To(BeTrue())
			Expect(ns).To(Equal("tigera-operator"))
		})
		It("should be active if map specifies matching namespace", func() {
			operatorNamespace = func() string { return "active-test-namespace" }
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ActiveConfigMapName,
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{"active-namespace": "active-test-namespace"},
			}
			active, ns := IsThisOperatorActive(cm)
			Expect(active).To(BeTrue())
			Expect(ns).To(Equal("active-test-namespace"))
		})
		It("should not be active if map doesn't match namespace", func() {
			operatorNamespace = func() string { return "inactive-test-namespace" }
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ActiveConfigMapName,
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{"active-namespace": "active-test-namespace"},
			}
			active, ns := IsThisOperatorActive(cm)
			Expect(active).To(BeFalse())
			Expect(ns).To(Equal("active-test-namespace"))
		})
		It("should not be active if map doesn't contain namespace", func() {
			operatorNamespace = func() string { return "inactive-test-namespace" }
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ActiveConfigMapName,
					Namespace: common.CalicoNamespace,
				},
				Data: map[string]string{"incorrect-key": "active-test-namespace"},
			}
			active, ns := IsThisOperatorActive(cm)
			Expect(active).To(BeFalse())
			Expect(ns).To(Equal(""))
		})
	})
})
