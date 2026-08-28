// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

func getK8sNodes(x int) *corev1.NodeList {
	nodes := &corev1.NodeList{
		Items: []corev1.Node{},
	}
	for i := 0; i < x; i++ {
		nodes.Items = append(nodes.Items, corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("node%d", i),
			},
		})
	}
	return nodes
}

var _ = Describe("Convert typha check tests", func() {
	ctx := context.Background()
	var scheme *runtime.Scheme
	var pool *v3.IPPool
	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())
		pool = v3.NewIPPool()
		pool.Spec = v3.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    v3.IPIPModeAlways,
			NATOutgoing: true,
		}
	})

	Describe("handle when previous typha exists", func() {
		It("should not return an error with 2 nodes and 1 typha", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(1)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td).WithLists(getK8sNodes(2)).Build()
			_, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
		})
		It("should not return an error with 3 nodes and 1 typha", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(1)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td).WithLists(getK8sNodes(3)).Build()
			_, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
		})
	})
	Describe("handle enough nodes with previous Typha", func() {
		It("should succeed with 5 nodes and 1 typha ", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(1)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td).WithLists(getK8sNodes(5)).Build()
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
		It("should succeed with 8 nodes and 4 typha ", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(4)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td).WithLists(getK8sNodes(8)).Build()
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
	})
	Describe("handle no previous Typha", func() {
		It("should not error with 0 replicas", func() {
			td := emptyTyphaDeployment()
			td.Spec.Replicas = int32Ptr(0)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td).WithLists(getK8sNodes(2)).Build()
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
		It("should not error with no replicas", func() {
			td := emptyTyphaDeployment()

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig(), td).WithLists(getK8sNodes(2)).Build()
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
		It("should not error with no typha deployment", func() {
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), pool, emptyFelixConfig()).WithLists(getK8sNodes(2)).Build()
			_, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
		})
	})
	Context("typha prometheus metrics", func() {
		var (
			comps = emptyComponents()
			i     = &operatorv1.Installation{}
		)

		BeforeEach(func() {
			comps = emptyComponents()
			i = &operatorv1.Installation{}
		})
		It("with metrics enabled the default port is used", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "TYPHA_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}}
			Expect(handleTyphaMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(*i.Spec.TyphaMetricsPort).To(Equal(int32(9091)))
		})
		It("defaults prometheus off when no prometheus environment variables set", func() {
			Expect(handleFelixNodeMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.TyphaMetricsPort).To(BeNil())
		})
		It("with metrics port env var only, metrics are still disabled", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "TYPHA_PROMETHEUSMETRICSPORT",
				Value: "5555",
			}}

			Expect(handleTyphaMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(i.Spec.TyphaMetricsPort).To(BeNil())
		})
		It("with metrics port and enabled is reflected in installation", func() {
			comps.typha.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "TYPHA_PROMETHEUSMETRICSENABLED",
				Value: "true",
			}, {
				Name:  "TYPHA_PROMETHEUSMETRICSPORT",
				Value: "7777",
			}}

			Expect(handleTyphaMetrics(&comps, i)).ToNot(HaveOccurred())
			Expect(*i.Spec.TyphaMetricsPort).To(Equal(int32(7777)))
		})
	})
})
