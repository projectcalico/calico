// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
)

var _ = Describe("PodTransformer", func() {
	newPod := func() *v1.Pod {
		return &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-node-xyz",
				Namespace: "calico-system",
				Labels: map[string]string{
					"k8s-app":                        "calico-node",
					"pod-template-generation":        "7",
					"controller-revision-hash":       "abc123",
					"projectcalico.org/orchestrator": "k8s",
				},
			},
			Spec: v1.PodSpec{
				NodeName:           "nodeA",
				ServiceAccountName: "calico-node",
			},
			Status: v1.PodStatus{
				PodIP: "10.0.0.1",
				Phase: v1.PodRunning,
				Conditions: []v1.PodCondition{
					{Type: v1.PodInitialized, Status: v1.ConditionTrue},
					{Type: v1.PodScheduled, Status: v1.ConditionTrue},
					{Type: v1.PodReady, Status: v1.ConditionTrue},
					{Type: v1.ContainersReady, Status: v1.ConditionTrue},
				},
			},
		}
	}

	transform := func(podControllerEnabled bool, pod *v1.Pod) *v1.Pod {
		out, err := converter.PodTransformer(podControllerEnabled)(pod)
		Expect(err).NotTo(HaveOccurred())
		transformed, ok := out.(*v1.Pod)
		Expect(ok).To(BeTrue())
		return transformed
	}

	It("retains only the PodReady condition regardless of pod controller state", func() {
		for _, enabled := range []bool{true, false} {
			out := transform(enabled, newPod())
			Expect(out.Status.Conditions).To(ConsistOf(v1.PodCondition{Type: v1.PodReady, Status: v1.ConditionTrue}))
		}
	})

	When("the pod controller is enabled", func() {
		It("keeps the full label set and service account name for policy matching", func() {
			out := transform(true, newPod())
			Expect(out.Labels).To(HaveLen(4))
			Expect(out.Spec.ServiceAccountName).To(Equal("calico-node"))
		})
	})

	When("the pod controller is disabled", func() {
		It("keeps only the k8s-app label and drops the service account name", func() {
			out := transform(false, newPod())
			Expect(out.Labels).To(Equal(map[string]string{"k8s-app": "calico-node"}))
			Expect(out.Spec.ServiceAccountName).To(BeEmpty())
		})

		It("sets no labels on a pod without the k8s-app label", func() {
			pod := newPod()
			delete(pod.Labels, "k8s-app")
			out := transform(false, pod)
			Expect(out.Labels).To(BeNil())
		})
	})
})
