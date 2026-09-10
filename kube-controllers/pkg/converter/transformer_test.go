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
	calicoNodePod := func() *v1.Pod {
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
				OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "calico-node"}},
			},
			Spec: v1.PodSpec{
				NodeName:           "nodeA",
				ServiceAccountName: "calico-node",
				Containers:         []v1.Container{{Name: "calico-node"}},
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

	workloadPod := func() *v1.Pod {
		pod := calicoNodePod()
		pod.Name = "nginx-abc"
		pod.Labels = map[string]string{"app": "nginx"}
		pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "nginx"}}
		pod.Spec.Containers = []v1.Container{{Name: "nginx"}}
		return pod
	}

	transform := func(podControllerEnabled bool, pod *v1.Pod) *v1.Pod {
		GinkgoHelper()
		out, err := converter.PodTransformer(podControllerEnabled)(pod)
		Expect(err).NotTo(HaveOccurred())
		transformed, ok := out.(*v1.Pod)
		Expect(ok).To(BeTrue())
		return transformed
	}

	Describe("identifying calico-node pods", func() {
		It("matches on the container name, so Canal's k8s-app label doesn't matter", func() {
			pod := calicoNodePod()
			pod.Labels["k8s-app"] = "canal"
			Expect(converter.IsCalicoNodePod(pod)).To(BeTrue())
		})

		It("does not match a pod that is not owned by a DaemonSet", func() {
			pod := calicoNodePod()
			pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "impostor"}}
			Expect(converter.IsCalicoNodePod(pod)).To(BeFalse())
		})

		It("does not match a DaemonSet pod with no calico-node container", func() {
			Expect(converter.IsCalicoNodePod(workloadPod())).To(BeFalse())
		})

		It("still matches after the pod has been through the transformer", func() {
			for _, enabled := range []bool{true, false} {
				Expect(converter.IsCalicoNodePod(transform(enabled, calicoNodePod()))).To(BeTrue())
			}
		})
	})

	Describe("slimming the cached pod", func() {
		It("keeps only the PodReady condition for a calico-node pod", func() {
			out := transform(false, calicoNodePod())
			Expect(out.Status.Conditions).To(ConsistOf(v1.PodCondition{Type: v1.PodReady, Status: v1.ConditionTrue}))
		})

		It("caches no conditions or containers for an ordinary workload pod", func() {
			// Every pod in the cluster passes through here, so the extra fields are worth
			// keeping only on the pods the node condition controller actually reads.
			out := transform(false, workloadPod())
			Expect(out.Status.Conditions).To(BeEmpty())
			Expect(out.Spec.Containers).To(BeEmpty())
			Expect(out.OwnerReferences).To(BeEmpty())
		})

		When("the pod controller is enabled", func() {
			It("keeps the full label set and service account name for policy matching", func() {
				out := transform(true, workloadPod())
				Expect(out.Labels).To(Equal(map[string]string{"app": "nginx"}))
				Expect(out.Spec.ServiceAccountName).To(Equal("calico-node"))
			})
		})

		When("the pod controller is disabled", func() {
			It("drops the labels and the service account name", func() {
				out := transform(false, calicoNodePod())
				Expect(out.Labels).To(BeEmpty())
				Expect(out.Spec.ServiceAccountName).To(BeEmpty())
			})
		})
	})
})
