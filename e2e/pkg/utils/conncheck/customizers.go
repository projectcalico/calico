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

package conncheck

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CombineCustomizers is a meta customizer that applies multiple Pod customizers
// to the Pod spec.
func CombineCustomizers(customizers ...func(*corev1.Pod)) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		for _, customizer := range customizers {
			customizer(pod)
		}
	}
}

func UseV4IPPool(poolName string) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		pod.Annotations["cni.projectcalico.org/ipv4pools"] = fmt.Sprintf(`["%s"]`, poolName)
	}
}

// WithNodeName returns a Pod customizer that pins a pod to a specific node.
func WithNodeName(name string) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		pod.Spec.NodeName = name
	}
}

// AvoidEachOther is a Pod customizer that adds PodAntiAffinity rules to avoid
// scheduling the Pod on the same node as other Pods deployed with this customizer.
func AvoidEachOther(pod *corev1.Pod) {
	// Include a label which we can use in the anti-affinity rule.
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels["e2e.projectcalico.org/anti-affinity"] = "true"

	// Add the PodAntiAffinity rule to make sure Pods are scheduled on different nodes.
	pod.Spec.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "e2e.projectcalico.org/anti-affinity",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"true"},
							},
						},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		},
	}
}
