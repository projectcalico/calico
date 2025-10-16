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
