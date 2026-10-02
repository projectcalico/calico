// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package conncheck

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAvoidNodes(t *testing.T) {
	excluded := corev1.NodeSelectorRequirement{
		Key:      "metadata.name",
		Operator: corev1.NodeSelectorOpNotIn,
		Values:   []string{"cp-1", "cp-2"},
	}

	t.Run("no affinity", func(t *testing.T) {
		pod := &corev1.Pod{}
		avoidNodes([]string{"cp-1", "cp-2"})(pod)
		terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) != 1 || len(terms[0].MatchFields) != 1 || terms[0].MatchFields[0].Operator != excluded.Operator ||
			terms[0].MatchFields[0].Key != excluded.Key || len(terms[0].MatchFields[0].Values) != 2 {
			t.Fatalf("want one term excluding the nodes, got %+v", terms)
		}
	})

	t.Run("existing terms", func(t *testing.T) {
		zone := corev1.NodeSelectorRequirement{Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"}}
		arch := corev1.NodeSelectorRequirement{Key: "arch", Operator: corev1.NodeSelectorOpIn, Values: []string{"amd64"}}
		pod := &corev1.Pod{Spec: corev1.PodSpec{Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{MatchExpressions: []corev1.NodeSelectorRequirement{zone}},
				{MatchExpressions: []corev1.NodeSelectorRequirement{arch}},
			}},
		}}}}
		avoidNodes([]string{"cp-1", "cp-2"})(pod)
		terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) != 2 {
			t.Fatalf("want the two existing terms, got %d", len(terms))
		}
		for i, term := range terms {
			if len(term.MatchExpressions) != 1 || len(term.MatchFields) != 1 || term.MatchFields[0].Key != excluded.Key {
				t.Fatalf("term %d: want its expression kept and the nodes excluded, got %+v", i, term)
			}
		}
	})

	t.Run("no nodes", func(t *testing.T) {
		pod := &corev1.Pod{}
		avoidNodes(nil)(pod)
		if pod.Spec.Affinity != nil {
			t.Fatalf("want the pod unchanged, got %+v", pod.Spec.Affinity)
		}
	})
}
