// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package conncheck

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/kubernetes/test/e2e/framework"
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

	t.Run("empty term", func(t *testing.T) {
		zone := corev1.NodeSelectorRequirement{Key: "zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"a"}}
		pod := &corev1.Pod{Spec: corev1.PodSpec{Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{MatchExpressions: []corev1.NodeSelectorRequirement{zone}},
				{},
			}},
		}}}}
		avoidNodes([]string{"cp-1", "cp-2"})(pod)
		terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) != 2 {
			t.Fatalf("want the two existing terms, got %d", len(terms))
		}
		if len(terms[0].MatchFields) != 1 || terms[0].MatchFields[0].Key != excluded.Key {
			t.Fatalf("want the zone term to exclude the nodes, got %+v", terms[0])
		}
		if len(terms[1].MatchExpressions) != 0 || len(terms[1].MatchFields) != 0 {
			t.Fatalf("want the empty term left empty so it still matches no node, got %+v", terms[1])
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

func testNode(name, ip string, ready, unschedulable bool) *corev1.Node {
	status := corev1.ConditionTrue
	if !ready {
		status = corev1.ConditionFalse
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: ip},
				{Type: corev1.NodeHostName, Address: name},
			},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}},
		},
	}
}

func apiServerEndpoints(ips ...string) *corev1.Endpoints {
	var addrs []corev1.EndpointAddress
	for _, ip := range ips {
		addrs = append(addrs, corev1.EndpointAddress{IP: ip})
	}
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"},
		Subsets:    []corev1.EndpointSubset{{Addresses: addrs}},
	}
}

func excludedNodes(pod *corev1.Pod) []string {
	if pod.Spec.Affinity == nil {
		return nil
	}
	return pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0].Values
}

func TestWithAvoidControlPlane(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nodes []*corev1.Node
		api   []string
		want  []string
	}{
		{
			name:  "ready worker",
			nodes: []*corev1.Node{testNode("cp-1", "10.0.0.1", true, false), testNode("w-1", "10.0.0.2", true, false)},
			api:   []string{"10.0.0.1"},
			want:  []string{"cp-1"},
		},
		{
			name:  "cordoned worker",
			nodes: []*corev1.Node{testNode("cp-1", "10.0.0.1", true, false), testNode("w-1", "10.0.0.2", true, true)},
			api:   []string{"10.0.0.1"},
		},
		{
			name:  "not ready worker",
			nodes: []*corev1.Node{testNode("cp-1", "10.0.0.1", true, false), testNode("w-1", "10.0.0.2", false, false)},
			api:   []string{"10.0.0.1"},
		},
		{
			name:  "control plane outside the node list",
			nodes: []*corev1.Node{testNode("w-1", "10.0.0.2", true, false), testNode("w-2", "10.0.0.3", true, false)},
			api:   []string{"192.168.0.1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(apiServerEndpoints(tc.api...))
			for _, n := range tc.nodes {
				if _, err := cs.CoreV1().Nodes().Create(t.Context(), n, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			pod := &corev1.Pod{}
			WithAvoidControlPlane(&framework.Framework{ClientSet: cs})(pod)
			got := excludedNodes(pod)
			if len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) {
				t.Fatalf("want excluded nodes %v, got %v", tc.want, got)
			}
		})
	}
}
