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

package utils

import (
	"context"
	"errors"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/libcalico-go/lib/nodestatus"
)

func taintedNode(taints ...v1.Taint) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec:       v1.NodeSpec{Taints: taints},
	}
}

func TestRemoveNetworkReadyTaint(t *testing.T) {
	networkNotReady := v1.Taint{Key: nodestatus.NetworkReadyTaintKey, Effect: v1.TaintEffectNoSchedule}
	unrelated := v1.Taint{Key: "example.com/other", Effect: v1.TaintEffectNoSchedule}

	tests := []struct {
		name     string
		existing []v1.Taint
		expected []v1.Taint
	}{
		{
			name:     "removes the taint",
			existing: []v1.Taint{networkNotReady},
			expected: []v1.Taint{},
		},
		{
			name:     "leaves unrelated taints in place",
			existing: []v1.Taint{unrelated, networkNotReady},
			expected: []v1.Taint{unrelated},
		},
		{
			name:     "does nothing when the taint is absent",
			existing: []v1.Taint{unrelated},
			expected: []v1.Taint{unrelated},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(taintedNode(tc.existing...))
			if err := RemoveNetworkReadyTaint(context.Background(), client, "node-a", time.Second); err != nil {
				t.Fatalf("RemoveNetworkReadyTaint: %v", err)
			}

			node, err := client.CoreV1().Nodes().Get(context.Background(), "node-a", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get node: %v", err)
			}
			if len(node.Spec.Taints) != len(tc.expected) {
				t.Fatalf("taints = %v, want %v", node.Spec.Taints, tc.expected)
			}
			for i, want := range tc.expected {
				if node.Spec.Taints[i].Key != want.Key {
					t.Errorf("taint %d = %q, want %q", i, node.Spec.Taints[i].Key, want.Key)
				}
			}
		})
	}
}

// The taint removal has to survive the apiserver being slow or unreachable while the node comes
// up, since giving up would leave the node unschedulable.
func TestRemoveNetworkReadyTaintRetries(t *testing.T) {
	client := fake.NewSimpleClientset(taintedNode(v1.Taint{
		Key:    nodestatus.NetworkReadyTaintKey,
		Effect: v1.TaintEffectNoSchedule,
	}))

	failures := 2
	client.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failures > 0 {
			failures--
			return true, nil, errors.New("apiserver is unreachable")
		}
		return false, nil, nil
	})

	if err := RemoveNetworkReadyTaint(context.Background(), client, "node-a", 10*time.Second); err != nil {
		t.Fatalf("RemoveNetworkReadyTaint: %v", err)
	}
	if failures != 0 {
		t.Fatalf("expected the failing reactor to be exhausted, %d left", failures)
	}

	node, err := client.CoreV1().Nodes().Get(context.Background(), "node-a", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if nodestatus.HasNetworkReadyTaint(node) {
		t.Error("taint was not removed after the retries")
	}
}

func TestRemoveNetworkReadyTaintTimesOut(t *testing.T) {
	client := fake.NewSimpleClientset()
	err := RemoveNetworkReadyTaint(context.Background(), client, "missing-node", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error for a node that does not exist")
	}
}

func TestSetNodeNetworkUnavailableCondition(t *testing.T) {
	client := fake.NewSimpleClientset(taintedNode())

	err := SetNodeNetworkUnavailableCondition(
		context.Background(),
		client,
		"node-a",
		false,
		nodestatus.NetworkReadyReason,
		nodestatus.NetworkReadyMessage,
		time.Second,
	)
	if err != nil {
		t.Fatalf("SetNodeNetworkUnavailableCondition: %v", err)
	}

	node, err := client.CoreV1().Nodes().Get(context.Background(), "node-a", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if nodestatus.NetworkUnavailable(node) != v1.ConditionFalse {
		t.Errorf("NetworkUnavailable = %v, want False", nodestatus.NetworkUnavailable(node))
	}
	if !nodestatus.OwnsNetworkUnavailable(node) {
		t.Error("the condition should be attributed to Calico")
	}
}
