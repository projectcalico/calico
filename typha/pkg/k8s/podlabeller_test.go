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

package k8s_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/typha/pkg/k8s"
)

func newPod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{"k8s-app": "calico-typha"},
		},
	}
}

func getPodLabel(t *testing.T, cs *fake.Clientset, ns, name, key string) (string, bool) {
	t.Helper()
	pod, err := cs.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}
	v, ok := pod.Labels[key]
	return v, ok
}

// TestPodLabeller_SetAndRemove verifies the leader label is applied and then
// removed, without disturbing other labels.
func TestPodLabeller_SetAndRemove(t *testing.T) {
	cs := fake.NewClientset(newPod("kube-system", "typha-a"))
	l := k8s.NewPodLabeller(cs, "kube-system", "typha-a")

	if err := l.SetLeaderLabel(context.Background()); err != nil {
		t.Fatalf("SetLeaderLabel: %v", err)
	}
	if v, ok := getPodLabel(t, cs, "kube-system", "typha-a", k8s.TyphaRoleLabel); !ok || v != k8s.TyphaRoleLeader {
		t.Fatalf("expected leader label, got %q (present=%v)", v, ok)
	}
	// Other labels untouched.
	if v, ok := getPodLabel(t, cs, "kube-system", "typha-a", "k8s-app"); !ok || v != "calico-typha" {
		t.Fatalf("k8s-app label disturbed: %q (present=%v)", v, ok)
	}

	if err := l.RemoveLeaderLabel(context.Background()); err != nil {
		t.Fatalf("RemoveLeaderLabel: %v", err)
	}
	if _, ok := getPodLabel(t, cs, "kube-system", "typha-a", k8s.TyphaRoleLabel); ok {
		t.Fatal("expected leader label to be removed")
	}
	if v, ok := getPodLabel(t, cs, "kube-system", "typha-a", "k8s-app"); !ok || v != "calico-typha" {
		t.Fatalf("k8s-app label disturbed after remove: %q (present=%v)", v, ok)
	}
}

// TestPodLabeller_SetIdempotent verifies that setting the label twice is a
// no-op the second time (no error).
func TestPodLabeller_SetIdempotent(t *testing.T) {
	cs := fake.NewClientset(newPod("ns1", "typha-b"))
	l := k8s.NewPodLabeller(cs, "ns1", "typha-b")

	for i := 0; i < 2; i++ {
		if err := l.SetLeaderLabel(context.Background()); err != nil {
			t.Fatalf("SetLeaderLabel iteration %d: %v", i, err)
		}
	}
	if v, _ := getPodLabel(t, cs, "ns1", "typha-b", k8s.TyphaRoleLabel); v != k8s.TyphaRoleLeader {
		t.Fatalf("expected leader label after double set, got %q", v)
	}
}

// TestPodLabeller_RemoveWhenAbsent verifies removing an absent label is a no-op.
func TestPodLabeller_RemoveWhenAbsent(t *testing.T) {
	cs := fake.NewClientset(newPod("ns1", "typha-c"))
	l := k8s.NewPodLabeller(cs, "ns1", "typha-c")
	if err := l.RemoveLeaderLabel(context.Background()); err != nil {
		t.Fatalf("RemoveLeaderLabel on absent label: %v", err)
	}
}

// TestPodLabeller_MissingPodErrors verifies a patch against a non-existent pod
// returns an error (so the role manager can log it).
func TestPodLabeller_MissingPodErrors(t *testing.T) {
	cs := fake.NewClientset()
	l := k8s.NewPodLabeller(cs, "ns1", "ghost")
	if err := l.SetLeaderLabel(context.Background()); err == nil {
		t.Fatal("expected error patching non-existent pod")
	}
}
