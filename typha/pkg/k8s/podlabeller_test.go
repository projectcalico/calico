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
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
)

func newPod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			// Pod template ships every Typha at tier-2.
			Labels: map[string]string{"k8s-app": "calico-typha", k8s.TyphaTierLabel: k8s.TyphaTier2},
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

// TestPodLabeller_TierTransitions verifies the tier label is patched to each
// value as the role changes, without disturbing other labels.
func TestPodLabeller_TierTransitions(t *testing.T) {
	cs := fake.NewClientset(newPod("kube-system", "typha-a"))
	l := k8s.NewPodLabeller(cs, "kube-system", "typha-a")

	cases := []struct {
		role rolemanager.Role
		want string
	}{
		{rolemanager.Leader, k8s.TyphaTierLeader},
		{rolemanager.Tier1, k8s.TyphaTier1},
		{rolemanager.Tier2, k8s.TyphaTier2},
	}
	for _, c := range cases {
		if err := l.SetTierLabel(context.Background(), c.role); err != nil {
			t.Fatalf("SetTierLabel(%v): %v", c.role, err)
		}
		if v, ok := getPodLabel(t, cs, "kube-system", "typha-a", k8s.TyphaTierLabel); !ok || v != c.want {
			t.Fatalf("role %v: expected tier label %q, got %q (present=%v)", c.role, c.want, v, ok)
		}
		// Other labels untouched.
		if v, ok := getPodLabel(t, cs, "kube-system", "typha-a", "k8s-app"); !ok || v != "calico-typha" {
			t.Fatalf("k8s-app label disturbed by role %v: %q (present=%v)", c.role, v, ok)
		}
	}
}

// TestPodLabeller_SetIdempotent verifies that setting the same tier twice is a
// no-op the second time (no error).
func TestPodLabeller_SetIdempotent(t *testing.T) {
	cs := fake.NewClientset(newPod("ns1", "typha-b"))
	l := k8s.NewPodLabeller(cs, "ns1", "typha-b")

	for i := 0; i < 2; i++ {
		if err := l.SetTierLabel(context.Background(), rolemanager.Leader); err != nil {
			t.Fatalf("SetTierLabel iteration %d: %v", i, err)
		}
	}
	if v, _ := getPodLabel(t, cs, "ns1", "typha-b", k8s.TyphaTierLabel); v != k8s.TyphaTierLeader {
		t.Fatalf("expected leader tier after double set, got %q", v)
	}
}

// TestTierLabelValue verifies the role→label mapping, including the Sourceless
// fallback to the safe leaf value.
func TestTierLabelValue(t *testing.T) {
	cases := map[rolemanager.Role]string{
		rolemanager.Leader:     k8s.TyphaTierLeader,
		rolemanager.Tier1:      k8s.TyphaTier1,
		rolemanager.Tier2:      k8s.TyphaTier2,
		rolemanager.Sourceless: k8s.TyphaTier2,
	}
	for role, want := range cases {
		if got := k8s.TierLabelValue(role); got != want {
			t.Errorf("TierLabelValue(%v)=%q, want %q", role, got, want)
		}
	}
}

// TestPodLabeller_MissingPodErrors verifies a patch against a non-existent pod
// returns an error (so the role manager can log it).
func TestPodLabeller_MissingPodErrors(t *testing.T) {
	cs := fake.NewClientset()
	l := k8s.NewPodLabeller(cs, "ns1", "ghost")
	if err := l.SetTierLabel(context.Background(), rolemanager.Leader); err == nil {
		t.Fatal("expected error patching non-existent pod")
	}
}
