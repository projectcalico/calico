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

package validation_test

import (
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestNetworkPolicy_TierDefaulting(t *testing.T) {
	ns := "default"

	t.Run("omitted tier is defaulted", func(t *testing.T) {
		name := uniqueName("np-tier")
		np := &v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec:       v3.NetworkPolicySpec{Selector: "all()"},
		}
		mustCreate(t, np)

		got := &v3.NetworkPolicy{}
		if err := testClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: ns}, got); err != nil {
			t.Fatalf("failed to get policy: %v", err)
		}
		if got.Spec.Tier != "default" {
			t.Fatalf("expected spec.tier=%q, got %q", "default", got.Spec.Tier)
		}
	})

	// Use an unstructured object to send tier: "" in the JSON payload.
	// The typed Go client would omit the field entirely due to omitempty,
	// which would test the CRD schema default rather than the MAP.
	t.Run("empty string tier is defaulted by MAP", func(t *testing.T) {
		name := uniqueName("np-tier")
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "projectcalico.org/v3",
				"kind":       "NetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      name,
					"namespace": ns,
				},
				"spec": map[string]interface{}{
					"tier":     "",
					"selector": "all()",
				},
			},
		}
		if err := testClient.Create(context.Background(), obj); err != nil {
			t.Fatalf("failed to create policy: %v", err)
		}
		t.Cleanup(func() {
			_ = testClient.Delete(context.Background(), obj)
		})

		got := &v3.NetworkPolicy{}
		if err := testClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: ns}, got); err != nil {
			t.Fatalf("failed to get policy: %v", err)
		}
		if got.Spec.Tier != "default" {
			t.Fatalf("expected spec.tier=%q, got %q", "default", got.Spec.Tier)
		}
	})

	t.Run("explicit tier is preserved", func(t *testing.T) {
		name := uniqueName("np-tier")
		np := &v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec:       v3.NetworkPolicySpec{Tier: "default", Selector: "all()"},
		}
		mustCreate(t, np)

		got := &v3.NetworkPolicy{}
		if err := testClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: ns}, got); err != nil {
			t.Fatalf("failed to get policy: %v", err)
		}
		if got.Spec.Tier != "default" {
			t.Fatalf("expected spec.tier=%q, got %q", "default", got.Spec.Tier)
		}
	})
}

func TestNetworkPolicy_TierLabel(t *testing.T) {
	ns := "default"
	name := uniqueName("np-label")
	np := &v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       v3.NetworkPolicySpec{Selector: "all()"},
	}
	mustCreate(t, np)

	got := &v3.NetworkPolicy{}
	if err := testClient.Get(context.Background(), client.ObjectKey{Name: name, Namespace: ns}, got); err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	tierLabel := got.Labels["projectcalico.org/tier"]
	if tierLabel != "default" {
		t.Fatalf("expected projectcalico.org/tier label=%q, got %q", "default", tierLabel)
	}
}
