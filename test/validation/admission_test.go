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
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestNetworkPolicy_TierDefaulting(t *testing.T) {
	if !admissionPoliciesEnabled {
		t.Skip("MutatingAdmissionPolicy not supported on this K8s version")
	}
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
	if !admissionPoliciesEnabled {
		t.Skip("MutatingAdmissionPolicy not supported on this K8s version")
	}
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

// blockSize is the one IP pool default a static CRD default cannot express, since
// IPv4 wants 26 and IPv6 wants 122.
func TestIPPool_BlockSizeDefaulting(t *testing.T) {
	if !admissionPoliciesEnabled {
		t.Skip("MutatingAdmissionPolicy not supported on this K8s version")
	}

	for _, tc := range []struct {
		name string
		cidr string
		want int
	}{
		{name: "IPv4 pool defaults to 26", cidr: nextPoolCIDR(), want: 26},
		{name: "IPv6 pool defaults to 122", cidr: nextPoolCIDRv6(), want: 122},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := uniqueName("ippool-blocksize")
			mustCreate(t, &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       v3.IPPoolSpec{CIDR: tc.cidr},
			})

			got := &v3.IPPool{}
			if err := testClient.Get(context.Background(), client.ObjectKey{Name: name}, got); err != nil {
				t.Fatalf("failed to get pool: %v", err)
			}
			if got.Spec.BlockSize != tc.want {
				t.Fatalf("expected spec.blockSize=%d, got %d", tc.want, got.Spec.BlockSize)
			}
		})
	}

	t.Run("explicit blockSize is preserved", func(t *testing.T) {
		name := uniqueName("ippool-blocksize")
		mustCreate(t, &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       v3.IPPoolSpec{CIDR: nextPoolCIDR(), BlockSize: 24},
		})

		got := &v3.IPPool{}
		if err := testClient.Get(context.Background(), client.ObjectKey{Name: name}, got); err != nil {
			t.Fatalf("failed to get pool: %v", err)
		}
		if got.Spec.BlockSize != 24 {
			t.Fatalf("expected spec.blockSize=24, got %d", got.Spec.BlockSize)
		}
	})

	// The policy runs before schema validation, so a malformed CIDR must fall
	// through to the validator rather than erroring inside CEL.
	t.Run("malformed CIDR is rejected by the schema", func(t *testing.T) {
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "projectcalico.org/v3",
				"kind":       "IPPool",
				"metadata":   map[string]interface{}{"name": uniqueName("ippool-badcidr")},
				"spec":       map[string]interface{}{"cidr": "not-a-cidr"},
			},
		}
		err := testClient.Create(context.Background(), obj)
		if err == nil {
			_ = testClient.Delete(context.Background(), obj)
			t.Fatal("expected creation to fail")
		}
		if !strings.Contains(err.Error(), "cidr") {
			t.Fatalf("expected a cidr validation error, got: %v", err)
		}
	})
}

// blockSize is immutable, so a write that omits it must not be able to clear it.
func TestIPPool_BlockSizeSurvivesUpdateThatOmitsIt(t *testing.T) {
	if !admissionPoliciesEnabled {
		t.Skip("MutatingAdmissionPolicy not supported on this K8s version")
	}

	name := uniqueName("ippool-omit")
	cidr := nextPoolCIDR()
	mustCreate(t, &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.IPPoolSpec{CIDR: cidr},
	})

	created := &v3.IPPool{}
	if err := testClient.Get(context.Background(), client.ObjectKey{Name: name}, created); err != nil {
		t.Fatalf("failed to get pool: %v", err)
	}
	if created.Spec.BlockSize != 26 {
		t.Fatalf("precondition: expected blockSize=26, got %d", created.Spec.BlockSize)
	}

	// Update through an unstructured object with no blockSize, the way a GitOps
	// apply of a manifest that never mentioned it would.
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "projectcalico.org/v3",
			"kind":       "IPPool",
			"metadata": map[string]interface{}{
				"name":            name,
				"resourceVersion": created.ResourceVersion,
			},
			"spec": map[string]interface{}{
				"cidr":        cidr,
				"natOutgoing": true,
			},
		},
	}
	if err := testClient.Update(context.Background(), obj); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	got := &v3.IPPool{}
	if err := testClient.Get(context.Background(), client.ObjectKey{Name: name}, got); err != nil {
		t.Fatalf("failed to get pool after update: %v", err)
	}
	if got.Spec.BlockSize != 26 {
		t.Fatalf("expected blockSize to survive the update as 26, got %d", got.Spec.BlockSize)
	}
}
