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

package tier

import (
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stesting "k8s.io/client-go/testing"
)

func TestReconcile_AddsFinalizer(t *testing.T) {
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tier"},
		Spec:       v3.TierSpec{},
	}
	cli := fake.NewSimpleClientset(tier)
	c := &TierController{ctx: context.Background(), cli: cli}

	if err := c.Reconcile(tier); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify that an Update was issued to add the finalizer.
	updated := getUpdatedTier(t, cli, "my-tier")
	if !hasFinalizer(updated) {
		t.Fatal("expected finalizer to be added")
	}
}

func TestReconcile_SkipsFinalizerIfAlreadyPresent(t *testing.T) {
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "my-tier",
			Finalizers: []string{v3.TierFinalizer},
		},
		Spec: v3.TierSpec{},
	}
	cli := fake.NewSimpleClientset(tier)
	c := &TierController{ctx: context.Background(), cli: cli}

	if err := c.Reconcile(tier); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// No update should have been issued since the finalizer is already present.
	for _, action := range cli.Actions() {
		if action.GetVerb() == "update" && action.GetResource().Resource == "tiers" {
			t.Fatal("unexpected update action when finalizer already present")
		}
	}
}

func TestReconcile_RemovesFinalizerWhenNoPolicies(t *testing.T) {
	now := metav1.Now()
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-tier",
			Finalizers:        []string{v3.TierFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v3.TierSpec{},
	}

	// Empty policy lists — no policies reference this tier.
	cli := fake.NewSimpleClientset(tier)
	c := &TierController{ctx: context.Background(), cli: cli}

	if err := c.Reconcile(tier); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	updated := getUpdatedTier(t, cli, "my-tier")
	if hasFinalizer(updated) {
		t.Fatal("expected finalizer to be removed when no policies exist")
	}
}

func TestReconcile_KeepsFinalizerWhenPoliciesExist(t *testing.T) {
	now := metav1.Now()
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-tier",
			Finalizers:        []string{v3.TierFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: v3.TierSpec{},
	}

	// Create a GNP that references this tier.
	gnp := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tier.policy1"},
		Spec:       v3.GlobalNetworkPolicySpec{Tier: "my-tier"},
	}

	cli := fake.NewSimpleClientset(tier, gnp)
	c := &TierController{ctx: context.Background(), cli: cli}

	if err := c.Reconcile(tier); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// The finalizer should still be present because there are policies in the tier.
	// Verify that an UpdateStatus was issued (for the terminating condition), not a
	// regular Update to remove the finalizer.
	foundStatusUpdate := false
	for _, action := range cli.Actions() {
		if action.GetVerb() == "update" && action.GetSubresource() == "status" {
			foundStatusUpdate = true
			ua := action.(k8stesting.UpdateAction)
			updated := ua.GetObject().(*v3.Tier)
			if !hasFinalizer(updated) {
				t.Fatal("finalizer should not be removed when policies exist")
			}
			// Check the condition.
			found := false
			for _, c := range updated.Status.Conditions {
				if c.Type == "Ready" && c.Status == metav1.ConditionFalse && c.Reason == "Terminating" {
					found = true
				}
			}
			if !found {
				t.Fatal("expected Ready=False/Terminating condition on tier status")
			}
		}
	}
	if !foundStatusUpdate {
		t.Fatal("expected a status update when policies still exist")
	}
}

func TestReconcile_DeletingTierWithoutFinalizer(t *testing.T) {
	now := metav1.Now()
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-tier",
			DeletionTimestamp: &now,
		},
		Spec: v3.TierSpec{},
	}
	cli := fake.NewSimpleClientset(tier)
	c := &TierController{ctx: context.Background(), cli: cli}

	if err := c.Reconcile(tier); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// No updates should be issued — just skip.
	for _, action := range cli.Actions() {
		if action.GetVerb() == "update" {
			t.Fatal("unexpected update for deleting tier without finalizer")
		}
	}
}

func TestPolicyCounts_Summary(t *testing.T) {
	tests := []struct {
		name     string
		counts   policyCounts
		expected string
	}{
		{
			name:     "single GNP",
			counts:   policyCounts{GlobalNetworkPolicies: 1},
			expected: "1 GlobalNetworkPolicy",
		},
		{
			name:     "multiple GNPs",
			counts:   policyCounts{GlobalNetworkPolicies: 3},
			expected: "3 GlobalNetworkPolicies",
		},
		{
			name:     "mixed types",
			counts:   policyCounts{GlobalNetworkPolicies: 2, NetworkPolicies: 1, StagedNetworkPolicies: 5},
			expected: "2 GlobalNetworkPolicies, 1 NetworkPolicy, 5 StagedNetworkPolicies",
		},
		{
			name:     "all types",
			counts:   policyCounts{GlobalNetworkPolicies: 1, NetworkPolicies: 1, StagedGlobalNetworkPolicies: 1, StagedNetworkPolicies: 1},
			expected: "1 GlobalNetworkPolicy, 1 NetworkPolicy, 1 StagedGlobalNetworkPolicy, 1 StagedNetworkPolicy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.counts.summary(); got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestSetCondition(t *testing.T) {
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
	}

	cond := metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionFalse,
		Reason:  "Terminating",
		Message: "2 policies remain",
	}

	// First call should return true (condition added).
	if !setCondition(tier, cond) {
		t.Fatal("expected setCondition to return true on first call")
	}
	if len(tier.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(tier.Status.Conditions))
	}

	// Same condition again should return false (no change).
	if setCondition(tier, cond) {
		t.Fatal("expected setCondition to return false when condition unchanged")
	}

	// Different message should return true (condition updated).
	cond.Message = "1 policy remains"
	if !setCondition(tier, cond) {
		t.Fatal("expected setCondition to return true when message changed")
	}
	if tier.Status.Conditions[0].Message != "1 policy remains" {
		t.Fatalf("expected updated message, got %q", tier.Status.Conditions[0].Message)
	}
}

// getUpdatedTier finds the tier from Update actions in the fake client.
func getUpdatedTier(t *testing.T, cli *fake.Clientset, name string) *v3.Tier {
	t.Helper()
	for _, action := range cli.Actions() {
		if action.GetVerb() == "update" && action.GetResource().Resource == "tiers" && action.GetSubresource() == "" {
			ua := action.(k8stesting.UpdateAction)
			obj := ua.GetObject()
			tier, ok := obj.(*v3.Tier)
			if ok && tier.Name == name {
				return tier
			}
		}
	}

	// Also check creates, in case the fake registered it differently.
	t.Fatalf("no Update action found for tier %q; actions: %s", name, actionSummary(cli.Actions()))
	return nil
}

func actionSummary(actions []k8stesting.Action) string {
	var s string
	for _, a := range actions {
		s += a.GetVerb() + " " + a.GetResource().Resource
		if a.GetSubresource() != "" {
			s += "/" + a.GetSubresource()
		}
		s += ", "
	}
	if s == "" {
		return "(none)"
	}
	return s
}
