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
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// newTestController creates a TierController with a tier informer seeded with the given
// tier and policy informers backed by the given GNP objects. The informers have the tier
// index registered so countPoliciesInTier works.
func newTestController(cli *fake.Clientset, tier *v3.Tier, gnps ...*v3.GlobalNetworkPolicy) *TierController {
	tierStore := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if tier != nil {
		_ = tierStore.Add(tier)
	}

	gnpInformer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{tierIndex: tierKeyFunc})
	for _, gnp := range gnps {
		_ = gnpInformer.Add(gnp)
	}
	npInformer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{tierIndex: tierKeyFunc})
	sgnpInformer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{tierIndex: tierKeyFunc})
	snpInformer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{tierIndex: tierKeyFunc})

	return &TierController{
		ctx:          context.Background(),
		cli:          cli,
		tierInformer: &fakeSharedIndexInformer{indexer: tierStore},
		policyInformers: []cache.SharedIndexInformer{
			&fakeSharedIndexInformer{indexer: gnpInformer},
			&fakeSharedIndexInformer{indexer: npInformer},
			&fakeSharedIndexInformer{indexer: sgnpInformer},
			&fakeSharedIndexInformer{indexer: snpInformer},
		},
	}
}

// fakeSharedIndexInformer wraps a cache.Indexer to satisfy cache.SharedIndexInformer
// for testing. Only GetIndexer and GetStore are implemented.
type fakeSharedIndexInformer struct {
	cache.SharedIndexInformer
	indexer cache.Indexer
}

func (f *fakeSharedIndexInformer) GetIndexer() cache.Indexer {
	return f.indexer
}

func (f *fakeSharedIndexInformer) GetStore() cache.Store {
	return f.indexer
}

func TestReconcile_AddsFinalizer(t *testing.T) {
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tier"},
		Spec:       v3.TierSpec{},
	}
	cli := fake.NewClientset(tier)
	c := newTestController(cli, tier)

	if err := c.reconcile("my-tier"); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

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
	cli := fake.NewClientset(tier)
	c := newTestController(cli, tier)

	if err := c.reconcile("my-tier"); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

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
	cli := fake.NewClientset(tier)
	c := newTestController(cli, tier)

	if err := c.reconcile("my-tier"); err != nil {
		t.Fatalf("reconcile failed: %v", err)
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
	gnp := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tier.policy1"},
		Spec:       v3.GlobalNetworkPolicySpec{Tier: "my-tier"},
	}

	cli := fake.NewClientset(tier, gnp)
	c := newTestController(cli, tier, gnp)

	if err := c.reconcile("my-tier"); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	foundStatusUpdate := false
	for _, action := range cli.Actions() {
		if action.GetVerb() == "update" && action.GetSubresource() == "status" {
			foundStatusUpdate = true
			ua := action.(k8stesting.UpdateAction)
			updated := ua.GetObject().(*v3.Tier)
			if !hasFinalizer(updated) {
				t.Fatal("finalizer should not be removed when policies exist")
			}
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
	cli := fake.NewClientset(tier)
	c := newTestController(cli, tier)

	if err := c.reconcile("my-tier"); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	for _, action := range cli.Actions() {
		if action.GetVerb() == "update" {
			t.Fatal("unexpected update for deleting tier without finalizer")
		}
	}
}

func TestReconcile_TierNotInCache(t *testing.T) {
	cli := fake.NewClientset()
	c := newTestController(cli, nil)

	if err := c.reconcile("nonexistent"); err != nil {
		t.Fatalf("reconcile should not error for missing tier: %v", err)
	}

	for _, action := range cli.Actions() {
		if action.GetVerb() == "update" {
			t.Fatal("unexpected update for nonexistent tier")
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

	if !setCondition(tier, cond) {
		t.Fatal("expected setCondition to return true on first call")
	}
	if len(tier.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(tier.Status.Conditions))
	}

	if setCondition(tier, cond) {
		t.Fatal("expected setCondition to return false when condition unchanged")
	}

	cond.Message = "1 policy remains"
	if !setCondition(tier, cond) {
		t.Fatal("expected setCondition to return true when message changed")
	}
	if tier.Status.Conditions[0].Message != "1 policy remains" {
		t.Fatalf("expected updated message, got %q", tier.Status.Conditions[0].Message)
	}
}

func TestCountPoliciesInTier(t *testing.T) {
	gnp1 := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tier.policy1"},
		Spec:       v3.GlobalNetworkPolicySpec{Tier: "my-tier"},
	}
	gnp2 := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tier.policy2"},
		Spec:       v3.GlobalNetworkPolicySpec{Tier: "my-tier"},
	}
	gnpOther := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "other-tier.policy1"},
		Spec:       v3.GlobalNetworkPolicySpec{Tier: "other-tier"},
	}

	cli := fake.NewClientset()
	c := newTestController(cli, nil, gnp1, gnp2, gnpOther)

	counts, err := c.countPoliciesInTier("my-tier")
	if err != nil {
		t.Fatalf("countPoliciesInTier failed: %v", err)
	}
	if counts.GlobalNetworkPolicies != 2 {
		t.Fatalf("expected 2 GNPs, got %d", counts.GlobalNetworkPolicies)
	}
	if counts.total() != 2 {
		t.Fatalf("expected total 2, got %d", counts.total())
	}

	counts, err = c.countPoliciesInTier("other-tier")
	if err != nil {
		t.Fatalf("countPoliciesInTier failed: %v", err)
	}
	if counts.GlobalNetworkPolicies != 1 {
		t.Fatalf("expected 1 GNP for other-tier, got %d", counts.GlobalNetworkPolicies)
	}

	counts, err = c.countPoliciesInTier("no-such-tier")
	if err != nil {
		t.Fatalf("countPoliciesInTier failed: %v", err)
	}
	if counts.total() != 0 {
		t.Fatalf("expected 0 for non-existent tier, got %d", counts.total())
	}
}

func TestHandleErr_RequeuesOnError(t *testing.T) {
	c := &TierController{
		queue: newFakeQueue(),
	}

	c.handleErr(fmt.Errorf("transient error"), "my-tier")

	fq, ok := c.queue.(*fakeRateLimitingQueue)
	if !ok {
		t.Fatal("unexpected queue type")
	}
	if fq.rateLimitedAdds != 1 {
		t.Fatalf("expected 1 rate-limited requeue, got %d", fq.rateLimitedAdds)
	}
}

func TestHandleErr_ForgetsOnSuccess(t *testing.T) {
	c := &TierController{
		queue: newFakeQueue(),
	}

	c.handleErr(nil, "my-tier")

	fq, ok := c.queue.(*fakeRateLimitingQueue)
	if !ok {
		t.Fatal("unexpected queue type")
	}
	if fq.forgets != 1 {
		t.Fatalf("expected 1 forget, got %d", fq.forgets)
	}
	if fq.rateLimitedAdds != 0 {
		t.Fatalf("expected 0 rate-limited requeues, got %d", fq.rateLimitedAdds)
	}
}

// fakeRateLimitingQueue tracks calls for testing handleErr behavior.
type fakeRateLimitingQueue struct {
	workqueue.TypedRateLimitingInterface[string]
	rateLimitedAdds int
	forgets         int
	requeues        int
}

func newFakeQueue() workqueue.TypedRateLimitingInterface[string] {
	return &fakeRateLimitingQueue{}
}

func (f *fakeRateLimitingQueue) AddRateLimited(item string)  { f.rateLimitedAdds++ }
func (f *fakeRateLimitingQueue) Forget(item string)          { f.forgets++ }
func (f *fakeRateLimitingQueue) NumRequeues(item string) int { return f.requeues }

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
