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

package ippool

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func TestPoolSortFunc(t *testing.T) {
	now := time.Unix(0, 0)

	makePool := func(name string, createdAt time.Time, condition *metav1.Condition, deleting bool) *v3.IPPool {
		p := &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				CreationTimestamp: metav1.NewTime(createdAt),
			},
		}
		if deleting {
			ts := metav1.NewTime(now)
			p.DeletionTimestamp = &ts
		}
		if condition != nil {
			p.Status = &v3.IPPoolStatus{
				Conditions: []metav1.Condition{*condition},
			}
		}
		return p
	}

	allocatable := &metav1.Condition{
		Type:   v3.IPPoolConditionAllocatable,
		Status: metav1.ConditionTrue,
		Reason: v3.IPPoolReasonOK,
	}
	disabled := &metav1.Condition{
		Type:   v3.IPPoolConditionAllocatable,
		Status: metav1.ConditionFalse,
		Reason: v3.IPPoolReasonCIDROverlap,
	}

	tests := []struct {
		name     string
		pools    []*v3.IPPool
		expected []string // expected order of pool names after sorting
	}{
		{
			name: "active pools sort before disabled pools",
			pools: []*v3.IPPool{
				makePool("disabled-pool", now.Add(-1*time.Minute), disabled, false),
				makePool("active-pool", now, allocatable, false),
			},
			expected: []string{"active-pool", "disabled-pool"},
		},
		{
			name: "active pools sort before terminating pools",
			pools: []*v3.IPPool{
				makePool("terminating-pool", now.Add(-1*time.Minute), allocatable, true),
				makePool("active-pool", now, allocatable, false),
			},
			expected: []string{"active-pool", "terminating-pool"},
		},
		{
			name: "terminating pools sort before disabled pools",
			pools: []*v3.IPPool{
				makePool("disabled-pool", now.Add(-2*time.Minute), disabled, false),
				makePool("terminating-pool", now.Add(-1*time.Minute), allocatable, true),
			},
			expected: []string{"terminating-pool", "disabled-pool"},
		},
		{
			name: "terminating pool with Allocatable=False still sorts before disabled pools",
			pools: []*v3.IPPool{
				makePool("disabled-pool", now.Add(-2*time.Minute), disabled, false),
				makePool("terminating-pool", now.Add(-1*time.Minute), disabled, true),
			},
			expected: []string{"terminating-pool", "disabled-pool"},
		},
		{
			name: "within same category, older pools sort first",
			pools: []*v3.IPPool{
				makePool("newer-pool", now, allocatable, false),
				makePool("older-pool", now.Add(-1*time.Minute), allocatable, false),
			},
			expected: []string{"older-pool", "newer-pool"},
		},
		{
			name: "same category and timestamp sorts by name",
			pools: []*v3.IPPool{
				makePool("pool-b", now, allocatable, false),
				makePool("pool-a", now, allocatable, false),
			},
			expected: []string{"pool-a", "pool-b"},
		},
		{
			name: "new pools with no condition sort after active pools",
			pools: []*v3.IPPool{
				makePool("new-pool", now.Add(-1*time.Minute), nil, false),
				makePool("active-pool", now, allocatable, false),
			},
			expected: []string{"active-pool", "new-pool"},
		},
		{
			name: "new pools with no condition sort after terminating pools",
			pools: []*v3.IPPool{
				makePool("new-pool", now.Add(-1*time.Minute), nil, false),
				makePool("terminating-pool", now, allocatable, true),
			},
			expected: []string{"terminating-pool", "new-pool"},
		},
		{
			name: "new pools with no condition sort after disabled pools",
			pools: []*v3.IPPool{
				makePool("new-pool", now.Add(-1*time.Minute), nil, false),
				makePool("disabled-pool", now, disabled, false),
			},
			expected: []string{"disabled-pool", "new-pool"},
		},
		{
			name: "full scenario: active, terminating, disabled, and new pools",
			pools: []*v3.IPPool{
				makePool("disabled-2", now.Add(-1*time.Minute), disabled, false),
				makePool("active-pool", now.Add(-5*time.Minute), allocatable, false),
				makePool("new-pool", now, nil, false),
				makePool("disabled-1", now.Add(-2*time.Minute), disabled, false),
				makePool("terminating-pool", now.Add(-3*time.Minute), allocatable, true),
			},
			expected: []string{"active-pool", "terminating-pool", "disabled-1", "disabled-2", "new-pool"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slices.SortFunc(tt.pools, func(a, b *v3.IPPool) int {
				return poolSortFunc(a, b)
			})

			got := make([]string, len(tt.pools))
			for i, p := range tt.pools {
				got[i] = p.Name
			}

			if len(got) != len(tt.expected) {
				t.Fatalf("expected %v, got %v", tt.expected, got)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Fatalf("expected %v, got %v", tt.expected, got)
				}
			}
		})
	}
}

// fakeSharedIndexInformer wraps a cache.Indexer to satisfy cache.SharedIndexInformer for testing.
// Only GetIndexer and GetStore are implemented.
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

// fakeIPAM stubs out the IPAM calls the finalizer path makes for a deleting pool.
type fakeIPAM struct {
	ipam.Interface
}

func (f *fakeIPAM) ReleasePoolAffinities(ctx context.Context, pool cnet.IPNet) error {
	return nil
}

// fakeRateLimitingQueue tracks calls for testing handleErr behavior.
type fakeRateLimitingQueue struct {
	workqueue.TypedRateLimitingInterface[string]
	rateLimitedAdds int
	forgets         int
	requeues        int
}

func (f *fakeRateLimitingQueue) AddRateLimited(item string)  { f.rateLimitedAdds++ }
func (f *fakeRateLimitingQueue) Forget(item string)          { f.forgets++ }
func (f *fakeRateLimitingQueue) NumRequeues(item string) int { return f.requeues }

// newTestController builds a controller whose pool informer is seeded with the given pools and
// whose block informer is empty. The returned indexer is the same one the controller reads, so
// tests can assert on whether the controller mutated the objects it was handed.
func newTestController(cli *fake.Clientset, pools ...*v3.IPPool) (*IPPoolController, cache.Indexer) {
	poolIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, p := range pools {
		if err := poolIndexer.Add(p); err != nil {
			panic(err)
		}
	}
	blockIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

	c := &IPPoolController{
		ctx:           context.Background(),
		cli:           cli,
		poolInformer:  &fakeSharedIndexInformer{indexer: poolIndexer},
		blockInformer: &fakeSharedIndexInformer{indexer: blockIndexer},
		ipam:          &fakeIPAM{},
		queue:         &fakeRateLimitingQueue{},
	}
	return c, poolIndexer
}

func testPool(name, cidr string) *v3.IPPool {
	return &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.IPPoolSpec{CIDR: cidr},
	}
}

// failOn makes every write matching verb/subresource fail with a conflict, and counts attempts.
func failOn(cli *fake.Clientset, verb, subresource string, count *int) {
	cli.PrependReactor(verb, "ippools", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != subresource {
			return false, nil, nil
		}
		*count++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "projectcalico.org", Resource: "ippools"}, "conflict", fmt.Errorf("stale object"))
	})
}

// logEntry returns a throwaway log context for functions that require one.
func logEntry() *logrus.Entry {
	return logrus.WithField("test", true)
}

// hasConflict reports whether err, which may be a nested aggregate of wrapped errors, contains a conflict.
func hasConflict(err error) bool {
	agg, ok := err.(utilerrors.Aggregate)
	if !ok {
		return apierrors.IsConflict(err)
	}
	for _, e := range utilerrors.Flatten(agg).Errors() {
		if apierrors.IsConflict(e) {
			return true
		}
	}
	return false
}

func cachedPool(t *testing.T, idx cache.Indexer, name string) *v3.IPPool {
	t.Helper()
	obj, exists, err := idx.GetByKey(name)
	if err != nil || !exists {
		t.Fatalf("pool %q not in cache (exists=%v, err=%v)", name, exists, err)
	}
	return obj.(*v3.IPPool)
}

// TestReconcileConditions_FailedStatusUpdateDoesNotPoisonCache is the regression test for
// CORE-13258. A rejected UpdateStatus used to leave the informer-cached pool asserting the
// condition, after which the idempotency check in setConditionOnPool suppressed every retry.
func TestReconcileConditions_FailedStatusUpdateDoesNotPoisonCache(t *testing.T) {
	pool := testPool("pool-1", "192.168.0.0/24")
	cli := fake.NewClientset(pool)
	attempts := 0
	failOn(cli, "update", "status", &attempts)

	c, idx := newTestController(cli, pool)

	if _, err := c.reconcileConditions(c.ctx); err == nil {
		t.Fatal("expected reconcileConditions to surface the failed status write")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 UpdateStatus attempt, got %d", attempts)
	}

	// The cached object must not claim a condition the API server rejected.
	if cp := cachedPool(t, idx, "pool-1"); cp.Status != nil && len(cp.Status.Conditions) > 0 {
		t.Fatalf("informer cache was mutated by a failed write: %+v", cp.Status.Conditions)
	}

	// And the next pass must retry rather than short-circuit on the poisoned cache.
	if _, err := c.reconcileConditions(c.ctx); err == nil {
		t.Fatal("expected second reconcileConditions to surface the failed status write")
	}
	if attempts != 2 {
		t.Fatalf("expected the second pass to retry the write, got %d total attempts", attempts)
	}
}

// TestReconcileConditions_RecoversOnceWriteSucceeds confirms the retry actually lands the
// condition once the transient failure clears.
func TestReconcileConditions_RecoversOnceWriteSucceeds(t *testing.T) {
	pool := testPool("pool-1", "192.168.0.0/24")
	cli := fake.NewClientset(pool)
	fail := true
	attempts := 0
	cli.PrependReactor("update", "ippools", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "status" {
			return false, nil, nil
		}
		attempts++
		if fail {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "ippools"}, "pool-1", nil)
		}
		return false, nil, nil
	})

	c, _ := newTestController(cli, pool)

	if _, err := c.reconcileConditions(c.ctx); err == nil {
		t.Fatal("expected first pass to fail")
	}

	fail = false
	if _, err := c.reconcileConditions(c.ctx); err != nil {
		t.Fatalf("expected second pass to succeed, got %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}

	updated, err := cli.ProjectcalicoV3().IPPools().Get(context.Background(), "pool-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pool: %v", err)
	}
	if !hasCondition(updated, v3.IPPoolConditionAllocatable, metav1.ConditionTrue) {
		t.Fatalf("expected Allocatable=True to be persisted, got %+v", updated.Status)
	}
}

// TestReconcileFinalizer_FailedUpdateDoesNotPoisonCache covers the same mutate-before-write
// pattern on the finalizer path.
func TestReconcileFinalizer_FailedUpdateDoesNotPoisonCache(t *testing.T) {
	pool := testPool("pool-1", "192.168.0.0/24")
	cli := fake.NewClientset(pool)
	attempts := 0
	failOn(cli, "update", "", &attempts)

	c, idx := newTestController(cli, pool)

	if err := c.reconcileFinalizer(c.ctx, logEntry(), pool); err == nil {
		t.Fatal("expected reconcileFinalizer to return the failed write")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 Update attempt, got %d", attempts)
	}
	if cp := cachedPool(t, idx, "pool-1"); hasFinalizer(cp) {
		t.Fatal("informer cache gained a finalizer from a failed write")
	}

	// A pool that never got its finalizer written must be retried, not skipped.
	if err := c.reconcileFinalizer(c.ctx, logEntry(), pool); err == nil {
		t.Fatal("expected second reconcileFinalizer to return the failed write")
	}
	if attempts != 2 {
		t.Fatalf("expected the second pass to retry, got %d total attempts", attempts)
	}
}

// TestReconcileFinalizer_RemovalFailureDoesNotPoisonCache covers the removal branch, which
// deletes from the finalizer slice rather than appending to it.
func TestReconcileFinalizer_RemovalFailureDoesNotPoisonCache(t *testing.T) {
	pool := testPool("pool-1", "192.168.0.0/24")
	pool.Finalizers = []string{IPPoolFinalizer}
	pool.Status = &v3.IPPoolStatus{
		Conditions: []metav1.Condition{{
			Type:   v3.IPPoolConditionAllocatable,
			Status: metav1.ConditionFalse,
			Reason: v3.IPPoolReasonCIDROverlap,
		}},
	}
	cli := fake.NewClientset(pool)
	attempts := 0
	failOn(cli, "update", "", &attempts)

	c, idx := newTestController(cli, pool)

	if err := c.reconcileFinalizer(c.ctx, logEntry(), pool); err == nil {
		t.Fatal("expected reconcileFinalizer to return the failed write")
	}
	if cp := cachedPool(t, idx, "pool-1"); !hasFinalizer(cp) {
		t.Fatal("informer cache lost its finalizer to a failed write")
	}
	if err := c.reconcileFinalizer(c.ctx, logEntry(), pool); err == nil {
		t.Fatal("expected second reconcileFinalizer to return the failed write")
	}
	if attempts != 2 {
		t.Fatalf("expected the second pass to retry, got %d total attempts", attempts)
	}
}

// TestReconcile_ConflictRequeues checks the whole loop: a conflicting write must come back
// through the workqueue rather than being logged and dropped.
func TestReconcile_ConflictRequeues(t *testing.T) {
	pool := testPool("pool-1", "192.168.0.0/24")
	cli := fake.NewClientset(pool)
	attempts := 0
	failOn(cli, "update", "status", &attempts)

	c, _ := newTestController(cli, pool)

	err := c.reconcile()
	if err == nil {
		t.Fatal("expected reconcile to return the conflict")
	}
	if !hasConflict(err) {
		t.Fatalf("expected a conflict error, got %v", err)
	}

	c.handleErr(err, reconcileKey)
	fq := c.queue.(*fakeRateLimitingQueue)
	if fq.rateLimitedAdds != 1 {
		t.Fatalf("expected 1 rate-limited requeue, got %d", fq.rateLimitedAdds)
	}
	if fq.forgets != 0 {
		t.Fatalf("expected the key to be kept, got %d forgets", fq.forgets)
	}
}

func TestHandleErr_ForgetsOnSuccess(t *testing.T) {
	c, _ := newTestController(fake.NewClientset())

	c.handleErr(nil, reconcileKey)

	fq := c.queue.(*fakeRateLimitingQueue)
	if fq.forgets != 1 {
		t.Fatalf("expected 1 forget, got %d", fq.forgets)
	}
	if fq.rateLimitedAdds != 0 {
		t.Fatalf("expected 0 requeues, got %d", fq.rateLimitedAdds)
	}
}

func TestHandleErr_DropsAfterMaxRetries(t *testing.T) {
	c, _ := newTestController(fake.NewClientset())
	fq := c.queue.(*fakeRateLimitingQueue)
	fq.requeues = maxRetries

	c.handleErr(fmt.Errorf("persistent error"), reconcileKey)

	if fq.rateLimitedAdds != 0 {
		t.Fatalf("expected no requeue past maxRetries, got %d", fq.rateLimitedAdds)
	}
	if fq.forgets != 1 {
		t.Fatalf("expected the key to be forgotten, got %d forgets", fq.forgets)
	}
}

// TestReconcile_HappyPath is a sanity check that the restructured reconcile still writes both
// the condition and the finalizer for a single healthy pool.
func TestReconcile_HappyPath(t *testing.T) {
	pool := testPool("pool-1", "192.168.0.0/24")
	cli := fake.NewClientset(pool)
	c, idx := newTestController(cli, pool)

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	updated, err := cli.ProjectcalicoV3().IPPools().Get(context.Background(), "pool-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pool: %v", err)
	}
	if !hasCondition(updated, v3.IPPoolConditionAllocatable, metav1.ConditionTrue) {
		t.Fatalf("expected Allocatable=True, got %+v", updated.Status)
	}
	if !hasFinalizer(updated) {
		t.Fatal("expected finalizer to be added")
	}

	// Even on the happy path the controller must not have written through to the shared cache.
	if cp := cachedPool(t, idx, "pool-1"); hasFinalizer(cp) || cp.Status != nil {
		t.Fatalf("controller mutated the informer cache: finalizers=%v status=%+v", cp.Finalizers, cp.Status)
	}
}

// TestReconcile_FinalizerWriteUsesStatusResourceVersion checks that the finalizer write uses
// the resourceVersion the status write returned.
func TestReconcile_FinalizerWriteUsesStatusResourceVersion(t *testing.T) {
	pool := testPool("pool-1", "192.168.0.0/24")
	pool.ResourceVersion = "1"
	cli := fake.NewClientset(pool)

	var finalizerRV string
	cli.PrependReactor("update", "ippools", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj := a.(k8stesting.UpdateAction).GetObject().(*v3.IPPool)
		if a.GetSubresource() == "status" {
			accepted := obj.DeepCopy()
			accepted.ResourceVersion = "2"
			return true, accepted, nil
		}
		finalizerRV = obj.ResourceVersion
		return true, obj, nil
	})

	c, _ := newTestController(cli, pool)

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if finalizerRV != "2" {
		t.Fatalf("expected finalizer write to use resourceVersion 2, got %q", finalizerRV)
	}
}
