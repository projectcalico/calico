// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	IPPoolFinalizer = "projectcalico.org/ippool-finalizer"
)

// IPPoolController is responsible for watching IPPool and IPAMBlock resources and managing the finalization / deletion
// of IP pools. when a new IP pool is added, it ensures a finalizer is added to it. When an IP pool is deleted, it ensures that all
// associated IPAM blocks are released before allowing the pool to be fully deleted.
type IPPoolController struct {
	ctx context.Context

	// For syncing node objects from the k8s API.
	poolInformer  cache.SharedIndexInformer
	blockInformer cache.SharedIndexInformer

	cli  clientset.Interface
	ipam ipam.Interface
}

func NewController(
	ctx context.Context,
	cli clientset.Interface,
	poolInformer cache.SharedIndexInformer,
	blockInformer cache.SharedIndexInformer,
	ipam ipam.Interface,
) controller.Controller {
	c := &IPPoolController{
		ctx:           ctx,
		cli:           cli,
		poolInformer:  poolInformer,
		blockInformer: blockInformer,
		ipam:          ipam,
	}

	// Configure events for new IP pools.
	poolHandlers := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj any) {
			logrus.WithField("name", obj.(*v3.IPPool).Name).Info("Handling pool deletion")
			if err := c.Reconcile(obj.(*v3.IPPool)); err != nil {
				logrus.WithError(err).Error("Error handling pool deletion")
			}
		},
		AddFunc: func(obj any) {
			logrus.WithField("name", obj.(*v3.IPPool).Name).Info("Handling pool add")
			if err := c.Reconcile(obj.(*v3.IPPool)); err != nil {
				logrus.WithError(err).Error("Error handling pool add")
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			logrus.WithField("name", newObj.(*v3.IPPool).Name).Info("Handling pool update")
			if err := c.Reconcile(newObj.(*v3.IPPool)); err != nil {
				logrus.WithError(err).Error("Error handling pool update")
			}
		},
	}
	if _, err := poolInformer.AddEventHandler(poolHandlers); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for IPPool")
	}

	// Configure handlers for IPAM block updates. We need to trigger a reconcile for any
	// deleting IP pools when blocks are deleted, to ensure we can finalize the pool.
	blockHandlers := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj any) {
			block := obj.(*v3.IPAMBlock)

			// Find any pools that might be associated with this block and trigger a reconcile.
			for _, i := range poolInformer.GetIndexer().List() {
				pool := i.(*v3.IPPool)
				if pool.DeletionTimestamp == nil {
					// Pool is not being deleted, skip it.
					continue
				}
				_, poolNet, err := cnet.ParseCIDR(pool.Spec.CIDR)
				if err != nil {
					logrus.WithError(err).WithField("cidr", pool.Spec.CIDR).Error("Failed to parse CIDR from IPPool")
					continue
				}
				_, blockNet, err := cnet.ParseCIDR(block.Spec.CIDR)
				if err != nil {
					logrus.WithError(err).WithField("cidr", block.Spec.CIDR).Error("Failed to parse CIDR from IPAMBlock")
					continue
				}
				if poolNet.Contains(blockNet.IP) {
					logrus.WithField("name", pool.Name).Debug("Triggering reconcile for finalizing pool due to block deletion")
					if err := c.Reconcile(pool); err != nil {
						logrus.WithError(err).Error("Error handling pool reconcile due to block deletion")
					}
				}
			}
		},
	}
	if _, err := blockInformer.AddEventHandler(blockHandlers); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for IPAMBlock")
	}

	return c
}

// Run starts the node controller. It does start-of-day preparation
// and then launches worker threads.
func (c *IPPoolController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	logrus.Info("Starting IPPool controller")

	// Wait till k8s cache is synced
	logrus.Debug("Waiting to sync with Kubernetes API")
	if !cache.WaitForNamedCacheSync("pools", stopCh, c.poolInformer.HasSynced, c.blockInformer.HasSynced) {
		logrus.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}

	logrus.Debug("Finished syncing with Kubernetes API")

	<-stopCh
	logrus.Info("Stopping IPPool controller")
}

func (c *IPPoolController) Reconcile(p *v3.IPPool) error {
	ctx := context.TODO()
	logCtx := logrus.WithFields(logrus.Fields{
		"name":         p.Name,
		"cidr":         p.Spec.CIDR,
		"hasFinalizer": hasFinalizer(p),
	})
	logCtx.Debug("Reconciling IPPool")

	// First, check for overlapping IP pools and update their status accordingly.
	if err := c.reconcileConditions(ctx); err != nil {
		logCtx.WithError(err).Warn("Failed to reconcile pool overlaps")
	}

	// Next, ensure that the finalizer is added / removed as needed.
	if err := c.reconcileFinalizer(ctx, logCtx, p); err != nil {
		return fmt.Errorf("failed to reconcile finalizer for IPPool: %w", err)
	}
	return nil
}

// reconcileConditions checks for various conditions that should be set on each IP pool.
func (c *IPPoolController) reconcileConditions(ctx context.Context) error {
	pools := c.poolInformer.GetIndexer().List()
	slices.SortFunc(pools, poolSortFunc)

	// Every time an IP pool is added, updated, or deleted, we need to check if it changes the active set of pools. We only
	// allow a single IP pool covering a given CIDR to be active at a time, and so we need to ensure that:
	// - When a pool is added / updated, if it overlaps with an existing active pool, we should not enable the new pool.
	// - When a pool is deleted, if it was the only active pool covering its CIDR, we should enable another overlapping pool if there is one.
	// Use a trie to find overlapping pools more efficiently. We can insert each pool into the trie, and if we find an existing pool that
	// overlaps with it, we can mark the new pool as disabled.
	trie := ip.NewCIDRTrie()
	triev6 := ip.NewCIDRTrie()
	active := map[string]*v3.IPPool{}
	overlapping := map[string]*v3.IPPool{}
	for _, p := range pools {
		pool := p.(*v3.IPPool)

		cidr, err := ip.CIDRFromString(pool.Spec.CIDR)
		if err != nil {
			logrus.WithError(err).WithField("cidr", pool.Spec.CIDR).Error("Failed to parse CIDR from IPPool")
			continue
		}

		// Use the appropriate trie based on the IP address family of this pool.
		t := trie
		if cidr.Version() == 6 {
			t = triev6
		}

		// If the pool is administratively disabled, reflect that in its conditions and skip it for the purposes of
		// determining overlaps, since an administratively disabled pool should not block other pools from being active.
		if pool.Spec.Disabled {
			cond := metav1.Condition{
				Type:    v3.IPPoolConditionAllocatable,
				Status:  metav1.ConditionFalse,
				Reason:  v3.IPPoolReasonDisabled,
				Message: "IPPool.Spec.Disabled is true",
			}
			if err := updateCondition(ctx, c.cli, pool, cond); err != nil {
				logrus.WithError(err).WithField("pool", pool.Name).Error("Failed to update status of IPPool")
			}
			continue
		}
		if pool.DeletionTimestamp != nil {
			cond := metav1.Condition{
				Type:    v3.IPPoolConditionAllocatable,
				Status:  metav1.ConditionFalse,
				Reason:  v3.IPPoolReasonTerminating,
				Message: "IPPool is being deleted",
			}
			if err := updateCondition(ctx, c.cli, pool, cond); err != nil {
				logrus.WithError(err).WithField("pool", pool.Name).Error("Failed to update status of IPPool")
			}
			// If the pool is being deleted, we still want to consider it for overlaps.
			// This ensures we don't preemptively enable another pool that might overlap with it until this pool
			// is fully deleted.
			t.Update(cidr, pool)
			continue
		}

		// Check if this pool is overlapped by any existing active pool in the trie.
		if e := t.Get(cidr); e != nil || t.Intersects(cidr) || t.Covers(cidr) {
			// This pool overlaps with an existing active pool, so we should disable it.
			logrus.WithField("overlap", pool.Name).Debug("Found overlapping pools")
			overlapping[pool.Name] = pool
		}

		if _, ok := overlapping[pool.Name]; !ok {
			// This pool does not overlap with any existing active pools, so we can add it to the active set and insert it into the trie.
			logrus.WithField("pool", pool.Name).Debug("Found non-overlapping pool, adding to active set")
			active[pool.Name] = pool
			t.Update(cidr, pool)
		}
	}

	// Mark any overlapping pools as disabled.
	for _, pool := range overlapping {
		// Disable any other overlapping pools by setting a condition on them, which will prevent IPAM from allocating from those pools.
		cond := metav1.Condition{
			Type:    v3.IPPoolConditionAllocatable,
			Status:  metav1.ConditionFalse,
			Reason:  v3.IPPoolReasonCIDROverlap,
			Message: "CIDR overlaps another pool; disabled to prevent IP allocation conflicts.",
		}
		if err := updateCondition(ctx, c.cli, pool, cond); err != nil {
			logrus.WithError(err).WithField("pool", pool.Name).Error("Failed to update status of IPPool")
		}
	}

	// Make sure non-overlapping pools are enabled by removing the disabled condition if it exists.
	for _, pool := range active {
		cond := metav1.Condition{
			Type:    v3.IPPoolConditionAllocatable,
			Status:  metav1.ConditionTrue,
			Reason:  v3.IPPoolReasonOK,
			Message: "IPPool is available for IP allocation.",
		}
		if setConditionOnPool(pool, cond) {
			logrus.WithField("pool", pool.Name).Infof("Setting condition %s to %s", cond.Type, cond.Status)
			if _, err := c.cli.ProjectcalicoV3().IPPools().UpdateStatus(ctx, pool, metav1.UpdateOptions{}); err != nil {
				logrus.WithError(err).WithField("otherPool", pool.Name).Error("Failed to update status of IPPool")
			}

			// If this pool was previously disabled, we need to ensure the finalizer is correctly set on it since
			// it would not have had one applied when it was disabled.
			if err := c.reconcileFinalizer(ctx, logrus.WithField("pool", pool.Name), pool); err != nil {
				logrus.WithError(err).WithField("otherPool", pool.Name).Error("Failed to reconcile finalizer for IPPool")
			}
		}
	}

	return nil
}

func poolSortFunc(a, b any) int {
	poolA := a.(*v3.IPPool)
	poolB := b.(*v3.IPPool)

	aCat := poolSortCategory(poolA)
	bCat := poolSortCategory(poolB)
	if aCat != bCat {
		return aCat - bCat
	}

	// Within the same category, sort by creation timestamp (older first).
	if poolA.CreationTimestamp.Before(&poolB.CreationTimestamp) {
		return -1
	}
	if poolB.CreationTimestamp.Before(&poolA.CreationTimestamp) {
		return 1
	}

	// If creation timestamps are equal, sort by name to ensure a deterministic order.
	return strings.Compare(poolA.Name, poolB.Name)
}

// poolSortCategory returns the sort priority for a pool:
//   - 0: Active pools (Allocatable=True, not being deleted) — sorted first so we prefer to keep existing active pools active.
//   - 1: Terminating pools (DeletionTimestamp set) — sorted after active but before disabled pools, so they are
//     inserted into the overlap trie before disabled pools are evaluated. This ensures terminating pools continue
//     to mask overlapping disabled pools until fully deleted.
//   - 2: Disabled pools (Allocatable=False, not being deleted) — sorted after terminating pools.
//   - 3: New pools (no Allocatable condition yet) — sorted last so they don't preempt any existing pools.
func poolSortCategory(p *v3.IPPool) int {
	if hasCondition(p, v3.IPPoolConditionAllocatable, metav1.ConditionTrue) && p.DeletionTimestamp == nil {
		return 0
	}
	if p.DeletionTimestamp != nil {
		return 1
	}
	if hasCondition(p, v3.IPPoolConditionAllocatable, metav1.ConditionFalse) {
		return 2
	}
	return 3
}

// reconcileFinalizer ensures that a finalizer is added to the pool when it is created, and that when the pool is deleted, all associated
// IPAM blocks are released before the finalizer is removed and the pool can be fully deleted.
func (c *IPPoolController) reconcileFinalizer(ctx context.Context, logCtx *logrus.Entry, p *v3.IPPool) error {
	var err error

	if p.DeletionTimestamp != nil {
		logCtx = logCtx.WithField("deletionTimestamp", p.DeletionTimestamp.String())
	}

	if p.DeletionTimestamp == nil {
		if hasCondition(p, v3.IPPoolConditionAllocatable, metav1.ConditionFalse) {
			// If this pool is disabled due to CIDR overlaps or other validation issues, we should not add a finalizer to it
			// since any IPAM blocks within this CIDR belong to the active pool and we don't want to interfere with the deletion of this
			// pool if the user tries to delete it to resolve the overlap.
			if hasFinalizer(p) {
				logCtx.Info("IPPool is not active, removing finalizer")
				p.Finalizers = slices.DeleteFunc(p.Finalizers, func(s string) bool { return s == IPPoolFinalizer })
				if _, err = c.cli.ProjectcalicoV3().IPPools().Update(ctx, p, metav1.UpdateOptions{}); err != nil {
					logCtx.WithError(err).Error("Failed to remove finalizer from IPPool")
					return err
				}
			}
			return nil
		}

		// If the IP pool is not being deleted, add a finalizer to it so we can insert ourselves into the deletion flow.
		if !hasFinalizer(p) {
			logCtx.Info("Adding finalizer to IPPool")
			p.SetFinalizers(append(p.Finalizers, IPPoolFinalizer))
			if _, err = c.cli.ProjectcalicoV3().IPPools().Update(ctx, p, metav1.UpdateOptions{}); err != nil {
				logCtx.WithError(err).Error("Failed to add finalizer to IPPool")
				return err
			}
		}
		return nil
	}

	if !hasFinalizer(p) {
		logCtx.Info("IPPool is being deleted, but no finalizer is present, skipping finalization")
		return nil
	}

	// If the IP pool is being deleted, and we have a finalizer:
	// - Release all affinities for this IP pool in order to prevent new allocations.
	// - Wait until all IPAM blocks within the pool are released before removing the finalizer.
	_, parsedNet, err := cnet.ParseCIDR(p.Spec.CIDR)
	if err != nil {
		return err
	}
	logCtx.Info("IPPool is being deleted, releasing affinities")
	if err = c.ipam.ReleasePoolAffinities(ctx, *parsedNet); err != nil {
		return err
	}

	// If there are no IPAM blocks left in this pool, it is safe to remove our finalizer.
	if c.blocksInPool(*parsedNet) {
		logCtx.Info("IPAM blocks still exist in pool, not removing finalizer")
		return nil
	}

	logCtx.Info("No IPAM blocks left in pool, removing finalizer")
	p.Finalizers = slices.DeleteFunc(p.Finalizers, func(s string) bool { return s == IPPoolFinalizer })
	if _, err := c.cli.ProjectcalicoV3().IPPools().Update(ctx, p, metav1.UpdateOptions{}); err != nil {
		logCtx.WithError(err).Error("Failed to remove finalizer from IPPool")
		return err
	}
	return nil
}

func (c *IPPoolController) blocksInPool(cidr cnet.IPNet) bool {
	// Go through all of the IPAM blocks and check if any of them are in this pool.
	// TODO: We should be able to optimize this by using better data structures instead of iterating through all blocks.
	for _, i := range c.blockInformer.GetIndexer().List() {
		block := i.(*v3.IPAMBlock)
		_, parsedNet, err := cnet.ParseCIDR(block.Spec.CIDR)
		if err != nil {
			logrus.WithError(err).WithField("cidr", block.Spec.CIDR).Error("Failed to parse CIDR from IPAMBlock")
			continue
		}
		if cidr.Contains(parsedNet.IP) {
			logrus.WithField("cidr", cidr.String()).WithField("block", block.Spec.CIDR).Debug("Found IPAMBlock in pool")
			return true
		}
	}
	return false
}

func hasFinalizer(p *v3.IPPool) bool {
	return slices.Contains(p.Finalizers, IPPoolFinalizer)
}

func hasCondition(p *v3.IPPool, conditionType string, status metav1.ConditionStatus) bool {
	if p.Status == nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == conditionType && c.Status == status {
			return true
		}
	}
	return false
}

// updateCondition updates the given condition on the IP pool if it has changed, and updates the status of the pool if needed.
func updateCondition(ctx context.Context, cli clientset.Interface, p *v3.IPPool, condition metav1.Condition) error {
	if setConditionOnPool(p, condition) {
		logrus.WithField("pool", p.Name).Infof("Updating condition %s to %s", condition.Type, condition.Status)
		if _, err := cli.ProjectcalicoV3().IPPools().UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
			logrus.WithError(err).WithField("pool", p.Name).Error("Failed to update status of IPPool")
			return err
		}
	}
	return nil
}

// setConditionOnPool sets the given condition on the IP pool, replacing any existing condition of the same type.
// Returns true if the condition was changed and needs to be updated in the API, or false if the condition was already in the desired state.
func setConditionOnPool(p *v3.IPPool, condition metav1.Condition) bool {
	if p.Status == nil {
		// If there is no status, we need to create one and add the condition to it.
		condition.LastTransitionTime = metav1.Now()
		p.Status = &v3.IPPoolStatus{
			Conditions: []metav1.Condition{condition},
		}
		return true
	}

	conditions := p.Status.Conditions
	for i, c := range conditions {
		if c.Type == condition.Type {
			if c.Status == condition.Status && c.Reason == condition.Reason && c.Message == condition.Message {
				// No change, return false.
				return false
			}

			// Update existing condition.
			condition.LastTransitionTime = metav1.Now()
			p.Status.Conditions[i] = condition
			return true
		}
	}

	// Condition not found, add it.
	condition.LastTransitionTime = metav1.Now()
	p.Status.Conditions = append(p.Status.Conditions, condition)
	return true
}
