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
	if err := c.reconcilePoolOverlaps(ctx); err != nil {
		logCtx.WithError(err).Warn("Failed to reconcile pool overlaps")
	}

	// Next, ensure that the finalizer is added / removed as needed.
	if err := c.reconcileFinalizer(ctx, logCtx, p); err != nil {
		return fmt.Errorf("failed to reconcile finalizer for IPPool: %w", err)
	}
	return nil
}

// reconcilePoolOverlaps checks for overlapping pools and ensures that any overlapping IP pools are not both active at the same time.
//
// Every time an IP pool is added, updated, or deleted, we need to check if it changes the active set of pools. We only
// allow a single IP pool covering a given CIDR to be active at a time, and so we need to ensure that:
// - When a pool is added / updated, if it overlaps with an existing active pool, we should not enable the new pool.
// - When a pool is deleted, if it was the only active pool covering its CIDR, we should enable another overlapping pool if there is one.
func (c *IPPoolController) reconcilePoolOverlaps(ctx context.Context) error {
	// Use a trie to find overlapping pools more efficiently. We can insert each pool into the trie, and if we find an existing pool that
	// overlaps with it, we can mark the new pool as disabled.
	trie := ip.NewCIDRTrie()
	pools := c.poolInformer.GetIndexer().List()
	slices.SortFunc(pools, poolSortFunc)

	active := map[string]*v3.IPPool{}
	disabled := map[string]*v3.IPPool{}

	for _, p := range pools {
		pool := p.(*v3.IPPool)

		c, err := ip.CIDRFromString(pool.Spec.CIDR)
		if err != nil {
			logrus.WithError(err).WithField("cidr", pool.Spec.CIDR).Error("Failed to parse CIDR from IPPool")
			continue
		}

		// Check if this pool is overlapped by any existing active pool in the trie.
		if trie.Intersects(c) {
			// This pool overlaps with an existing active pool, so we should disable it.
			logrus.WithField("overlap", pool.Name).Debug("Found overlapping pools")
			disabled[pool.Name] = pool
		}

		if _, ok := disabled[pool.Name]; !ok {
			// This pool does not overlap with any existing active pools, so we can add it to the active set and insert it into the trie.
			logrus.WithField("pool", pool.Name).Debug("Found non-overlapping pool, adding to active set")
			active[pool.Name] = pool
			trie.Update(c, pool)
		}
	}

	// Mark any overlapping pools as disabled.
	for _, pool := range disabled {
		// Disable any other overlapping pools by setting a condition on them, which will prevent IPAM from allocating from those pools.
		cond := metav1.Condition{
			Type:    v3.IPPoolConditionDisabled,
			Status:  metav1.ConditionTrue,
			Reason:  "OverlappingPool",
			Message: "CIDR overlaps another pool; disabled to prevent IP allocation conflicts.",
		}
		if setCondition(pool, cond) {
			logrus.WithField("otherPool", pool.Name).Info("Disabling IPPool due to overlap")
			if _, err := c.cli.ProjectcalicoV3().IPPools().UpdateStatus(ctx, pool, metav1.UpdateOptions{}); err != nil {
				logrus.WithError(err).WithField("otherPool", pool.Name).Error("Failed to update status of IPPool")
			}
		}
	}

	// Make sure non-overlapping pools are enabled by removing the disabled condition if it exists.
	for _, pool := range active {
		if removeCondition(pool, v3.IPPoolConditionDisabled) {
			logrus.WithField("pool", pool.Name).Info("Enabling IPPool")
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

	// Disabled pools should be sorted after active pools, so that we prefer to keep
	// existing active pools active when there are overlaps.
	aDisabled := hasCondition(poolA, v3.IPPoolConditionDisabled)
	bDisabled := hasCondition(poolB, v3.IPPoolConditionDisabled)
	if aDisabled && !bDisabled {
		return 1
	}
	if !aDisabled && bDisabled {
		return -1
	}

	// If both pools are in the same state (both active or both disabled), sort by creation timestamp,
	// sorting older pools first.
	if poolA.CreationTimestamp.Before(&poolB.CreationTimestamp) {
		return -1
	}
	if poolB.CreationTimestamp.Before(&poolA.CreationTimestamp) {
		return 1
	}

	// If creation timestamps are equal, sort by name to ensure a deterministic order.
	return strings.Compare(poolA.Name, poolB.Name)
}

// reconcileFinalizer ensures that a finalizer is added to the pool when it is created, and that when the pool is deleted, all associated
// IPAM blocks are released before the finalizer is removed and the pool can be fully deleted.
func (c *IPPoolController) reconcileFinalizer(ctx context.Context, logCtx *logrus.Entry, p *v3.IPPool) error {
	var err error

	if p.DeletionTimestamp != nil {
		logCtx = logCtx.WithField("deletionTimestamp", p.DeletionTimestamp.String())
	}

	if p.DeletionTimestamp == nil {
		if hasCondition(p, v3.IPPoolConditionDisabled) {
			// If this pool is disabled due to CIDR overlaps or other validation issues, we should not add a finalizer to it
			// since any IPAM blocks within this CIDR belong to the active pool and we don't want to interfere with the deletion of this
			// pool if the user tries to delete it to resolve the overlap.
			if hasFinalizer(p) {
				logCtx.Info("IPPool is not active, removing finalizer")
				p.Finalizers = slices.Delete(p.Finalizers, slices.Index(p.Finalizers, IPPoolFinalizer), slices.Index(p.Finalizers, IPPoolFinalizer)+1)
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
	p.Finalizers = slices.Delete(p.Finalizers, slices.Index(p.Finalizers, IPPoolFinalizer), slices.Index(p.Finalizers, IPPoolFinalizer)+1)
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

func hasCondition(p *v3.IPPool, conditionType string) bool {
	if p.Status == nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == conditionType {
			return true
		}
	}
	return false
}

// setCondition sets the given condition on the IP pool, replacing any existing condition of the same type.
// Returns true if the condition was added or updated, false if no change was made.
func setCondition(p *v3.IPPool, condition metav1.Condition) bool {
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

func removeCondition(p *v3.IPPool, conditionType string) bool {
	if p.Status == nil {
		return false
	}
	conditions := p.Status.Conditions
	for i, c := range conditions {
		if c.Type == conditionType {
			p.Status.Conditions = slices.Delete(conditions, i, i+1)
			return true
		}
	}
	return false
}
