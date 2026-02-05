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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

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

func poolActive(p *v3.IPPool) bool {
	if p.DeletionTimestamp != nil {
		return false
	}
	if p.Status != nil {
		for _, cond := range p.Status.Conditions {
			if cond.Type == "Disabled" && cond.Status == metav1.ConditionTrue {
				return false
			}
		}
	}
	return true
}

func poolsOverlap(p1, p2 *v3.IPPool) (bool, error) {
	_, net1, err := cnet.ParseCIDR(p1.Spec.CIDR)
	if err != nil {
		return false, fmt.Errorf("failed to parse CIDR from IPPool %s: %w", p1.Name, err)
	}
	_, net2, err := cnet.ParseCIDR(p2.Spec.CIDR)
	if err != nil {
		return false, fmt.Errorf("failed to parse CIDR from IPPool %s: %w", p2.Name, err)
	}
	return net1.IsNetOverlap(net2.IPNet), nil
}

func (c *IPPoolController) Reconcile(p *v3.IPPool) error {
	ctx := context.TODO()
	logCtx := logrus.WithFields(logrus.Fields{
		"name":         p.Name,
		"cidr":         p.Spec.CIDR,
		"hasFinalizer": HasFinalizer(p),
	})
	logCtx.Debug("Reconciling IPPool")

	if p.DeletionTimestamp != nil {
		logCtx = logCtx.WithField("deletionTimestamp", p.DeletionTimestamp.String())
	}
	var err error

	// Every time an IP pool is added, updated, or deleted, we need to check if it changes the active set of pools. We only
	// allow a single IP pool covering a given CIDR to be active at a time, and so we need to ensure that:
	// - When a pool is added / updated, if it overlaps with an existing active pool, we should not enable the new pool.
	// - When a pool is deleted, if it was the only active pool covering its CIDR, we should enable another overlapping pool if there is one.

	// Build a mapping of base IP to pools that cover that base IP.
	pools := map[string][]*v3.IPPool{}
	for _, i := range c.poolInformer.GetIndexer().List() {
		_, net, err := cnet.ParseCIDR(i.(*v3.IPPool).Spec.CIDR)
		if err != nil {
			logCtx.WithError(err).WithField("cidr", i.(*v3.IPPool).Spec.CIDR).Error("Failed to parse CIDR from IPPool")
			continue
		}
		baseIP := net.IP.String()
		if _, ok := pools[baseIP]; !ok {
			pools[baseIP] = []*v3.IPPool{}
		}
		pools[baseIP] = append(pools[baseIP], i.(*v3.IPPool))
	}

	// Sort each list of pools so that we have a consistent order when checking for overlaps.
	// We sort by creation timestamp, then by name to ensure a consistent order.
	for baseIP := range pools {
		slices.SortFunc(pools[baseIP], func(a, b *v3.IPPool) int {
			if a.CreationTimestamp.Equal(&b.CreationTimestamp) {
				return strings.Compare(a.Name, b.Name)
			}
			if a.CreationTimestamp.Before(&b.CreationTimestamp) {
				return -1
			}
			return 1
		})
	}

	// Check for overlapping pools. Any entry with more than one pool in it indicates an overlap. If there is
	// an overlap, we enable the first active pool in the list and disable all others.
	for _, overlappingPools := range pools {
		if len(overlappingPools) > 1 {
			// There is overlap - ensure only the first active pool is enabled.
			for i, pool := range overlappingPools {
				if i == 0 {
					// Enable the first (i.e., the oldest) pool.
					pool.Status = &v3.IPPoolStatus{
						Conditions: []metav1.Condition{},
					}
				} else {
					// Disable all other pools.
					pool.Status = &v3.IPPoolStatus{
						Conditions: []metav1.Condition{{
							Type:   "Disabled",
							Status: metav1.ConditionTrue,
							Reason: "OverlappingPool",
							Message: fmt.Sprintf(
								"CIDR overlaps %s; disabled to prevent IP address allocation conflicts.",
								overlappingPools[0].Name,
							),
							LastTransitionTime: metav1.Now(),
						}},
					}
				}
				if _, err = c.cli.ProjectcalicoV3().IPPools().UpdateStatus(ctx, pool, v1.UpdateOptions{}); err != nil {
					logCtx.WithError(err).WithField("otherPool", pool.Name).Error("Failed to update status of IPPool")
					return err
				}
			}
			continue
		}

		// Only a single pool covers this base IP - ensure it is enabled.
		pool := overlappingPools[0]
		pool.Status = &v3.IPPoolStatus{
			Conditions: []metav1.Condition{},
		}
		if _, err = c.cli.ProjectcalicoV3().IPPools().UpdateStatus(ctx, pool, v1.UpdateOptions{}); err != nil {
			logCtx.WithError(err).Error("Failed to update status of IPPool")
		}
	}

	if p.DeletionTimestamp == nil {
		// If the IP pool is not being deleted, add a finalizer to it so we can insert ourselves into the deletion flow.
		if !HasFinalizer(p) {
			logCtx.Info("Adding finalizer to IPPool")
			p.SetFinalizers(append(p.Finalizers, IPPoolFinalizer))
			if _, err = c.cli.ProjectcalicoV3().IPPools().Update(ctx, p, v1.UpdateOptions{}); err != nil {
				logCtx.WithError(err).Error("Failed to add finalizer to IPPool")
				return err
			}
		}
		return nil
	}

	if !HasFinalizer(p) {
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
	if _, err := c.cli.ProjectcalicoV3().IPPools().Update(ctx, p, v1.UpdateOptions{}); err != nil {
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

func HasFinalizer(p *v3.IPPool) bool {
	return slices.Contains(p.Finalizers, IPPoolFinalizer)
}
