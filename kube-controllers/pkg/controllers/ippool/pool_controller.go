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
	"slices"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
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
