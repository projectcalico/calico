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
	"slices"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// maxRetries is the number of times a tier key will be retried before being dropped.
const maxRetries = 5

// tierIndex is the name of the cache index used to look up policies by tier name.
const tierIndex = "byTier"

// tierKeyFunc extracts the tier name from a policy object for use as a cache index key.
func tierKeyFunc(obj any) ([]string, error) {
	name := tierNameFromPolicy(obj)
	if name == "" {
		return nil, nil
	}
	return []string{name}, nil
}

// TierController watches Tier resources and manages their finalizers for cascading deletion.
// When a tier is created, it adds a finalizer. When a tier is being deleted, it checks whether
// any policies still reference the tier and updates the tier's status accordingly. Once all
// policies are removed (by the user), it removes the finalizer to allow the tier to be deleted.
//
// The controller also watches all policy types (GNP, NP, SGNP, SNP) so that when a policy is
// deleted, it re-reconciles the owning tier to check whether the finalizer can be removed.
type TierController struct {
	ctx             context.Context
	cli             clientset.Interface
	tierInformer    cache.SharedIndexInformer
	allInformers    []cache.SharedIndexInformer
	policyInformers []cache.SharedIndexInformer
	queue           workqueue.TypedRateLimitingInterface[string]
}

func NewController(
	ctx context.Context,
	cli clientset.Interface,
	tierInformer cache.SharedIndexInformer,
	policyInformers ...cache.SharedIndexInformer,
) controller.Controller {
	c := &TierController{
		ctx:             ctx,
		cli:             cli,
		tierInformer:    tierInformer,
		allInformers:    append([]cache.SharedIndexInformer{tierInformer}, policyInformers...),
		policyInformers: policyInformers,
		queue:           workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}

	// Add a cache index to each policy informer so we can efficiently look up
	// policies by tier name without hitting the API server.
	for _, inf := range policyInformers {
		if err := inf.AddIndexers(cache.Indexers{tierIndex: tierKeyFunc}); err != nil {
			logrus.WithError(err).Fatal("Failed to add tier index to policy informer")
		}
	}

	// Tier events: enqueue the tier name for reconciliation.
	tierHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			tier, ok := obj.(*v3.Tier)
			if !ok {
				logrus.WithField("type", fmt.Sprintf("%T", obj)).Error("Unexpected object type in tier add handler")
				return
			}
			c.queue.Add(tier.Name)
		},
		UpdateFunc: func(oldObj, newObj any) {
			tier, ok := newObj.(*v3.Tier)
			if !ok {
				logrus.WithField("type", fmt.Sprintf("%T", newObj)).Error("Unexpected object type in tier update handler")
				return
			}
			c.queue.Add(tier.Name)
		},
		DeleteFunc: func(obj any) {
			tier, ok := obj.(*v3.Tier)
			if !ok {
				logrus.WithField("type", fmt.Sprintf("%T", obj)).Error("Unexpected object type in tier delete handler")
				return
			}
			c.queue.Add(tier.Name)
		},
	}
	if _, err := tierInformer.AddEventHandler(tierHandlers); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for Tier")
	}

	// Watch policy resources so that when a policy is deleted, we re-reconcile the
	// owning tier (which may now be ready to have its finalizer removed).
	policyHandlers := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj any) {
			tierName := tierNameFromPolicy(obj)
			if tierName == "" {
				if accessor, ok := obj.(metav1.ObjectMetaAccessor); ok {
					meta := accessor.GetObjectMeta()
					logrus.WithFields(logrus.Fields{
						"kind":      fmt.Sprintf("%T", obj),
						"name":      meta.GetName(),
						"namespace": meta.GetNamespace(),
					}).Error("Policy has no tier set, cannot reconcile owning tier")
				}
				return
			}
			c.queue.Add(tierName)
		},
	}
	for _, inf := range policyInformers {
		if _, err := inf.AddEventHandler(policyHandlers); err != nil {
			logrus.WithError(err).Fatal("Failed to register policy event handler for Tier controller")
		}
	}

	return c
}

// tierNameFromPolicy extracts the tier name from a policy object using the
// shared names.TierFromPolicy helper. Handles the DeletedFinalStateUnknown
// wrapper that the informer may pass to delete handlers.
func tierNameFromPolicy(obj any) string {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
	tier, ok := names.TierFromPolicy(obj)
	if !ok {
		logrus.WithField("type", fmt.Sprintf("%T", obj)).Warn("Could not extract tier from policy object")
	}
	return tier
}

func (c *TierController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()
	defer c.queue.ShutDown()

	logrus.Info("Starting Tier controller")
	syncFuncs := make([]cache.InformerSynced, len(c.allInformers))
	for i, inf := range c.allInformers {
		syncFuncs[i] = inf.HasSynced
	}
	if !cache.WaitForNamedCacheSync("tiers", stopCh, syncFuncs...) {
		logrus.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}
	logrus.Info("Tier controller synced and ready")

	go c.runWorker()

	<-stopCh
	logrus.Info("Stopping Tier controller")
}

func (c *TierController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *TierController) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.reconcile(key)
	c.handleErr(err, key)
	return true
}

func (c *TierController) handleErr(err error, key string) {
	if err == nil {
		c.queue.Forget(key)
		return
	}
	if c.queue.NumRequeues(key) < maxRetries {
		logrus.WithError(err).WithField("name", key).Warning("Error reconciling tier, will retry")
		c.queue.AddRateLimited(key)
		return
	}
	c.queue.Forget(key)
	logrus.WithError(err).WithField("name", key).Error("Dropping tier out of queue after max retries")
}

// reconcile looks up the tier by name from the informer cache and reconciles it.
func (c *TierController) reconcile(name string) error {
	logCtx := logrus.WithField("name", name)
	obj, exists, err := c.tierInformer.GetStore().GetByKey(name)
	if err != nil {
		return fmt.Errorf("failed to get tier from cache: %v", err)
	}
	if !exists {
		logCtx.Debug("Tier not found in cache, nothing to reconcile")
		return nil
	}
	tier, ok := obj.(*v3.Tier)
	if !ok {
		return fmt.Errorf("unexpected object type in tier cache: %T", obj)
	}

	if tier.DeletionTimestamp == nil {
		// Tier is not being deleted — ensure it has a finalizer.
		if !hasFinalizer(tier) {
			logCtx.Info("Adding finalizer to Tier")
			tier.SetFinalizers(append(tier.Finalizers, v3.TierFinalizer))
			if _, err := c.cli.ProjectcalicoV3().Tiers().Update(c.ctx, tier, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to add finalizer: %v", err)
			}
		}
		return nil
	}

	// Tier is being deleted.
	if !hasFinalizer(tier) {
		logCtx.Debug("Tier is being deleted but has no finalizer, skipping")
		return nil
	}

	// Count remaining policies across all four policy types that reference this tier.
	counts, err := c.countPoliciesInTier(tier.Name)
	if err != nil {
		return fmt.Errorf("counting policies in tier: %v", err)
	}

	if counts.total() > 0 {
		logCtx.WithField("remaining", counts.total()).Info("Policies still exist in tier, updating status")
		return c.setTerminatingCondition(tier, counts)
	}

	// No policies left — remove the finalizer to allow deletion.
	logCtx.Info("No policies remain in tier, removing finalizer")
	tier.Finalizers = slices.DeleteFunc(tier.Finalizers, func(s string) bool { return s == v3.TierFinalizer })
	if _, err := c.cli.ProjectcalicoV3().Tiers().Update(c.ctx, tier, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to remove finalizer: %v", err)
	}
	return nil
}

// policyCounts tracks the number of policies referencing a tier, broken down by kind.
type policyCounts struct {
	GlobalNetworkPolicies       int
	NetworkPolicies             int
	StagedGlobalNetworkPolicies int
	StagedNetworkPolicies       int
}

func (p policyCounts) total() int {
	return p.GlobalNetworkPolicies + p.NetworkPolicies + p.StagedGlobalNetworkPolicies + p.StagedNetworkPolicies
}

// summary returns a concise breakdown of remaining policy counts by kind,
// e.g. "3 GlobalNetworkPolicies, 1 NetworkPolicy".
func (p policyCounts) summary() string {
	var parts []string
	if p.GlobalNetworkPolicies > 0 {
		parts = append(parts, fmt.Sprintf("%d GlobalNetworkPolic%s", p.GlobalNetworkPolicies, pluralY(p.GlobalNetworkPolicies)))
	}
	if p.NetworkPolicies > 0 {
		parts = append(parts, fmt.Sprintf("%d NetworkPolic%s", p.NetworkPolicies, pluralY(p.NetworkPolicies)))
	}
	if p.StagedGlobalNetworkPolicies > 0 {
		parts = append(parts, fmt.Sprintf("%d StagedGlobalNetworkPolic%s", p.StagedGlobalNetworkPolicies, pluralY(p.StagedGlobalNetworkPolicies)))
	}
	if p.StagedNetworkPolicies > 0 {
		parts = append(parts, fmt.Sprintf("%d StagedNetworkPolic%s", p.StagedNetworkPolicies, pluralY(p.StagedNetworkPolicies)))
	}
	return strings.Join(parts, ", ")
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// countPoliciesInTier uses the informer cache index to count all policies that reference
// the given tier, avoiding direct API server calls.
func (c *TierController) countPoliciesInTier(tierName string) (policyCounts, error) {
	var counts policyCounts
	for _, inf := range c.policyInformers {
		items, err := inf.GetIndexer().ByIndex(tierIndex, tierName)
		if err != nil {
			return counts, fmt.Errorf("looking up policies by tier %q: %v", tierName, err)
		}
		for _, item := range items {
			switch item.(type) {
			case *v3.GlobalNetworkPolicy:
				counts.GlobalNetworkPolicies++
			case *v3.NetworkPolicy:
				counts.NetworkPolicies++
			case *v3.StagedGlobalNetworkPolicy:
				counts.StagedGlobalNetworkPolicies++
			case *v3.StagedNetworkPolicy:
				counts.StagedNetworkPolicies++
			}
		}
	}
	return counts, nil
}

// setTerminatingCondition updates the tier's status to indicate it's terminating with remaining policies.
func (c *TierController) setTerminatingCondition(t *v3.Tier, counts policyCounts) error {
	cond := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "Terminating",
		Message:            fmt.Sprintf("Waiting for policies to be removed: %s", counts.summary()),
		LastTransitionTime: metav1.Now(),
	}

	changed := setCondition(t, cond)
	if !changed {
		return nil
	}

	if _, err := c.cli.ProjectcalicoV3().Tiers().UpdateStatus(c.ctx, t, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("updating tier status: %v", err)
	}
	return nil
}

func hasFinalizer(t *v3.Tier) bool {
	return slices.Contains(t.Finalizers, v3.TierFinalizer)
}

// setCondition sets or updates the given condition on the tier. Returns true if the condition changed.
func setCondition(t *v3.Tier, cond metav1.Condition) bool {
	for i, existing := range t.Status.Conditions {
		if existing.Type == cond.Type {
			if existing.Status == cond.Status && existing.Reason == cond.Reason && existing.Message == cond.Message {
				return false
			}
			t.Status.Conditions[i] = cond
			return true
		}
	}
	t.Status.Conditions = append(t.Status.Conditions, cond)
	return true
}
