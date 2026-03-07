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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
)

// TierController watches Tier resources and manages their finalizers for cascading deletion.
// When a tier is created, it adds a finalizer. When a tier is being deleted, it checks whether
// any policies still reference the tier and updates the tier's status accordingly. Once all
// policies are removed (by the user), it removes the finalizer to allow the tier to be deleted.
type TierController struct {
	ctx          context.Context
	cli          clientset.Interface
	tierInformer cache.SharedIndexInformer
}

func NewController(
	ctx context.Context,
	cli clientset.Interface,
	tierInformer cache.SharedIndexInformer,
) controller.Controller {
	c := &TierController{
		ctx:          ctx,
		cli:          cli,
		tierInformer: tierInformer,
	}

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			tier := obj.(*v3.Tier)
			logrus.WithField("name", tier.Name).Info("Handling tier add")
			if err := c.Reconcile(tier); err != nil {
				logrus.WithError(err).Error("Error handling tier add")
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			tier := newObj.(*v3.Tier)
			logrus.WithField("name", tier.Name).Info("Handling tier update")
			if err := c.Reconcile(tier); err != nil {
				logrus.WithError(err).Error("Error handling tier update")
			}
		},
		DeleteFunc: func(obj any) {
			tier := obj.(*v3.Tier)
			logrus.WithField("name", tier.Name).Info("Handling tier deletion")
			if err := c.Reconcile(tier); err != nil {
				logrus.WithError(err).Error("Error handling tier deletion")
			}
		},
	}
	if _, err := tierInformer.AddEventHandler(handlers); err != nil {
		logrus.WithError(err).Fatal("Failed to register event handler for Tier")
	}

	return c
}

func (c *TierController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	logrus.Info("Starting Tier controller")
	if !cache.WaitForNamedCacheSync("tiers", stopCh, c.tierInformer.HasSynced) {
		logrus.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}
	logrus.Debug("Finished syncing with Kubernetes API")

	<-stopCh
	logrus.Info("Stopping Tier controller")
}

func (c *TierController) Reconcile(t *v3.Tier) error {
	logCtx := logrus.WithField("name", t.Name)

	if t.DeletionTimestamp == nil {
		// Tier is not being deleted — ensure it has a finalizer.
		if !hasFinalizer(t) {
			logCtx.Info("Adding finalizer to Tier")
			t.SetFinalizers(append(t.Finalizers, v3.TierFinalizer))
			if _, err := c.cli.ProjectcalicoV3().Tiers().Update(c.ctx, t, metav1.UpdateOptions{}); err != nil {
				logCtx.WithError(err).Error("Failed to add finalizer to Tier")
				return err
			}
		}
		return nil
	}

	// Tier is being deleted.
	if !hasFinalizer(t) {
		logCtx.Info("Tier is being deleted but has no finalizer, skipping")
		return nil
	}

	// Count remaining policies across all four policy types that reference this tier.
	remaining, err := c.countPoliciesInTier(t.Name)
	if err != nil {
		logCtx.WithError(err).Error("Failed to count policies in tier")
		return err
	}

	if remaining > 0 {
		logCtx.WithField("remaining", remaining).Info("Policies still exist in tier, updating status")
		return c.setTerminatingCondition(t, remaining)
	}

	// No policies left — remove the finalizer to allow deletion.
	logCtx.Info("No policies remain in tier, removing finalizer")
	t.Finalizers = slices.DeleteFunc(t.Finalizers, func(s string) bool { return s == v3.TierFinalizer })
	if _, err := c.cli.ProjectcalicoV3().Tiers().Update(c.ctx, t, metav1.UpdateOptions{}); err != nil {
		logCtx.WithError(err).Error("Failed to remove finalizer from Tier")
		return err
	}
	return nil
}

// countPoliciesInTier uses field selectors to count all policies that reference the given tier.
func (c *TierController) countPoliciesInTier(tierName string) (int, error) {
	ctx := c.ctx
	fieldSelector := fmt.Sprintf("spec.tier=%s", tierName)
	opts := metav1.ListOptions{FieldSelector: fieldSelector}

	total := 0

	// GlobalNetworkPolicies (cluster-scoped)
	gnpList, err := c.cli.ProjectcalicoV3().GlobalNetworkPolicies().List(ctx, opts)
	if err != nil {
		return 0, fmt.Errorf("listing GlobalNetworkPolicies: %v", err)
	}
	total += len(gnpList.Items)

	// NetworkPolicies (namespaced — list across all namespaces)
	npList, err := c.cli.ProjectcalicoV3().NetworkPolicies("").List(ctx, opts)
	if err != nil {
		return 0, fmt.Errorf("listing NetworkPolicies: %v", err)
	}
	total += len(npList.Items)

	// StagedGlobalNetworkPolicies (cluster-scoped)
	sgnpList, err := c.cli.ProjectcalicoV3().StagedGlobalNetworkPolicies().List(ctx, opts)
	if err != nil {
		return 0, fmt.Errorf("listing StagedGlobalNetworkPolicies: %v", err)
	}
	total += len(sgnpList.Items)

	// StagedNetworkPolicies (namespaced)
	snpList, err := c.cli.ProjectcalicoV3().StagedNetworkPolicies("").List(ctx, opts)
	if err != nil {
		return 0, fmt.Errorf("listing StagedNetworkPolicies: %v", err)
	}
	total += len(snpList.Items)

	return total, nil
}

// setTerminatingCondition updates the tier's status to indicate it's terminating with remaining policies.
func (c *TierController) setTerminatingCondition(t *v3.Tier, remaining int) error {
	cond := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "Terminating",
		Message:            fmt.Sprintf("Tier is being deleted. %d policies still reference this tier and must be removed before deletion can complete.", remaining),
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
