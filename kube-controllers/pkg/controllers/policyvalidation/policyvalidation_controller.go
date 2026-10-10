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

package policyvalidation

import (
	"context"
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

const maxRetries = 5

// PolicyValidationController watches all Calico policy types, runs the Go validation
// logic against each policy, and updates a "Valid" status condition on the resource.
type PolicyValidationController struct {
	ctx       context.Context
	cli       clientset.Interface
	informers []cache.SharedIndexInformer
	queue     workqueue.TypedRateLimitingInterface[string]
}

func NewController(
	ctx context.Context,
	cli clientset.Interface,
	informers ...cache.SharedIndexInformer,
) controller.Controller {
	c := &PolicyValidationController{
		ctx:       ctx,
		cli:       cli,
		informers: informers,
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if key, err := policyKey(obj); err == nil {
				c.queue.Add(key)
			}
		},
		UpdateFunc: func(_, newObj any) {
			if key, err := policyKey(newObj); err == nil {
				c.queue.Add(key)
			}
		},
	}
	for _, inf := range informers {
		if _, err := inf.AddEventHandler(handler); err != nil {
			logrus.WithError(err).Fatal("Failed to register event handler for policy validation controller")
		}
	}

	return c
}

func (c *PolicyValidationController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()
	defer c.queue.ShutDown()

	logrus.Info("Starting PolicyValidation controller")
	syncFuncs := make([]cache.InformerSynced, len(c.informers))
	for i, inf := range c.informers {
		syncFuncs[i] = inf.HasSynced
	}
	if !cache.WaitForNamedCacheSync("policyvalidation", stopCh, syncFuncs...) {
		logrus.Info("Failed to sync resources, received signal for PolicyValidation controller to shut down.")
		return
	}
	logrus.Info("PolicyValidation controller synced and ready")

	go c.runWorker()

	<-stopCh
	logrus.Info("Stopping PolicyValidation controller")
}

func (c *PolicyValidationController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *PolicyValidationController) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.reconcile(key)
	c.handleErr(err, key)
	return true
}

func (c *PolicyValidationController) handleErr(err error, key string) {
	if err == nil {
		c.queue.Forget(key)
		return
	}
	if c.queue.NumRequeues(key) < maxRetries {
		logrus.WithError(err).WithField("key", key).Warning("Error reconciling policy, will retry")
		c.queue.AddRateLimited(key)
		return
	}
	c.queue.Forget(key)
	logrus.WithError(err).WithField("key", key).Error("Dropping policy out of queue after max retries")
}

// reconcile looks up the policy from the informer caches and validates it.
func (c *PolicyValidationController) reconcile(key string) error {
	logCtx := logrus.WithField("key", key)

	obj, exists, err := c.getFromCache(key)
	if err != nil {
		return fmt.Errorf("failed to get policy from cache: %w", err)
	}
	if !exists {
		logCtx.Debug("Policy not found in cache, nothing to reconcile")
		return nil
	}

	// Run the full validation suite.
	validationErr := validator.Validate(obj)

	condition := metav1.Condition{
		Type: v3.PolicyConditionValid,
	}
	if validationErr != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = v3.PolicyReasonInvalid
		condition.Message = validationErr.Error()
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Reason = v3.PolicyReasonValid
		condition.Message = ""
	}

	return c.updateCondition(logCtx, obj, condition)
}

// getFromCache searches all informer caches for the given key.
func (c *PolicyValidationController) getFromCache(key string) (any, bool, error) {
	for _, inf := range c.informers {
		obj, exists, err := inf.GetStore().GetByKey(key)
		if err != nil {
			return nil, false, err
		}
		if exists {
			return obj, true, nil
		}
	}
	return nil, false, nil
}

// updateCondition sets the Valid condition on the policy and writes the status subresource.
func (c *PolicyValidationController) updateCondition(logCtx *logrus.Entry, obj any, condition metav1.Condition) error {
	switch p := obj.(type) {
	case *v3.NetworkPolicy:
		p = p.DeepCopy()
		if !setCondition(&p.Status, condition) {
			return nil
		}
		logCtx.Infof("Updating Valid condition to %s", condition.Status)
		_, err := c.cli.ProjectcalicoV3().NetworkPolicies(p.Namespace).UpdateStatus(c.ctx, p, metav1.UpdateOptions{})
		return err
	case *v3.GlobalNetworkPolicy:
		p = p.DeepCopy()
		if !setCondition(&p.Status, condition) {
			return nil
		}
		logCtx.Infof("Updating Valid condition to %s", condition.Status)
		_, err := c.cli.ProjectcalicoV3().GlobalNetworkPolicies().UpdateStatus(c.ctx, p, metav1.UpdateOptions{})
		return err
	case *v3.StagedNetworkPolicy:
		p = p.DeepCopy()
		if !setCondition(&p.Status, condition) {
			return nil
		}
		logCtx.Infof("Updating Valid condition to %s", condition.Status)
		_, err := c.cli.ProjectcalicoV3().StagedNetworkPolicies(p.Namespace).UpdateStatus(c.ctx, p, metav1.UpdateOptions{})
		return err
	case *v3.StagedGlobalNetworkPolicy:
		p = p.DeepCopy()
		if !setCondition(&p.Status, condition) {
			return nil
		}
		logCtx.Infof("Updating Valid condition to %s", condition.Status)
		_, err := c.cli.ProjectcalicoV3().StagedGlobalNetworkPolicies().UpdateStatus(c.ctx, p, metav1.UpdateOptions{})
		return err
	case *v3.StagedKubernetesNetworkPolicy:
		p = p.DeepCopy()
		if !setCondition(&p.Status, condition) {
			return nil
		}
		logCtx.Infof("Updating Valid condition to %s", condition.Status)
		_, err := c.cli.ProjectcalicoV3().StagedKubernetesNetworkPolicies(p.Namespace).UpdateStatus(c.ctx, p, metav1.UpdateOptions{})
		return err
	default:
		return fmt.Errorf("unexpected policy type: %T", obj)
	}
}

// policyKey returns the informer cache key for a policy object.
func policyKey(obj any) (string, error) {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
	return cache.MetaNamespaceKeyFunc(obj)
}

// setCondition updates the Valid condition on a PolicyStatus, creating the status if nil.
// Returns true if the condition changed and needs to be written.
func setCondition(status **v3.PolicyStatus, condition metav1.Condition) bool {
	if *status == nil {
		condition.LastTransitionTime = metav1.Now()
		*status = &v3.PolicyStatus{
			Conditions: []metav1.Condition{condition},
		}
		return true
	}

	for i, c := range (*status).Conditions {
		if c.Type == condition.Type {
			if c.Status == condition.Status && c.Reason == condition.Reason && c.Message == condition.Message {
				return false
			}
			condition.LastTransitionTime = metav1.Now()
			(*status).Conditions[i] = condition
			return true
		}
	}

	condition.LastTransitionTime = metav1.Now()
	(*status).Conditions = append((*status).Conditions, condition)
	return true
}
