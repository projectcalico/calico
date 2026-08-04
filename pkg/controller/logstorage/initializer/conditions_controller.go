// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package initializer

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
)

func AddConditionsController(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		return nil
	}

	// Create the reconciler
	r := &LogStorageConditions{
		client:      mgr.GetClient(),
		scheme:      mgr.GetScheme(),
		multiTenant: opts.MultiTenant,
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("log-storage-conditions-controller").
		Watches(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{}).
		Watches(&operatorv1.TigeraStatus{}, &handler.EnqueueRequestForObject{}).
		For(&operatorv1.LogStorage{}).
		Complete(r)
}

var _ reconcile.Reconciler = &LogStorageConditions{}

// LogStorageConditions implements a controller that monitors the status of various log storage related TigeraStatus objects and
// updates the LogStorage object's status conditions accordingly.
type LogStorageConditions struct {
	client      client.Client
	scheme      *runtime.Scheme
	multiTenant bool
}

func (r *LogStorageConditions) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Conditions")

	ls := &operatorv1.LogStorage{}
	key := utils.DefaultEnterpriseInstanceKey
	if err := r.client.Get(ctx, key, ls); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// Fetch the current status condition for log storage
	currentConditions := getCurrentConditions(ls.Status.Conditions)

	// Aggregate TigeraStatus conditions from all logstorage subcontrollers into a map,
	// using the condition type (e.g., Available, Progressing, and Degraded) as the key.
	desiredConditions, err := r.getDesiredConditions(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Compare and update the current StatusCondition if there are any new changes
	ls.Status.Conditions = updateConditions(currentConditions, desiredConditions)

	if err := r.client.Status().Update(ctx, ls); err != nil {
		log.WithValues("reason", err).Info("Failed to update LogStorage status conditions")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func getCurrentConditions(lsConditions []metav1.Condition) map[string]metav1.Condition {
	statusConditions := make(map[string]metav1.Condition)
	for _, condition := range lsConditions {
		statusConditions[condition.Type] = condition
	}
	return statusConditions
}

func (r *LogStorageConditions) getDesiredConditions(ctx context.Context) (map[string]metav1.Condition, error) {
	expectedInstances := []string{TigeraStatusName, TigeraStatusLogStorageAccess, TigeraStatusLogStorageElastic, TigeraStatusLogStorageSecrets}
	if r.multiTenant {
		expectedInstances = append(expectedInstances, TigeraStatusLogStorageUsers)
	} else {
		expectedInstances = append(expectedInstances, TigeraStatusLogStorageESMetrics, TigeraStatusLogStorageKubeController, TigeraStatusLogStorageDashboards)
	}

	// Keep track of which instances are in which state.
	states := map[string][]string{
		string(operatorv1.ComponentDegraded):    {},
		string(operatorv1.ComponentAvailable):   {},
		string(operatorv1.ComponentProgressing): {},
	}

	// We also keep track of the oldest observed generation here so we can add it to the conditions later.
	var observedGeneration int64

	// Build up the lists of which components are in which state.
	for _, instance := range expectedInstances {
		ts := &operatorv1.TigeraStatus{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: instance}, ts); err != nil && errors.IsNotFound(err) {
			// Expected status not found, treat it as an error.
			states[string(operatorv1.ComponentDegraded)] = append(states[string(operatorv1.ComponentDegraded)], instance)
			continue
		} else if err != nil {
			return nil, err
		}

		// Found it - add to states map, which we use to track which TigeraStatuses are in which state(s).
		for _, condition := range ts.Status.Conditions {
			if condition.Status == operatorv1.ConditionTrue {
				states[string(condition.Type)] = append(states[string(condition.Type)], instance)
			}
			if observedGeneration == 0 || condition.ObservedGeneration < observedGeneration {
				observedGeneration = condition.ObservedGeneration
			}
		}
	}

	// Convert the states map to a set of conditions.
	conditions := map[string]metav1.Condition{}
	for statusType, instances := range states {

		condition := metav1.Condition{
			Type:               statusType,
			ObservedGeneration: observedGeneration,
			Reason:             string(operatorv1.Unknown),
		}
		if statusType != string(operatorv1.ComponentAvailable) && len(instances) != 0 {
			// This condition is true.
			condition.Status = metav1.ConditionTrue
			condition.Reason = string(operatorv1.ResourceNotReady)
			condition.Message = fmt.Sprintf("The following sub-controllers are in this condition: %+v", instances)
		} else if statusType != string(operatorv1.ComponentAvailable) {
			// This condition is false.
			condition.Status = metav1.ConditionFalse
		} else {
			// This is the available condition, which is only true if all statuses are available.
			condition.Type = string(operatorv1.ComponentReady)
			// Available will be mapped to Ready while storing in ls Conditions. Update the key type to Ready for Available
			statusType = condition.Type
			if len(instances) == len(expectedInstances) {
				condition.Status = metav1.ConditionTrue
				condition.Reason = string(operatorv1.AllObjectsAvailable)
				condition.Message = "All sub-controllers are available"
			} else {
				condition.Status = metav1.ConditionFalse
			}
		}
		// Store the condition.
		conditions[statusType] = condition
	}
	return conditions, nil
}

func updateConditions(currentConditions, desiredConditions map[string]metav1.Condition) []metav1.Condition {
	statusConditions := []metav1.Condition{}

	// Update the current log storage condition only when the aggregate desired status have new changes
	for _, desired := range desiredConditions {

		current, ok := currentConditions[desired.Type]
		if !ok || current.Status != desired.Status || current.Message != desired.Message {
			desired.LastTransitionTime = metav1.NewTime(time.Now())
		} else {
			desired.LastTransitionTime = current.LastTransitionTime
		}

		statusConditions = append(statusConditions, desired)
	}
	return statusConditions
}
