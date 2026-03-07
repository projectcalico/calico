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

package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicov3 "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	apiregv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// NewController creates a new migration controller. It watches for DatastoreMigration CRs
// and drives the v1-to-v3 CRD migration state machine.
func NewController(
	ctx context.Context,
	k8sClient kubernetes.Interface,
	backendClient api.Client,
	v3Client calicov3.ProjectcalicoV3Interface,
	dynamicClient dynamic.Interface,
	apiregClient apiregv1client.ApiregistrationV1Interface,
) controller.Controller {
	return &migrationController{
		ctx:           ctx,
		k8sClient:     k8sClient,
		backendClient: backendClient,
		v3Client:      v3Client,
		dynamicClient: dynamicClient,
		apiregClient:  apiregClient,
	}
}

type migrationController struct {
	ctx           context.Context
	k8sClient     kubernetes.Interface
	backendClient api.Client
	v3Client      calicov3.ProjectcalicoV3Interface
	dynamicClient dynamic.Interface
	apiregClient  apiregv1client.ApiregistrationV1Interface
}

func (c *migrationController) Run(stop chan struct{}) {
	log.Info("Starting datastore migration controller")
	defer log.Info("Stopping datastore migration controller")

	// Poll for DatastoreMigration CRs. In a production implementation, this would use
	// an informer/watch, but for the prototype a simple poll loop is sufficient.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := c.reconcile(); err != nil {
				log.WithError(err).Error("Migration reconcile error")
			}
		}
	}
}

func (c *migrationController) reconcile() error {
	dm, err := c.getDatastoreMigration("v1-to-v3")
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting DatastoreMigration: %v", err)
	}

	logCtx := log.WithFields(log.Fields{
		"name":  dm.Name,
		"phase": dm.Status.Phase,
	})

	switch dm.Status.Phase {
	case "", DatastoreMigrationPhasePending:
		return c.handlePending(logCtx, dm)
	case DatastoreMigrationPhaseMigrating:
		return c.handleMigrating(logCtx, dm)
	case DatastoreMigrationPhaseConverged:
		return c.handleConverged(logCtx, dm)
	case DatastoreMigrationPhaseComplete:
		logCtx.Debug("Migration already complete")
		return nil
	case DatastoreMigrationPhaseFailed:
		logCtx.Debug("Migration has failed, no further action")
		return nil
	default:
		return fmt.Errorf("unknown migration phase: %s", dm.Status.Phase)
	}
}

// handlePending validates prerequisites and transitions to Migrating.
func (c *migrationController) handlePending(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration is pending, validating prerequisites")

	// Validate that the APIService exists (we're running in API server mode).
	_, err := c.apiregClient.APIServices().Get(c.ctx, "v3.projectcalico.org", metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logCtx.Warn("APIService v3.projectcalico.org not found — may not be needed or already partially complete")
		} else {
			return fmt.Errorf("checking APIService: %v", err)
		}
	}

	// Transition to Migrating.
	now := metav1.Now()
	dm.Status.Phase = DatastoreMigrationPhaseMigrating
	dm.Status.StartedAt = &now
	return c.updateStatus(dm)
}

// handleMigrating runs the core migration logic.
func (c *migrationController) handleMigrating(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration in progress")

	// Step 1: Delete the APIService to route v3 requests to CRDs.
	if err := c.deleteAPIService(logCtx); err != nil {
		return err
	}

	// Step 2: Create v3 ClusterInformation with DatastoreReady=false to lock the datastore.
	if err := c.lockDatastore(logCtx); err != nil {
		return err
	}

	// Step 3: Migrate all resources in order.
	migrators := GetRegistry()
	sort.Slice(migrators, func(i, j int) bool {
		return migrators[i].Order < migrators[j].Order
	})

	totalMigrated := 0
	totalSkipped := 0
	totalCount := 0
	var allConflicts []string
	uidMap := make(map[types.UID]types.UID)

	for _, m := range migrators {
		result, err := MigrateResourceType(c.ctx, c.backendClient, m)
		if err != nil {
			c.setFailedStatus(dm, fmt.Sprintf("failed migrating %s: %v", m.Kind, err))
			return c.updateStatus(dm)
		}
		totalMigrated += result.Migrated
		totalSkipped += result.Skipped
		allConflicts = append(allConflicts, result.Conflicts...)
		totalCount += result.Migrated + result.Skipped + len(result.Conflicts)
		for oldUID, newUID := range result.UIDMapping {
			uidMap[oldUID] = newUID
		}
	}

	// Second pass: remap OwnerReference UIDs that point to Calico resources.
	if err := RemapOwnerReferences(c.ctx, uidMap, migrators); err != nil {
		c.setFailedStatus(dm, fmt.Sprintf("failed remapping OwnerReferences: %v", err))
		return c.updateStatus(dm)
	}

	// Update progress.
	dm.Status.Progress = DatastoreMigrationProgress{
		Total:     totalCount,
		Migrated:  totalMigrated,
		Skipped:   totalSkipped,
		Conflicts: len(allConflicts),
	}

	// Update conditions for conflicts.
	dm.Status.Conditions = nil
	for _, conflict := range allConflicts {
		dm.Status.Conditions = append(dm.Status.Conditions, metav1.Condition{
			Type:               "Conflict",
			Status:             metav1.ConditionTrue,
			Reason:             "ResourceMismatch",
			Message:            conflict,
			LastTransitionTime: metav1.Now(),
		})
	}

	if len(allConflicts) > 0 {
		logCtx.WithField("conflicts", len(allConflicts)).Warn("Migration has conflicts that need manual resolution")
		return c.updateStatus(dm)
	}

	// No conflicts — transition to Converged.
	dm.Status.Phase = DatastoreMigrationPhaseConverged
	logCtx.Info("Migration converged, unlocking datastore")

	// Step 4: Unlock the datastore.
	if err := c.unlockDatastore(logCtx); err != nil {
		return err
	}

	return c.updateStatus(dm)
}

// handleConverged transitions to Complete after the operator detects v3 CRDs.
func (c *migrationController) handleConverged(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration converged, transitioning to Complete")
	now := metav1.Now()
	dm.Status.Phase = DatastoreMigrationPhaseComplete
	dm.Status.CompletedAt = &now
	return c.updateStatus(dm)
}

// deleteAPIService removes the v3.projectcalico.org APIService so that K8s routes
// projectcalico.org/v3 requests to the CRDs instead of the aggregated API server.
func (c *migrationController) deleteAPIService(logCtx *log.Entry) error {
	err := c.apiregClient.APIServices().Delete(c.ctx, "v3.projectcalico.org", metav1.DeleteOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logCtx.Debug("APIService already deleted")
			return nil
		}
		return fmt.Errorf("deleting APIService: %v", err)
	}
	logCtx.Info("Deleted APIService v3.projectcalico.org")
	return nil
}

// lockDatastore creates or updates the v3 ClusterInformation with DatastoreReady=false
// to signal components to pause and retain cached dataplane state.
func (c *migrationController) lockDatastore(logCtx *log.Entry) error {
	ready := false
	ci := &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: apiv3.ClusterInformationSpec{
			DatastoreReady: &ready,
		},
	}

	existing, err := c.v3Client.ClusterInformations().Get(c.ctx, "default", metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			_, err = c.v3Client.ClusterInformations().Create(c.ctx, ci, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("creating v3 ClusterInformation: %v", err)
			}
			logCtx.Info("Created v3 ClusterInformation with DatastoreReady=false")
			return nil
		}
		return fmt.Errorf("getting v3 ClusterInformation: %v", err)
	}

	existing.Spec.DatastoreReady = &ready
	_, err = c.v3Client.ClusterInformations().Update(c.ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating v3 ClusterInformation: %v", err)
	}
	logCtx.Info("Set DatastoreReady=false on v3 ClusterInformation")
	return nil
}

// unlockDatastore sets DatastoreReady=true on the v3 ClusterInformation,
// signaling components to resume normal operation reading from v3 CRDs.
func (c *migrationController) unlockDatastore(logCtx *log.Entry) error {
	existing, err := c.v3Client.ClusterInformations().Get(c.ctx, "default", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting v3 ClusterInformation for unlock: %v", err)
	}

	ready := true
	existing.Spec.DatastoreReady = &ready
	_, err = c.v3Client.ClusterInformations().Update(c.ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("unlocking datastore: %v", err)
	}
	logCtx.Info("Set DatastoreReady=true on v3 ClusterInformation")
	return nil
}

func (c *migrationController) setFailedStatus(dm *DatastoreMigration, message string) {
	dm.Status.Phase = DatastoreMigrationPhaseFailed
	dm.Status.Conditions = append(dm.Status.Conditions, metav1.Condition{
		Type:               "Failed",
		Status:             metav1.ConditionTrue,
		Reason:             "MigrationError",
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// getDatastoreMigration retrieves a DatastoreMigration CR by name using the dynamic client.
func (c *migrationController) getDatastoreMigration(name string) (*DatastoreMigration, error) {
	uns, err := c.dynamicClient.Resource(DatastoreMigrationGVR).Get(c.ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return unstructuredToDatastoreMigration(uns)
}

// updateStatus updates the status subresource of a DatastoreMigration CR.
func (c *migrationController) updateStatus(dm *DatastoreMigration) error {
	uns, err := datastoreMigrationToUnstructured(dm)
	if err != nil {
		return fmt.Errorf("converting DatastoreMigration to unstructured: %v", err)
	}
	_, err = c.dynamicClient.Resource(DatastoreMigrationGVR).UpdateStatus(c.ctx, uns, metav1.UpdateOptions{})
	return err
}

func unstructuredToDatastoreMigration(uns *unstructured.Unstructured) (*DatastoreMigration, error) {
	data, err := uns.MarshalJSON()
	if err != nil {
		return nil, err
	}
	dm := &DatastoreMigration{}
	if err := json.Unmarshal(data, dm); err != nil {
		return nil, err
	}
	return dm, nil
}

func datastoreMigrationToUnstructured(dm *DatastoreMigration) (*unstructured.Unstructured, error) {
	data, err := json.Marshal(dm)
	if err != nil {
		return nil, err
	}
	uns := &unstructured.Unstructured{}
	if err := uns.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return uns, nil
}
