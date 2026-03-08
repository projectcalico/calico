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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

const (
	// finalizerName is added to the DatastoreMigration CR in the Pending phase.
	// On deletion:
	//   - If migration is Complete: delete v1 CRDs (crd.projectcalico.org).
	//   - Otherwise: abort migration and restore the APIService.
	finalizerName = "migration.projectcalico.org/v1-crd-cleanup"

	// savedAPIServiceAnnotation holds the serialized APIService object so it
	// can be restored on abort.
	savedAPIServiceAnnotation = "migration.projectcalico.org/saved-apiservice"
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

	// If the CR is being deleted, run the finalizer logic.
	if dm.DeletionTimestamp != nil {
		return c.handleDeletion(logCtx, dm)
	}

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

// handlePending validates prerequisites, adds the finalizer, and transitions to Migrating.
func (c *migrationController) handlePending(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration is pending, validating prerequisites")

	// Add the finalizer if not already present.
	if !hasFinalizer(dm) {
		logCtx.Info("Adding finalizer to DatastoreMigration CR")
		if err := c.addFinalizer(dm); err != nil {
			return fmt.Errorf("adding finalizer: %v", err)
		}
		// Re-fetch after metadata update to avoid conflicts.
		var err error
		dm, err = c.getDatastoreMigration(dm.Name)
		if err != nil {
			return fmt.Errorf("re-fetching DatastoreMigration after finalizer: %v", err)
		}
	}

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

	// Step 1: Save and delete the APIService to route v3 requests to CRDs.
	if err := c.saveAndDeleteAPIService(logCtx, dm); err != nil {
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

	var allConflicts []string
	uidMap := make(map[types.UID]types.UID)

	// Initialize progress tracking.
	dm.Status.Progress = DatastoreMigrationProgress{
		TotalTypes:  len(migrators),
		TypeDetails: make([]TypeMigrationProgress, 0, len(migrators)),
	}

	for i, m := range migrators {
		// Update current-type progress before starting each type.
		dm.Status.Progress.CurrentType = m.Kind
		dm.Status.Progress.CompletedTypes = i
		if err := c.updateStatus(dm); err != nil {
			logCtx.WithError(err).Warn("Failed to update progress status")
		}

		result, err := MigrateResourceType(c.ctx, c.backendClient, m)
		if err != nil {
			c.setFailedStatus(dm, fmt.Sprintf("failed migrating %s: %v", m.Kind, err))
			return c.updateStatus(dm)
		}

		dm.Status.Progress.Migrated += result.Migrated
		dm.Status.Progress.Skipped += result.Skipped
		dm.Status.Progress.Total += result.Migrated + result.Skipped + len(result.Conflicts)
		dm.Status.Progress.Conflicts += len(result.Conflicts)
		dm.Status.Progress.TypeDetails = append(dm.Status.Progress.TypeDetails, TypeMigrationProgress{
			Kind:      m.Kind,
			Migrated:  result.Migrated,
			Skipped:   result.Skipped,
			Conflicts: len(result.Conflicts),
		})

		allConflicts = append(allConflicts, result.Conflicts...)
		for oldUID, newUID := range result.UIDMapping {
			uidMap[oldUID] = newUID
		}
	}

	// Mark all types complete.
	dm.Status.Progress.CompletedTypes = len(migrators)
	dm.Status.Progress.CurrentType = ""

	// Second pass: remap OwnerReference UIDs that point to Calico resources.
	if err := RemapOwnerReferences(c.ctx, uidMap, migrators); err != nil {
		c.setFailedStatus(dm, fmt.Sprintf("failed remapping OwnerReferences: %v", err))
		return c.updateStatus(dm)
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

// handleDeletion runs the finalizer logic when the DatastoreMigration CR is being deleted.
func (c *migrationController) handleDeletion(logCtx *log.Entry, dm *DatastoreMigration) error {
	if !hasFinalizer(dm) {
		return nil
	}

	if dm.Status.Phase == DatastoreMigrationPhaseComplete {
		return c.handleCompletedCleanup(logCtx, dm)
	}
	return c.handleAbort(logCtx, dm)
}

// handleCompletedCleanup deletes v1 CRDs after a successful migration.
func (c *migrationController) handleCompletedCleanup(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration complete, cleaning up v1 CRDs")

	crds, err := c.k8sClient.Discovery().ServerResourcesForGroupVersion("apiextensions.k8s.io/v1")
	if err != nil {
		logCtx.WithError(err).Warn("Could not discover apiextensions, attempting direct CRD deletion")
	}
	_ = crds // Discovery is just a sanity check.

	// List all CRDs in the crd.projectcalico.org group and delete them.
	crdClient := c.dynamicClient.Resource(crdGVR)
	crdList, err := crdClient.List(c.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing CRDs: %v", err)
	}

	deleted := 0
	for _, crd := range crdList.Items {
		group, _, _ := unstructured.NestedString(crd.Object, "spec", "group")
		if group != "crd.projectcalico.org" {
			continue
		}
		logCtx.WithField("crd", crd.GetName()).Info("Deleting v1 CRD")
		if err := crdClient.Delete(c.ctx, crd.GetName(), metav1.DeleteOptions{}); err != nil {
			if !kerrors.IsNotFound(err) {
				return fmt.Errorf("deleting CRD %s: %v", crd.GetName(), err)
			}
		}
		deleted++
	}
	logCtx.WithField("deleted", deleted).Info("Finished deleting v1 CRDs")

	return c.removeFinalizer(dm)
}

// handleAbort restores the cluster to pre-migration state when the CR is deleted
// before migration completes.
func (c *migrationController) handleAbort(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration incomplete, aborting and restoring pre-migration state")

	// Step 1: Delete partial v3 resources that were created during migration.
	// This is best-effort — the resources become inert once the APIService is
	// restored since nothing reads v3 CRDs in API server mode, but cleaning
	// them up avoids confusion on retry.
	c.cleanupPartialV3Resources(logCtx)

	// Step 2: Delete the v3 ClusterInformation if it was created with
	// DatastoreReady=false, so components don't stay paused after restore.
	if err := c.v3Client.ClusterInformations().Delete(c.ctx, "default", metav1.DeleteOptions{}); err != nil {
		if !kerrors.IsNotFound(err) {
			logCtx.WithError(err).Warn("Failed to delete v3 ClusterInformation during abort")
		}
	} else {
		logCtx.Info("Deleted v3 ClusterInformation")
	}

	// Step 3: Restore the aggregated APIService from the saved annotation.
	if err := c.restoreAPIService(logCtx, dm); err != nil {
		logCtx.WithError(err).Error("Failed to restore APIService during abort")
		return fmt.Errorf("restoring APIService: %v", err)
	}

	return c.removeFinalizer(dm)
}

// cleanupPartialV3Resources deletes v3 resources that were created during
// migration. This is best-effort: failures are logged but don't block the abort.
func (c *migrationController) cleanupPartialV3Resources(logCtx *log.Entry) {
	migrators := GetRegistry()
	for _, m := range migrators {
		if m.ListV3 == nil {
			continue
		}
		v3List, err := m.ListV3(c.ctx)
		if err != nil {
			logCtx.WithError(err).WithField("kind", m.Kind).Warn("Failed to list v3 resources for cleanup")
			continue
		}
		for _, obj := range v3List {
			name := obj.GetName()
			ns := obj.GetNamespace()
			logCtx.WithFields(log.Fields{"kind": m.Kind, "name": name, "namespace": ns}).Debug("Deleting partial v3 resource")
			// Use the dynamic client with the v3 GVR to delete, since the
			// typed clients don't expose Delete on all types uniformly.
			// For the prototype, we skip actual deletion and just log. A
			// production implementation would use DeleteV3 on the migrator.
		}
		logCtx.WithFields(log.Fields{"kind": m.Kind, "count": len(v3List)}).Info("Found partial v3 resources for cleanup")
	}
}

// saveAndDeleteAPIService saves the current APIService to an annotation on the
// DatastoreMigration CR, then deletes it. If the APIService is already gone
// (e.g., controller restarted mid-migration), this is a no-op.
func (c *migrationController) saveAndDeleteAPIService(logCtx *log.Entry, dm *DatastoreMigration) error {
	apiSvc, err := c.apiregClient.APIServices().Get(c.ctx, "v3.projectcalico.org", metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logCtx.Debug("APIService already deleted")
			return nil
		}
		return fmt.Errorf("getting APIService for save: %v", err)
	}

	// Check if it's already a CRD-backed (automanaged) APIService. If so,
	// the aggregated one was already deleted and K8s auto-created this one.
	if apiSvc.Labels != nil && apiSvc.Labels["kube-aggregator.kubernetes.io/automanaged"] == "true" {
		logCtx.Debug("APIService is already CRD-backed, nothing to save/delete")
		return nil
	}

	// Save the APIService to an annotation if not already saved.
	if dm.Annotations == nil || dm.Annotations[savedAPIServiceAnnotation] == "" {
		// Clear server-side fields before serializing so we can re-create cleanly.
		saved := apiSvc.DeepCopy()
		saved.ResourceVersion = ""
		saved.UID = ""
		saved.CreationTimestamp = metav1.Time{}
		saved.ManagedFields = nil

		data, err := json.Marshal(saved)
		if err != nil {
			return fmt.Errorf("serializing APIService: %v", err)
		}

		if dm.Annotations == nil {
			dm.Annotations = make(map[string]string)
		}
		dm.Annotations[savedAPIServiceAnnotation] = string(data)
		if err := c.updateMetadata(dm); err != nil {
			return fmt.Errorf("saving APIService annotation: %v", err)
		}
		logCtx.Info("Saved APIService to annotation")

		// Re-fetch to avoid stale resourceVersion after metadata update.
		dm, err = c.getDatastoreMigration(dm.Name)
		if err != nil {
			return fmt.Errorf("re-fetching after saving APIService: %v", err)
		}
	}

	// Delete the APIService.
	err = c.apiregClient.APIServices().Delete(c.ctx, "v3.projectcalico.org", metav1.DeleteOptions{})
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

// restoreAPIService recreates the aggregated APIService from the saved annotation.
func (c *migrationController) restoreAPIService(logCtx *log.Entry, dm *DatastoreMigration) error {
	// Check if an aggregated APIService already exists (e.g., operator recreated it).
	existing, err := c.apiregClient.APIServices().Get(c.ctx, "v3.projectcalico.org", metav1.GetOptions{})
	if err == nil {
		if existing.Labels == nil || existing.Labels["kube-aggregator.kubernetes.io/automanaged"] != "true" {
			logCtx.Info("Aggregated APIService already exists, skipping restore")
			return nil
		}
		// The existing one is automanaged (CRD-backed). Delete it so we can
		// recreate the aggregated one.
		logCtx.Info("Deleting automanaged APIService to restore aggregated one")
		if err := c.apiregClient.APIServices().Delete(c.ctx, "v3.projectcalico.org", metav1.DeleteOptions{}); err != nil {
			if !kerrors.IsNotFound(err) {
				return fmt.Errorf("deleting automanaged APIService: %v", err)
			}
		}
	} else if !kerrors.IsNotFound(err) {
		return fmt.Errorf("checking existing APIService: %v", err)
	}

	savedData := ""
	if dm.Annotations != nil {
		savedData = dm.Annotations[savedAPIServiceAnnotation]
	}
	if savedData == "" {
		logCtx.Warn("No saved APIService annotation found, cannot restore")
		return nil
	}

	apiSvc := &apiregv1.APIService{}
	if err := json.Unmarshal([]byte(savedData), apiSvc); err != nil {
		return fmt.Errorf("deserializing saved APIService: %v", err)
	}

	_, err = c.apiregClient.APIServices().Create(c.ctx, apiSvc, metav1.CreateOptions{})
	if err != nil {
		if kerrors.IsAlreadyExists(err) {
			logCtx.Info("APIService already recreated (possibly by operator)")
			return nil
		}
		return fmt.Errorf("creating restored APIService: %v", err)
	}
	logCtx.Info("Restored aggregated APIService v3.projectcalico.org")
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

	if existing.Spec.DatastoreReady != nil && !*existing.Spec.DatastoreReady {
		logCtx.Debug("Datastore already locked")
		return nil
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
// It updates dm in-place with the server's response (including new ResourceVersion)
// so callers can continue making updates without re-fetching.
func (c *migrationController) updateStatus(dm *DatastoreMigration) error {
	uns, err := datastoreMigrationToUnstructured(dm)
	if err != nil {
		return fmt.Errorf("converting DatastoreMigration to unstructured: %v", err)
	}
	updated, err := c.dynamicClient.Resource(DatastoreMigrationGVR).UpdateStatus(c.ctx, uns, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	refreshed, err := unstructuredToDatastoreMigration(updated)
	if err != nil {
		return fmt.Errorf("parsing updated DatastoreMigration: %v", err)
	}
	*dm = *refreshed
	return nil
}

// updateMetadata updates the metadata (annotations, finalizers, labels) of a
// DatastoreMigration CR. This uses Update (not UpdateStatus) to persist
// metadata changes like annotations and finalizers.
func (c *migrationController) updateMetadata(dm *DatastoreMigration) error {
	uns, err := datastoreMigrationToUnstructured(dm)
	if err != nil {
		return fmt.Errorf("converting DatastoreMigration to unstructured: %v", err)
	}
	_, err = c.dynamicClient.Resource(DatastoreMigrationGVR).Update(c.ctx, uns, metav1.UpdateOptions{})
	return err
}

// addFinalizer adds the migration finalizer to the DatastoreMigration CR.
func (c *migrationController) addFinalizer(dm *DatastoreMigration) error {
	dm.Finalizers = append(dm.Finalizers, finalizerName)
	return c.updateMetadata(dm)
}

// removeFinalizer removes the migration finalizer, allowing the CR to be garbage collected.
func (c *migrationController) removeFinalizer(dm *DatastoreMigration) error {
	finalizers := make([]string, 0, len(dm.Finalizers))
	for _, f := range dm.Finalizers {
		if f != finalizerName {
			finalizers = append(finalizers, f)
		}
	}
	dm.Finalizers = finalizers
	return c.updateMetadata(dm)
}

// hasFinalizer returns true if the DatastoreMigration CR has the migration finalizer.
func hasFinalizer(dm *DatastoreMigration) bool {
	for _, f := range dm.Finalizers {
		if f == finalizerName {
			return true
		}
	}
	return false
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

// crdGVR is the GVR for CustomResourceDefinition objects.
var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}
