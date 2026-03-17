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
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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

	// defaultMigrationName is the well-known name of the DatastoreMigration CR.
	defaultMigrationName = "v1-to-v3"

	// apiServiceName is the name of the aggregated APIService for v3.projectcalico.org.
	apiServiceName = "v3.projectcalico.org"

	// clusterInfoName is the well-known name of the ClusterInformation resource.
	clusterInfoName = "default"

	// Condition types used in DatastoreMigration status.
	conditionTypeConflict = "Conflict"
	conditionTypeFailed   = "Failed"

	// Condition reasons used in DatastoreMigration status.
	conditionReasonResourceMismatch = "ResourceMismatch"
	conditionReasonMigrationError   = "MigrationError"
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
		migClient:     newMigrationClient(dynamicClient),
	}
}

// resyncPeriod controls how frequently the informer re-lists all resources.
// This ensures the Converged phase gets periodic re-checks (future-proofing
// for Felix/Typha active-API-group detection).
const resyncPeriod = 60 * time.Second

type migrationController struct {
	ctx           context.Context
	k8sClient     kubernetes.Interface
	backendClient api.Client
	v3Client      calicov3.ProjectcalicoV3Interface
	dynamicClient dynamic.Interface
	apiregClient  apiregv1client.ApiregistrationV1Interface
	migClient     *migrationClient
	queue         workqueue.TypedRateLimitingInterface[string]
}

func (m *migrationController) Run(stop chan struct{}) {
	log.Info("Starting datastore migration controller")
	defer log.Info("Stopping datastore migration controller")

	m.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	defer m.queue.ShutDown()

	factory := dynamicinformer.NewDynamicSharedInformerFactory(m.dynamicClient, resyncPeriod)
	informer := factory.ForResource(DatastoreMigrationGVR).Informer()

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			m.enqueue(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			m.enqueue(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			m.enqueue(obj)
		},
	}
	_, err := informer.AddEventHandler(handler)
	if err != nil {
		log.WithError(err).Fatal("Failed to add event handler to informer")
		return
	}

	ctx, cancel := context.WithCancel(m.ctx)
	defer cancel()

	go informer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		log.Error("Failed to sync informer cache")
		return
	}
	log.Info("Migration informer cache synced")

	go func() {
		<-stop
		cancel()
	}()

	for m.processNextWorkItem() {
	}
}

func (m *migrationController) enqueue(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		log.WithError(err).Error("Failed to get key for object")
		return
	}
	m.queue.Add(key)
}

func (m *migrationController) processNextWorkItem() bool {
	key, shutdown := m.queue.Get()
	if shutdown {
		return false
	}
	defer m.queue.Done(key)

	if err := m.reconcile(); err != nil {
		log.WithError(err).Error("Migration reconcile error")
		m.queue.AddRateLimited(key)
		return true
	}

	m.queue.Forget(key)
	return true
}

func (m *migrationController) reconcile() error {
	dm, err := m.migClient.Get(m.ctx, defaultMigrationName)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting DatastoreMigration: %w", err)
	}

	logCtx := log.WithFields(log.Fields{
		"name":  dm.Name,
		"phase": dm.Status.Phase,
	})

	// Validate Spec.Type before proceeding.
	if dm.Spec.Type != DatastoreMigrationTypeV1ToV3 {
		m.setFailedStatus(dm, fmt.Sprintf("unsupported migration type: %q (only %q is supported)", dm.Spec.Type, DatastoreMigrationTypeV1ToV3))
		return m.updateStatus(dm)
	}

	// If the CR is being deleted, run the finalizer logic.
	if dm.DeletionTimestamp != nil {
		return m.handleDeletion(logCtx, dm)
	}

	switch dm.Status.Phase {
	case "", DatastoreMigrationPhasePending:
		return m.handlePending(logCtx, dm)
	case DatastoreMigrationPhaseMigrating:
		return m.handleMigrating(logCtx, dm)
	case DatastoreMigrationPhaseWaitingForConflictResolution:
		return m.handleWaiting(logCtx, dm)
	case DatastoreMigrationPhaseConverged:
		return m.handleConverged(logCtx, dm)
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
func (m *migrationController) handlePending(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration is pending, validating prerequisites")

	// Add the finalizer if not already present.
	if !hasFinalizer(dm) {
		logCtx.Info("Adding finalizer to DatastoreMigration CR")
		if err := m.addFinalizer(dm); err != nil {
			return fmt.Errorf("adding finalizer: %w", err)
		}
	}

	// Pre-validation: verify we have the RBAC permissions needed for migration.
	// The operator creates the migration ClusterRole asynchronously when it sees
	// this CR, so we may need to wait a reconcile or two for it.
	migrators := GetRegistry()
	var forbidden []string
	for _, migrator := range migrators {
		_, err := migrator.ListV1(m.ctx, m.backendClient)
		if err != nil && kerrors.IsForbidden(err) {
			forbidden = append(forbidden, migrator.Kind)
		}
	}
	if len(forbidden) > 0 {
		logCtx.WithField("kinds", forbidden).Info("Waiting for migration RBAC — cannot list v1 resources for some types")
		dm.Status.Message = "Waiting for migration RBAC permissions"
		return m.updateStatus(dm)
	}

	// Pre-validation: check that v1 CRDs exist.
	crdClient := m.dynamicClient.Resource(crdGVR)
	crdList, err := crdClient.List(m.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing CRDs for pre-validation: %w", err)
	}
	v1CRDCount := 0
	for _, crd := range crdList.Items {
		group, _, _ := unstructured.NestedString(crd.Object, "spec", "group")
		if group == "crd.projectcalico.org" {
			v1CRDCount++
		}
	}
	if v1CRDCount == 0 {
		m.setFailedStatus(dm, "no v1 CRDs (crd.projectcalico.org) found — nothing to migrate")
		return m.updateStatus(dm)
	}
	logCtx.WithField("v1CRDs", v1CRDCount).Info("Found v1 CRDs to migrate")

	// Pre-validation: check the APIService.
	apiSvc, err := m.apiregClient.APIServices().Get(m.ctx, apiServiceName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logCtx.Warn("APIService v3.projectcalico.org not found — may not be running with API server aggregation")
		} else {
			return fmt.Errorf("checking APIService: %w", err)
		}
	} else if apiSvc.Labels != nil && apiSvc.Labels["kube-aggregator.kubernetes.io/automanaged"] == "true" {
		m.setFailedStatus(dm, "APIService v3.projectcalico.org is automanaged (CRD-backed), not aggregated — migration requires an aggregated API server")
		return m.updateStatus(dm)
	}

	// Detect install namespace.
	installNamespace := "kube-system"
	_, err = m.k8sClient.CoreV1().Namespaces().Get(m.ctx, "calico-system", metav1.GetOptions{})
	if err == nil {
		installNamespace = "calico-system"
	}

	// Detect install type (operator vs manifest).
	installType := "manifest"
	for _, ns := range []string{installNamespace, "tigera-operator"} {
		_, err = m.k8sClient.AppsV1().Deployments(ns).Get(m.ctx, "tigera-operator", metav1.GetOptions{})
		if err == nil {
			installType = "operator"
			break
		}
	}
	logCtx.WithFields(log.Fields{
		"installNamespace": installNamespace,
		"installType":      installType,
	}).Info("Detected installation details")

	// Pre-check conflicts: for each registered migrator, list v1 resources, convert,
	// and check if v3 equivalents exist with different specs. Log warnings only.
	migrators = GetRegistry()
	preCheckConflicts := 0
	for _, migrator := range migrators {
		if migrator.ListV1 == nil || migrator.Convert == nil || migrator.GetV3 == nil || migrator.SpecsEqual == nil {
			continue
		}
		v1List, err := migrator.ListV1(m.ctx, m.backendClient)
		if err != nil {
			logCtx.WithError(err).WithField("kind", migrator.Kind).Warn("Failed to list v1 resources for pre-check")
			continue
		}
		for _, kvp := range v1List.KVPairs {
			v3Obj, err := migrator.Convert(kvp)
			if err != nil {
				continue
			}
			existing, err := migrator.GetV3(m.ctx, v3Obj.GetName(), v3Obj.GetNamespace())
			if err != nil || existing == nil {
				continue
			}
			if !migrator.SpecsEqual(v3Obj, existing) {
				preCheckConflicts++
				logCtx.WithFields(log.Fields{
					"kind": migrator.Kind,
					"name": v3Obj.GetName(),
				}).Warn("Pre-check: v3 resource exists with different spec (will be reported as conflict during migration)")
			}
		}
	}
	if preCheckConflicts > 0 {
		logCtx.WithField("preCheckConflicts", preCheckConflicts).Warn("Pre-check found potential conflicts — migration will proceed but conflicts will be reported")
	}

	// Transition to Migrating.
	now := metav1.Now()
	dm.Status.Phase = DatastoreMigrationPhaseMigrating
	dm.Status.StartedAt = &now
	setPhaseMetric(DatastoreMigrationPhaseMigrating)
	return m.updateStatus(dm)
}

// handleMigrating runs the core migration logic.
func (m *migrationController) handleMigrating(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration in progress")
	dm.Status.Message = "Migrating resources"

	// Step 1: Save and delete the APIService to route v3 requests to CRDs.
	if err := m.saveAndDeleteAPIService(logCtx, dm); err != nil {
		return err
	}

	// Step 2: Create v3 ClusterInformation with DatastoreReady=false to lock the datastore.
	if err := m.lockDatastore(logCtx); err != nil {
		return err
	}

	// Step 3: Migrate all resources in order.
	migrators := GetRegistry()
	sort.Slice(migrators, func(i, j int) bool {
		return migrators[i].Order < migrators[j].Order
	})

	var allConflicts []ConflictInfo
	uidMap := make(map[types.UID]types.UID)

	// Initialize progress tracking.
	dm.Status.Progress = DatastoreMigrationProgress{
		TotalTypes:   len(migrators),
		TypeProgress: fmt.Sprintf("0 / %d", len(migrators)),
		TypeDetails:  make([]TypeMigrationProgress, 0, len(migrators)),
	}

	for i, migrator := range migrators {
		// Update current-type progress before starting each type.
		dm.Status.Progress.CurrentType = migrator.Kind
		dm.Status.Progress.CompletedTypes = i
		dm.Status.Progress.TypeProgress = fmt.Sprintf("%d / %d", i, len(migrators))
		if err := m.updateStatus(dm); err != nil {
			logCtx.WithError(err).Warn("Failed to update progress status")
		}

		typeStart := time.Now()
		result, err := MigrateResourceType(m.ctx, m.backendClient, migrator)
		migrationTypeDuration.WithLabelValues(migrator.Kind).Observe(time.Since(typeStart).Seconds())
		if err != nil {
			migrationResourceErrors.WithLabelValues(migrator.Kind).Inc()
			m.setFailedStatus(dm, fmt.Sprintf("failed migrating %s: %v", migrator.Kind, err))
			return m.updateStatus(dm)
		}

		migrationResourcesTotal.WithLabelValues(migrator.Kind, "migrated").Add(float64(result.Migrated))
		migrationResourcesTotal.WithLabelValues(migrator.Kind, "skipped").Add(float64(result.Skipped))
		migrationResourcesTotal.WithLabelValues(migrator.Kind, "conflict").Add(float64(len(result.Conflicts)))

		dm.Status.Progress.Migrated += result.Migrated
		dm.Status.Progress.Skipped += result.Skipped
		dm.Status.Progress.Total += result.Migrated + result.Skipped + len(result.Conflicts)
		dm.Status.Progress.Conflicts += len(result.Conflicts)
		dm.Status.Progress.TypeDetails = append(dm.Status.Progress.TypeDetails, TypeMigrationProgress{
			Kind:      migrator.Kind,
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
	dm.Status.Progress.TypeProgress = fmt.Sprintf("%d / %d", len(migrators), len(migrators))
	dm.Status.Progress.CurrentType = ""

	// Second pass: remap OwnerReference UIDs that point to Calico resources.
	if err := RemapOwnerReferences(m.ctx, uidMap, migrators); err != nil {
		m.setFailedStatus(dm, fmt.Sprintf("failed remapping OwnerReferences: %v", err))
		return m.updateStatus(dm)
	}

	// Update conditions for conflicts.
	dm.Status.Conditions = nil
	for _, ci := range allConflicts {
		dm.Status.Conditions = append(dm.Status.Conditions, metav1.Condition{
			Type:               conditionTypeConflict,
			Status:             metav1.ConditionTrue,
			Reason:             conditionReasonResourceMismatch,
			Message:            ci.String(),
			LastTransitionTime: metav1.Now(),
		})
	}

	if len(allConflicts) > 0 {
		logCtx.WithField("conflicts", len(allConflicts)).Warn("Migration has conflicts that need manual resolution")
		dm.Status.Phase = DatastoreMigrationPhaseWaitingForConflictResolution
		dm.Status.Message = fmt.Sprintf("%d resource conflicts need manual resolution", len(allConflicts))
		setPhaseMetric(DatastoreMigrationPhaseWaitingForConflictResolution)
		return m.updateStatus(dm)
	}

	// Record total migration duration.
	if dm.Status.StartedAt != nil {
		migrationDuration.Observe(time.Since(dm.Status.StartedAt.Time).Seconds())
	}

	// No conflicts — transition to Converged.
	dm.Status.Phase = DatastoreMigrationPhaseConverged
	dm.Status.Message = "Waiting for components to switch to v3 API group"
	setPhaseMetric(DatastoreMigrationPhaseConverged)
	logCtx.Info("Migration converged, unlocking datastore")

	// Step 4: Unlock the datastore.
	if err := m.unlockDatastore(logCtx); err != nil {
		return err
	}

	return m.updateStatus(dm)
}

// handleWaiting re-checks all previously conflicting resource types by
// re-running CheckConflicts against the registry. If no conflicts remain,
// it transitions back to Migrating to complete the migration.
func (m *migrationController) handleWaiting(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Re-checking conflicts")

	migrators := GetRegistry()
	var remaining []ConflictInfo
	for _, migrator := range migrators {
		conflicts, err := CheckConflicts(m.ctx, m.backendClient, migrator)
		if err != nil {
			logCtx.WithError(err).WithField("kind", migrator.Kind).Warn("Failed to check conflicts")
			remaining = append(remaining, ConflictInfo{Kind: migrator.Kind, Name: "unknown (check failed)"})
			continue
		}
		remaining = append(remaining, conflicts...)
	}

	if len(remaining) > 0 {
		logCtx.WithField("conflicts", len(remaining)).Debug("Conflicts still present")
		return nil
	}

	logCtx.Info("All conflicts resolved, transitioning back to Migrating")
	dm.Status.Conditions = nil
	dm.Status.Phase = DatastoreMigrationPhaseMigrating
	setPhaseMetric(DatastoreMigrationPhaseMigrating)
	return m.updateStatus(dm)
}

// handleConverged waits for all components to switch to the v3 API group
// before transitioning to Complete. It checks the calico-node DaemonSet for
// the CALICO_API_GROUP env var and verifies the rollout is fully complete.
func (m *migrationController) handleConverged(logCtx *log.Entry, dm *DatastoreMigration) error {
	ds, err := m.k8sClient.AppsV1().DaemonSets("calico-system").Get(m.ctx, "calico-node", metav1.GetOptions{})
	if err != nil {
		logCtx.WithError(err).Info("Failed to get calico-node DaemonSet, will retry")
		return nil
	}

	// Check if calico-node has been configured with the v3 API group.
	hasV3Env := false
	for _, c := range ds.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == "CALICO_API_GROUP" && e.Value == "projectcalico.org/v3" {
				hasV3Env = true
				break
			}
		}
	}
	if !hasV3Env {
		logCtx.Info("Waiting for calico-node DaemonSet to be configured with CALICO_API_GROUP=projectcalico.org/v3")
		dm.Status.Message = "Waiting for operator to configure calico-node with v3 API group"
		return m.updateStatus(dm)
	}

	// Verify the rollout is complete — all pods running the new template.
	if ds.Status.ObservedGeneration != ds.Generation {
		logCtx.Info("Waiting for calico-node DaemonSet rollout to be observed")
		dm.Status.Message = "Waiting for calico-node rollout to begin"
		return m.updateStatus(dm)
	}
	if ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
		logCtx.WithFields(log.Fields{
			"updatedNumberScheduled": ds.Status.UpdatedNumberScheduled,
			"desiredNumberScheduled": ds.Status.DesiredNumberScheduled,
		}).Info("Waiting for calico-node DaemonSet rollout to complete")
		dm.Status.Message = fmt.Sprintf("Waiting for calico-node rollout (%d/%d updated)", ds.Status.UpdatedNumberScheduled, ds.Status.DesiredNumberScheduled)
		return m.updateStatus(dm)
	}
	if ds.Status.NumberUnavailable > 0 {
		logCtx.WithField("numberUnavailable", ds.Status.NumberUnavailable).Info("Waiting for all calico-node pods to be available")
		dm.Status.Message = fmt.Sprintf("Waiting for calico-node pods to be available (%d unavailable)", ds.Status.NumberUnavailable)
		return m.updateStatus(dm)
	}

	logCtx.Info("All calico-node pods running with v3 API group, transitioning to Complete")
	now := metav1.Now()
	dm.Status.Phase = DatastoreMigrationPhaseComplete
	dm.Status.Message = "Migration complete"
	dm.Status.CompletedAt = &now
	setPhaseMetric(DatastoreMigrationPhaseComplete)
	return m.updateStatus(dm)
}

// handleDeletion runs the finalizer logic when the DatastoreMigration CR is being deleted.
func (m *migrationController) handleDeletion(logCtx *log.Entry, dm *DatastoreMigration) error {
	if !hasFinalizer(dm) {
		return nil
	}

	if dm.Status.Phase == DatastoreMigrationPhaseComplete {
		return m.handleCompletedCleanup(logCtx, dm)
	}
	return m.handleAbort(logCtx, dm)
}

// handleCompletedCleanup deletes v1 CRDs once the DatastoreMigration object
// has been deleted and is finalizing. If this errors, the workqueue will
// re-enqueue the item and retry since the finalizer is still present.
func (m *migrationController) handleCompletedCleanup(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration complete, cleaning up v1 CRDs")

	// List all CRDs in the crd.projectcalico.org group and delete them.
	crdClient := m.dynamicClient.Resource(crdGVR)
	crdList, err := crdClient.List(m.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing CRDs: %w", err)
	}

	deleted := 0
	for _, crd := range crdList.Items {
		group, _, _ := unstructured.NestedString(crd.Object, "spec", "group")
		if group != "crd.projectcalico.org" {
			continue
		}
		logCtx.WithField("crd", crd.GetName()).Info("Deleting v1 CRD")
		if err := crdClient.Delete(m.ctx, crd.GetName(), metav1.DeleteOptions{}); err != nil {
			if !kerrors.IsNotFound(err) {
				return fmt.Errorf("deleting CRD %s: %w", crd.GetName(), err)
			}
		}
		deleted++
	}
	logCtx.WithField("deleted", deleted).Info("Finished deleting v1 CRDs")

	return m.removeFinalizer(dm)
}

// handleAbort restores the cluster to pre-migration state when the CR is deleted
// before migration completes.
func (m *migrationController) handleAbort(logCtx *log.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration incomplete, aborting and restoring pre-migration state")

	// Step 1: Delete partial v3 resources that were created during migration.
	// This is best-effort — the resources become inert once the APIService is
	// restored since nothing reads v3 CRDs in API server mode, but cleaning
	// them up avoids confusion on retry.
	m.cleanupPartialV3Resources(logCtx)

	// Step 2: Restore v1 ClusterInformation to DatastoreReady=true so components
	// reading from crd.projectcalico.org/v1 resume normal operation.
	if err := m.setV1ClusterInfoReady(logCtx, true); err != nil {
		logCtx.WithError(err).Warn("Failed to restore v1 ClusterInformation during abort (may not exist)")
	}

	// Step 3: Delete the v3 ClusterInformation if it was created with
	// DatastoreReady=false, so components don't stay paused after restore.
	if err := m.v3Client.ClusterInformations().Delete(m.ctx, clusterInfoName, metav1.DeleteOptions{}); err != nil {
		if !kerrors.IsNotFound(err) {
			logCtx.WithError(err).Warn("Failed to delete v3 ClusterInformation during abort")
		}
	} else {
		logCtx.Info("Deleted v3 ClusterInformation")
	}

	// Step 4: Restore the aggregated APIService from the saved annotation.
	if err := m.restoreAPIService(logCtx, dm); err != nil {
		logCtx.WithError(err).Error("Failed to restore APIService during abort")
		return fmt.Errorf("restoring APIService: %w", err)
	}

	return m.removeFinalizer(dm)
}

// cleanupPartialV3Resources deletes v3 resources that were created during
// migration. This is best-effort: failures are logged but don't block the abort.
func (m *migrationController) cleanupPartialV3Resources(logCtx *log.Entry) {
	migrators := GetRegistry()
	for _, migrator := range migrators {
		if migrator.ListV3 == nil || migrator.DeleteV3 == nil {
			continue
		}
		v3List, err := migrator.ListV3(m.ctx)
		if err != nil {
			logCtx.WithError(err).WithField("kind", migrator.Kind).Warn("Failed to list v3 resources for cleanup")
			continue
		}
		deleted := 0
		for _, obj := range v3List {
			// Only delete resources that were created by migration, not
			// pre-existing v3 resources.
			annotations := obj.GetAnnotations()
			if annotations == nil || annotations[migratedByAnnotation] == "" {
				continue
			}
			name := obj.GetName()
			ns := obj.GetNamespace()
			if err := migrator.DeleteV3(m.ctx, name, ns); err != nil {
				if !kerrors.IsNotFound(err) {
					logCtx.WithError(err).WithFields(log.Fields{"kind": migrator.Kind, "name": name, "namespace": ns}).Warn("Failed to delete v3 resource during abort")
				}
				continue
			}
			deleted++
		}
		if deleted > 0 {
			logCtx.WithFields(log.Fields{"kind": migrator.Kind, "deleted": deleted}).Info("Deleted partial v3 resources")
		}
	}
}

// saveAndDeleteAPIService saves the current APIService to an annotation on the
// DatastoreMigration CR, then deletes it. If the APIService is already gone
// (e.g., controller restarted mid-migration), this is a no-op.
func (m *migrationController) saveAndDeleteAPIService(logCtx *log.Entry, dm *DatastoreMigration) error {
	apiSvc, err := m.apiregClient.APIServices().Get(m.ctx, apiServiceName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logCtx.Debug("APIService already deleted")
			return nil
		}
		return fmt.Errorf("getting APIService for save: %w", err)
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
			return fmt.Errorf("serializing APIService: %w", err)
		}

		if dm.Annotations == nil {
			dm.Annotations = make(map[string]string)
		}
		dm.Annotations[savedAPIServiceAnnotation] = string(data)
		if err := m.updateMetadata(dm); err != nil {
			return fmt.Errorf("saving APIService annotation: %w", err)
		}
		logCtx.Info("Saved APIService to annotation")
	}

	// Delete the APIService.
	err = m.apiregClient.APIServices().Delete(m.ctx, apiServiceName, metav1.DeleteOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logCtx.Debug("APIService already deleted")
			return nil
		}
		return fmt.Errorf("deleting APIService: %w", err)
	}
	logCtx.Info("Deleted APIService v3.projectcalico.org")
	return nil
}

// restoreAPIService recreates the aggregated APIService from the saved annotation.
func (m *migrationController) restoreAPIService(logCtx *log.Entry, dm *DatastoreMigration) error {
	// Check if an aggregated APIService already exists (e.g., operator recreated it).
	existing, err := m.apiregClient.APIServices().Get(m.ctx, apiServiceName, metav1.GetOptions{})
	if err == nil {
		if existing.Labels == nil || existing.Labels["kube-aggregator.kubernetes.io/automanaged"] != "true" {
			logCtx.Info("Aggregated APIService already exists, skipping restore")
			return nil
		}
		// The existing one is automanaged (CRD-backed). Delete it so we can
		// recreate the aggregated one.
		logCtx.Info("Deleting automanaged APIService to restore aggregated one")
		if err := m.apiregClient.APIServices().Delete(m.ctx, apiServiceName, metav1.DeleteOptions{}); err != nil {
			if !kerrors.IsNotFound(err) {
				return fmt.Errorf("deleting automanaged APIService: %w", err)
			}
		}
	} else if !kerrors.IsNotFound(err) {
		return fmt.Errorf("checking existing APIService: %w", err)
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
		return fmt.Errorf("deserializing saved APIService: %w", err)
	}

	_, err = m.apiregClient.APIServices().Create(m.ctx, apiSvc, metav1.CreateOptions{})
	if err != nil {
		if kerrors.IsAlreadyExists(err) {
			logCtx.Info("APIService already recreated (possibly by operator)")
			return nil
		}
		return fmt.Errorf("creating restored APIService: %w", err)
	}
	logCtx.Info("Restored aggregated APIService v3.projectcalico.org")
	return nil
}

// lockDatastore creates or updates both v3 and v1 ClusterInformation with
// DatastoreReady=false to signal components to pause and retain cached dataplane state.
// When creating the v3 ClusterInformation, it copies the full spec from the v1
// resource so that fields like ClusterGUID, ClusterType, and CalicoVersion are preserved.
func (m *migrationController) lockDatastore(logCtx *log.Entry) error {
	// Read the v1 ClusterInformation to use as the base for the v3 resource.
	ready := false
	v1Key := model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName}
	v1KVP, err := m.backendClient.Get(m.ctx, v1Key, "")
	if err != nil {
		logCtx.WithError(err).Warn("Failed to read v1 ClusterInformation, will create minimal v3 resource")
	}

	// Build the v3 ClusterInformation, copying the full spec from v1 if available.
	ci := &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
		Spec: apiv3.ClusterInformationSpec{
			DatastoreReady: &ready,
		},
	}
	if v1KVP != nil {
		if v1CI, ok := v1KVP.Value.(*apiv3.ClusterInformation); ok {
			ci.Spec = *v1CI.Spec.DeepCopy()
			ci.Spec.DatastoreReady = &ready
		}
	}

	existing, err := m.v3Client.ClusterInformations().Get(m.ctx, clusterInfoName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			_, err = m.v3Client.ClusterInformations().Create(m.ctx, ci, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("creating v3 ClusterInformation: %w", err)
			}
			logCtx.Info("Created v3 ClusterInformation with DatastoreReady=false")
		} else {
			return fmt.Errorf("getting v3 ClusterInformation: %w", err)
		}
	} else if existing.Spec.DatastoreReady == nil || *existing.Spec.DatastoreReady {
		existing.Spec.DatastoreReady = &ready
		_, err = m.v3Client.ClusterInformations().Update(m.ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating v3 ClusterInformation: %w", err)
		}
		logCtx.Info("Set DatastoreReady=false on v3 ClusterInformation")
	} else {
		logCtx.Debug("v3 ClusterInformation already locked")
	}

	// Lock v1 ClusterInformation via the backend client.
	if err := m.setV1ClusterInfoReady(logCtx, false); err != nil {
		logCtx.WithError(err).Warn("Failed to lock v1 ClusterInformation (may not exist)")
	}

	return nil
}

// unlockDatastore sets DatastoreReady=true on the v3 ClusterInformation,
// signaling components that have switched to v3 to resume normal operation.
//
// The v1 ClusterInformation is intentionally left locked. Components still
// reading v1 (before their rolling update to v3 mode) will see the lock and
// block CNI ADD/DEL operations. This prevents IPAM leaks during the rollout
// window — CNI operations retry until the component restarts with v3 mode,
// at which point they read the unlocked v3 ClusterInformation.
func (m *migrationController) unlockDatastore(logCtx *log.Entry) error {
	existing, err := m.v3Client.ClusterInformations().Get(m.ctx, clusterInfoName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting v3 ClusterInformation for unlock: %w", err)
	}

	ready := true
	existing.Spec.DatastoreReady = &ready
	_, err = m.v3Client.ClusterInformations().Update(m.ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("unlocking v3 datastore: %w", err)
	}
	logCtx.Info("Set DatastoreReady=true on v3 ClusterInformation (v1 remains locked)")

	return nil
}

// setV1ClusterInfoReady sets DatastoreReady on the v1 ClusterInformation via the
// libcalico-go backend client. If the v1 resource doesn't exist, this is a no-op.
func (m *migrationController) setV1ClusterInfoReady(logCtx *log.Entry, ready bool) error {
	key := model.ResourceKey{
		Kind: apiv3.KindClusterInformation,
		Name: clusterInfoName,
	}
	kvp, err := m.backendClient.Get(m.ctx, key, "")
	if err != nil {
		return fmt.Errorf("getting v1 ClusterInformation: %w", err)
	}

	ci, ok := kvp.Value.(*apiv3.ClusterInformation)
	if !ok {
		return fmt.Errorf("unexpected type for v1 ClusterInformation: %T", kvp.Value)
	}
	if ci.Spec.DatastoreReady != nil && *ci.Spec.DatastoreReady == ready {
		logCtx.WithField("ready", ready).Debug("v1 ClusterInformation already at desired state")
		return nil
	}

	ci.Spec.DatastoreReady = &ready
	kvp.Value = ci
	_, err = m.backendClient.Update(m.ctx, kvp)
	if err != nil {
		return fmt.Errorf("updating v1 ClusterInformation: %w", err)
	}
	logCtx.WithField("ready", ready).Info("Updated v1 ClusterInformation DatastoreReady")
	return nil
}

func (m *migrationController) setFailedStatus(dm *DatastoreMigration, message string) {
	dm.Status.Phase = DatastoreMigrationPhaseFailed
	setPhaseMetric(DatastoreMigrationPhaseFailed)
	dm.Status.Conditions = append(dm.Status.Conditions, metav1.Condition{
		Type:               conditionTypeFailed,
		Status:             metav1.ConditionTrue,
		Reason:             conditionReasonMigrationError,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// updateStatus updates the status subresource of a DatastoreMigration CR.
// It updates dm in-place with the server's response (including new ResourceVersion)
// so callers can continue making updates without re-fetching.
func (m *migrationController) updateStatus(dm *DatastoreMigration) error {
	refreshed, err := m.migClient.UpdateStatus(m.ctx, dm)
	if err != nil {
		return err
	}
	*dm = *refreshed
	return nil
}

// updateMetadata updates the metadata (annotations, finalizers, labels) of a
// DatastoreMigration CR. This uses Update (not UpdateStatus) to persist
// metadata changes like annotations and finalizers. It updates dm in-place
// with the server's response so callers can continue making updates without
// re-fetching.
func (m *migrationController) updateMetadata(dm *DatastoreMigration) error {
	refreshed, err := m.migClient.Update(m.ctx, dm)
	if err != nil {
		return err
	}
	*dm = *refreshed
	return nil
}

// addFinalizer adds the migration finalizer to the DatastoreMigration CR.
func (m *migrationController) addFinalizer(dm *DatastoreMigration) error {
	dm.Finalizers = append(dm.Finalizers, finalizerName)
	return m.updateMetadata(dm)
}

// removeFinalizer removes the migration finalizer, allowing the CR to be garbage collected.
func (m *migrationController) removeFinalizer(dm *DatastoreMigration) error {
	finalizers := make([]string, 0, len(dm.Finalizers))
	for _, f := range dm.Finalizers {
		if f != finalizerName {
			finalizers = append(finalizers, f)
		}
	}
	dm.Finalizers = finalizers
	return m.updateMetadata(dm)
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

// crdGVR is the GVR for CustomResourceDefinition objects.
var crdGVR = schema.GroupVersionResource{
	Group:    "apiextensions.k8s.io",
	Version:  "v1",
	Resource: "customresourcedefinitions",
}
