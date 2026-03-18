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
	"github.com/sirupsen/logrus"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/discovery"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
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

// ControllerConfig holds all dependencies for creating the migration controller.
type ControllerConfig struct {
	Ctx           context.Context
	K8sClient     kubernetes.Interface
	BackendClient api.Client
	RTClient      rtclient.Client
	DynamicClient dynamic.Interface
	APIRegClient  apiregv1client.ApiregistrationV1Interface
	CRDClient     apiextclient.Interface
}

// NewController creates a new migration controller. It watches for DatastoreMigration CRs
// and drives the v1-to-v3 CRD migration state machine. The returned controller defers
// startup until the DatastoreMigration CRD is installed and Established.
func NewController(cfg ControllerConfig) controller.Controller {
	m := &migrationController{
		ctx:           cfg.Ctx,
		k8sClient:     cfg.K8sClient,
		backendClient: cfg.BackendClient,
		rtClient:      cfg.RTClient,
		dynamicClient: cfg.DynamicClient,
		apiregClient:  cfg.APIRegClient,
	}
	return controller.NewDeferredCRDController(
		"datastoremigrations.migration.projectcalico.org",
		cfg.CRDClient,
		m,
	)
}

// resyncPeriod controls how frequently the informer re-lists all resources.
// This ensures the Converged phase gets periodic re-checks for component
// API group switchover detection.
const resyncPeriod = 60 * time.Second

type migrationController struct {
	ctx           context.Context
	k8sClient     kubernetes.Interface
	backendClient api.Client
	rtClient      rtclient.Client
	dynamicClient dynamic.Interface
	apiregClient  apiregv1client.ApiregistrationV1Interface
	queue         workqueue.TypedRateLimitingInterface[string]
}

// RunWithContext is called by the DeferredCRDController once the DatastoreMigration
// CRD is established. The context is cancelled when the CRD is removed or the
// parent controller is stopped.
func (m *migrationController) RunWithContext(ctx context.Context) {
	logrus.Info("DatastoreMigration CRD established, starting migration controller")
	defer logrus.Info("Stopping migration controller")

	m.ctx = ctx
	m.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	defer m.queue.ShutDown()

	factory := dynamicinformer.NewDynamicSharedInformerFactory(m.dynamicClient, resyncPeriod)
	informer := factory.ForResource(DatastoreMigrationGVR).Informer()

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			m.enqueue(obj)
		},
		UpdateFunc: func(oldObj, newObj any) {
			m.enqueue(newObj)
		},
		DeleteFunc: func(obj any) {
			m.enqueue(obj)
		},
	}
	_, err := informer.AddEventHandler(handler)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to add event handler to informer")
		return
	}

	go informer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		logrus.Error("Failed to sync informer cache")
		return
	}
	logrus.Info("Migration informer cache synced")

	for m.processNextWorkItem() {
	}
}

func (m *migrationController) enqueue(obj any) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		logrus.WithError(err).Error("Failed to get key for object")
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
		if isTerminal(err) {
			logrus.WithError(err).Error("Terminal migration error, setting Failed status")
			m.handleTerminalError(err)
			m.queue.Forget(key)
		} else {
			logrus.WithError(err).Error("Migration reconcile error, will retry")
			m.queue.AddRateLimited(key)
		}
		return true
	}

	m.queue.Forget(key)
	return true
}

// handleTerminalError fetches the current CR and sets it to Failed with the
// error message. If the CR can't be fetched or updated, the error is logged
// but not retried — the next reconcile will pick it up.
func (m *migrationController) handleTerminalError(err error) {
	dm := &DatastoreMigration{}
	if getErr := m.rtClient.Get(m.ctx, types.NamespacedName{Name: defaultMigrationName}, dm); getErr != nil {
		logrus.WithError(getErr).Error("Failed to fetch CR for terminal error status update")
		return
	}
	m.setFailedStatus(dm, err.Error())
	if updateErr := m.updateStatus(dm); updateErr != nil {
		logrus.WithError(updateErr).Error("Failed to update CR status for terminal error")
	}
}

func (m *migrationController) reconcile() error {
	dm := &DatastoreMigration{}
	if err := m.rtClient.Get(m.ctx, types.NamespacedName{Name: defaultMigrationName}, dm); err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting DatastoreMigration: %w", err)
	}

	logCtx := logrus.WithFields(logrus.Fields{
		"name":  dm.Name,
		"phase": dm.Status.Phase,
	})

	// Validate Spec.Type before proceeding.
	if dm.Spec.Type != DatastoreMigrationTypeAPIServerToCRDs {
		return asTerminal(fmt.Errorf("unsupported migration type: %q (only %q is supported)", dm.Spec.Type, DatastoreMigrationTypeAPIServerToCRDs))
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
func (m *migrationController) handlePending(logCtx *logrus.Entry, dm *DatastoreMigration) error {
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
	allMigrators := GetRegistry()
	var forbidden []string
	for _, migrator := range allMigrators {
		_, err := migrator.ListV1(m.ctx)
		if err != nil && kerrors.IsForbidden(err) {
			forbidden = append(forbidden, migrator.Kind())
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
		return asTerminal(fmt.Errorf("no v1 CRDs (crd.projectcalico.org) found — nothing to migrate"))
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
		return asTerminal(fmt.Errorf("APIService v3.projectcalico.org is automanaged (CRD-backed), not aggregated — migration requires an aggregated API server"))
	}

	// Detect install namespace from the serviceaccount namespace file.
	installNamespace := names.OwnNamespace()

	// Detect install type by checking whether the operator API group is registered.
	installType := "manifest"
	if discovery.IsOperatorManaged(m.k8sClient.Discovery()) {
		installType = "operator"
	}
	logCtx.WithFields(logrus.Fields{
		"installNamespace": installNamespace,
		"installType":      installType,
	}).Info("Detected installation details")

	// Pre-check conflicts: detect v3 resources that differ from their v1 source
	// before starting migration. This avoids locking the datastore only to
	// discover conflicts mid-migration.
	conflicts, err := DetectConflicts(m.ctx, allMigrators)
	if err != nil {
		return fmt.Errorf("pre-checking conflicts: %w", err)
	}
	if len(conflicts) > 0 {
		logCtx.WithField("conflicts", len(conflicts)).Warn("Pre-check found conflicts, waiting for resolution before migrating")
		dm.Status.Phase = DatastoreMigrationPhaseWaitingForConflictResolution
		dm.Status.Message = fmt.Sprintf("%d resource conflicts need resolution before migration can begin", len(conflicts))
		dm.Status.Conditions = nil
		for _, ci := range conflicts {
			dm.Status.Conditions = append(dm.Status.Conditions, metav1.Condition{
				Type:               conditionTypeConflict,
				Status:             metav1.ConditionTrue,
				Reason:             conditionReasonResourceMismatch,
				Message:            ci.String(),
				LastTransitionTime: metav1.Now(),
			})
		}
		setPhaseMetric(DatastoreMigrationPhaseWaitingForConflictResolution)
		return m.updateStatus(dm)
	}

	// Transition to Migrating.
	now := metav1.Now()
	dm.Status.Phase = DatastoreMigrationPhaseMigrating
	dm.Status.StartedAt = &now
	setPhaseMetric(DatastoreMigrationPhaseMigrating)
	return m.updateStatus(dm)
}

// handleMigrating runs the core migration logic.
func (m *migrationController) handleMigrating(logCtx *logrus.Entry, dm *DatastoreMigration) error {
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
	allMigrators := GetRegistry()
	sort.Slice(allMigrators, func(i, j int) bool {
		return allMigrators[i].Order() < allMigrators[j].Order()
	})

	var allConflicts []ConflictInfo
	uidMap := make(map[types.UID]types.UID)

	// Initialize progress tracking.
	dm.Status.Progress = DatastoreMigrationProgress{
		TotalTypes:   len(allMigrators),
		TypeProgress: fmt.Sprintf("0 / %d", len(allMigrators)),
		TypeDetails:  make([]TypeMigrationProgress, 0, len(allMigrators)),
	}

	for i, migrator := range allMigrators {
		// Update current-type progress before starting each type.
		dm.Status.Progress.CurrentType = migrator.Kind()
		dm.Status.Progress.CompletedTypes = i
		dm.Status.Progress.TypeProgress = fmt.Sprintf("%d / %d", i, len(allMigrators))
		if err := m.updateStatus(dm); err != nil {
			logCtx.WithError(err).Warn("Failed to update progress status")
		}

		typeStart := time.Now()
		result, err := MigrateResourceType(m.ctx, migrator)
		migrationTypeDuration.WithLabelValues(migrator.Kind()).Observe(time.Since(typeStart).Seconds())
		if err != nil {
			migrationResourceErrors.WithLabelValues(migrator.Kind()).Inc()
			return fmt.Errorf("migrating %s: %w", migrator.Kind(), err)
		}

		migrationResourcesTotal.WithLabelValues(migrator.Kind(), "migrated").Add(float64(result.Migrated))
		migrationResourcesTotal.WithLabelValues(migrator.Kind(), "skipped").Add(float64(result.Skipped))
		migrationResourcesTotal.WithLabelValues(migrator.Kind(), "conflict").Add(float64(len(result.Conflicts)))

		dm.Status.Progress.Migrated += result.Migrated
		dm.Status.Progress.Skipped += result.Skipped
		dm.Status.Progress.Total += result.Migrated + result.Skipped + len(result.Conflicts)
		dm.Status.Progress.Conflicts += len(result.Conflicts)
		dm.Status.Progress.TypeDetails = append(dm.Status.Progress.TypeDetails, TypeMigrationProgress{
			Kind:      migrator.Kind(),
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
	dm.Status.Progress.CompletedTypes = len(allMigrators)
	dm.Status.Progress.TypeProgress = fmt.Sprintf("%d / %d", len(allMigrators), len(allMigrators))
	dm.Status.Progress.CurrentType = ""

	// Second pass: remap OwnerReference UIDs that point to Calico resources.
	if err := RemapOwnerReferences(m.ctx, uidMap, allMigrators); err != nil {
		return fmt.Errorf("remapping OwnerReferences: %w", err)
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
	if err := m.unlockV3CRDDatastore(logCtx); err != nil {
		return err
	}

	return m.updateStatus(dm)
}

// handleWaiting re-checks all previously conflicting resource types by
// re-running CheckConflicts against the registry. If no conflicts remain,
// it transitions back to Migrating to complete the migration.
func (m *migrationController) handleWaiting(logCtx *logrus.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Re-checking conflicts")

	remaining, err := DetectConflicts(m.ctx, GetRegistry())
	if err != nil {
		return fmt.Errorf("re-checking conflicts: %w", err)
	}

	if len(remaining) > 0 {
		logCtx.WithField("conflicts", len(remaining)).Debug("Conflicts still present")
		return nil
	}

	logCtx.Info("All conflicts resolved, transitioning back to Pending for re-validation")
	dm.Status.Conditions = nil
	dm.Status.Phase = DatastoreMigrationPhasePending
	setPhaseMetric(DatastoreMigrationPhasePending)
	return m.updateStatus(dm)
}

// handleConverged waits for all components to switch to the v3 API group
// before transitioning to Complete. It checks the calico-node DaemonSet for
// the CALICO_API_GROUP env var and verifies the rollout is fully complete.
func (m *migrationController) handleConverged(logCtx *logrus.Entry, dm *DatastoreMigration) error {
	ds, err := m.k8sClient.AppsV1().DaemonSets(names.OwnNamespace()).Get(m.ctx, "calico-node", metav1.GetOptions{})
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
		logCtx.WithFields(logrus.Fields{
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
func (m *migrationController) handleDeletion(logCtx *logrus.Entry, dm *DatastoreMigration) error {
	if !hasFinalizer(dm) {
		return nil
	}

	switch dm.Status.Phase {
	case DatastoreMigrationPhaseComplete:
		return m.handleCompletedCleanup(logCtx, dm)
	case DatastoreMigrationPhaseConverged:
		// Once converged, the operator may have started rolling out pods with
		// v3 mode. Aborting is unsafe — the migration must complete from this
		// point. The finalizer blocks deletion until the phase reaches Complete.
		logCtx.Warn("Cannot abort from Converged phase — migration must complete. Waiting for Complete phase.")
		dm.Status.Message = "Deletion blocked: migration is Converged and cannot be rolled back. Wait for migration to complete."
		return m.updateStatus(dm)
	default:
		return m.handleAbort(logCtx, dm)
	}
}

// handleCompletedCleanup deletes v1 CRDs once the DatastoreMigration object
// has been deleted and is finalizing. If this errors, the workqueue will
// re-enqueue the item and retry since the finalizer is still present.
func (m *migrationController) handleCompletedCleanup(logCtx *logrus.Entry, dm *DatastoreMigration) error {
	logCtx.Info("Migration complete, cleaning up v1 CRDs")

	// List all CRDs in the crd.projectcalico.org group and delete them.
	// CRDs are only created by whatever installed them (operator, helm, kubectl);
	// the apiserver does not recreate them after deletion.
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
func (m *migrationController) handleAbort(logCtx *logrus.Entry, dm *DatastoreMigration) error {
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
	ciObj := &apiv3.ClusterInformation{ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName}}
	if err := m.rtClient.Delete(m.ctx, ciObj); err != nil {
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
func (m *migrationController) cleanupPartialV3Resources(logCtx *logrus.Entry) {
	for _, migrator := range GetRegistry() {
		items, err := migrator.ListV3(m.ctx)
		if err != nil {
			logCtx.WithError(err).WithField("kind", migrator.Kind()).Warn("Failed to list v3 resources for cleanup")
			continue
		}
		deleted := 0
		for _, obj := range items {
			// Only delete resources that were created by migration, not
			// pre-existing v3 resources.
			annotations := obj.GetAnnotations()
			if annotations == nil || annotations[migratedByAnnotation] == "" {
				logCtx.WithFields(logrus.Fields{"kind": migrator.Kind(), "name": obj.GetName()}).Debug("Skipping non-migrated v3 resource during cleanup")
				continue
			}
			if err := migrator.DeleteV3(m.ctx, obj); err != nil {
				if !kerrors.IsNotFound(err) {
					logCtx.WithError(err).WithFields(logrus.Fields{"kind": migrator.Kind(), "name": obj.GetName(), "namespace": obj.GetNamespace()}).Warn("Failed to delete v3 resource during abort")
				}
				continue
			}
			deleted++
		}
		if deleted > 0 {
			logCtx.WithFields(logrus.Fields{"kind": migrator.Kind(), "deleted": deleted}).Info("Deleted partial v3 resources")
		}
	}
}

// saveAndDeleteAPIService saves the current APIService to an annotation on the
// DatastoreMigration CR, then deletes it. If the APIService is already gone
// (e.g., controller restarted mid-migration), this is a no-op.
func (m *migrationController) saveAndDeleteAPIService(logCtx *logrus.Entry, dm *DatastoreMigration) error {
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
func (m *migrationController) restoreAPIService(logCtx *logrus.Entry, dm *DatastoreMigration) error {
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
func (m *migrationController) lockDatastore(logCtx *logrus.Entry) error {
	// Read the v1 ClusterInformation to use as the base for the v3 resource.
	v1Key := model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName}
	v1KVP, err := m.backendClient.Get(m.ctx, v1Key, "")
	if err != nil {
		logCtx.WithError(err).Warn("Failed to read v1 ClusterInformation, will create minimal v3 resource")
	}

	// Build the v3 ClusterInformation, copying the full spec from v1 if available.
	ci := &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
		Spec: apiv3.ClusterInformationSpec{
			DatastoreReady: ptr.To(false),
		},
	}
	if v1KVP != nil {
		if v1CI, ok := v1KVP.Value.(*apiv3.ClusterInformation); ok {
			ci.Spec = *v1CI.Spec.DeepCopy()
			ci.Spec.DatastoreReady = ptr.To(false)
		}
	}

	existing := &apiv3.ClusterInformation{}
	err = m.rtClient.Get(m.ctx, types.NamespacedName{Name: clusterInfoName}, existing)
	if err != nil {
		if kerrors.IsNotFound(err) {
			if createErr := m.rtClient.Create(m.ctx, ci); createErr != nil {
				return fmt.Errorf("creating v3 ClusterInformation: %w", createErr)
			}
			logCtx.Info("Created v3 ClusterInformation with DatastoreReady=false")
		} else {
			return fmt.Errorf("getting v3 ClusterInformation: %w", err)
		}
	} else if existing.Spec.DatastoreReady == nil || *existing.Spec.DatastoreReady {
		existing.Spec.DatastoreReady = ptr.To(false)
		if updateErr := m.rtClient.Update(m.ctx, existing); updateErr != nil {
			return fmt.Errorf("updating v3 ClusterInformation: %w", updateErr)
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

// unlockV3CRDDatastore sets DatastoreReady=true on the v3 ClusterInformation,
// signaling components that have switched to v3 to resume normal operation.
//
// The v1 ClusterInformation is intentionally left locked. Components still
// reading v1 (before their rolling update to v3 mode) will see the lock and
// block CNI ADD/DEL operations. This prevents IPAM leaks during the rollout
// window — CNI operations retry until the component restarts with v3 mode,
// at which point they read the unlocked v3 ClusterInformation.
func (m *migrationController) unlockV3CRDDatastore(logCtx *logrus.Entry) error {
	existing := &apiv3.ClusterInformation{}
	if err := m.rtClient.Get(m.ctx, types.NamespacedName{Name: clusterInfoName}, existing); err != nil {
		return fmt.Errorf("getting v3 ClusterInformation for unlock: %w", err)
	}

	existing.Spec.DatastoreReady = ptr.To(true)
	if err := m.rtClient.Update(m.ctx, existing); err != nil {
		return fmt.Errorf("unlocking v3 datastore: %w", err)
	}
	logCtx.Info("Set DatastoreReady=true on v3 ClusterInformation (v1 remains locked)")

	return nil
}

// setV1ClusterInfoReady sets DatastoreReady on the v1 ClusterInformation via the
// libcalico-go backend client. If the v1 resource doesn't exist, this is a no-op.
func (m *migrationController) setV1ClusterInfoReady(logCtx *logrus.Entry, ready bool) error {
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
// The controller-runtime client updates dm in-place with the server's response
// (including new ResourceVersion) so callers can continue making updates.
func (m *migrationController) updateStatus(dm *DatastoreMigration) error {
	return m.rtClient.Status().Update(m.ctx, dm)
}

// updateMetadata updates the metadata (annotations, finalizers, labels) of a
// DatastoreMigration CR. This uses Update (not UpdateStatus) to persist
// metadata changes like annotations and finalizers. The controller-runtime
// client updates dm in-place with the server's response.
func (m *migrationController) updateMetadata(dm *DatastoreMigration) error {
	return m.rtClient.Update(m.ctx, dm)
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
