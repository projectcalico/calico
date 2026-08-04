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

// Package migration implements the v1-to-v3 CRD migration controller.
package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
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
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
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

	// lockedByAnnotation holds the UID of the DatastoreMigration CR that set
	// DatastoreReady=false on a v3 ClusterInformation it did not create.
	lockedByAnnotation = "migration.projectcalico.org/locked-by"

	// defaultMigrationName is the well-known name of the DatastoreMigration CR.
	defaultMigrationName = "v1-to-v3"

	// apiServiceName is the name of the aggregated APIService for v3.projectcalico.org.
	apiServiceName = "v3.projectcalico.org"

	// clusterInfoName is the well-known name of the ClusterInformation resource.
	clusterInfoName = "default"

	// datastoreMigrationCRDName is the object name of the DatastoreMigration CRD.
	datastoreMigrationCRDName = "datastoremigrations.migration.projectcalico.org"

	// Condition types used in DatastoreMigration status.
	conditionTypeConflict = "Conflict"
	conditionTypeFailed   = "Failed"

	// Condition reasons used in DatastoreMigration status.
	conditionReasonResourceMismatch = "ResourceMismatch"
	conditionReasonMigrationError   = "MigrationError"
	conditionReasonConflictsOmitted = "ConflictsOmitted"

	// maxConflictConditions caps the number of per-resource Conflict conditions
	// emitted to status.conditions. This must stay strictly below the schema's
	// MaxItems (64 in types.go) so the cap here is what's actually hit, not the
	// apiserver rejecting the write.
	maxConflictConditions = 32
)

// ControllerConfig holds all dependencies for creating the migration controller.
type ControllerConfig struct {
	Ctx           context.Context
	K8sClient     kubernetes.Interface
	BackendClient api.Client
	RTClient      rtclient.WithWatch
	DynamicClient dynamic.Interface
	APIRegClient  apiregv1client.ApiregistrationV1Interface
	CRDClient     apiextclient.Interface
	Migrators     []migrators.ResourceMigrator

	// RTClientForVersion returns a client registering DatastoreMigration under the
	// given API version. Optional; RTClient is used as-is when nil.
	RTClientForVersion func(version string) (rtclient.WithWatch, error)

	// WaitingPollInterval controls how frequently the controller re-checks
	// conflicts during WaitingForConflictResolution. Defaults to 10s.
	WaitingPollInterval time.Duration

	// DrainPeriod is how long the controller waits after locking the v1
	// datastore before unregistering the APIService. Defaults to 10s.
	DrainPeriod time.Duration

	// RestartFunc is invoked once the migration reaches Complete in manifest
	// mode so kube-controllers can re-exec and pick up the v3 API group.
	// Defaults to os.Exit(0); tests override this with a no-op so the test
	// binary isn't killed mid-run.
	RestartFunc func()
}

// NewController creates a new migration controller. It watches for DatastoreMigration CRs
// and drives the v1-to-v3 CRD migration state machine. The returned controller defers
// startup until the DatastoreMigration CRD is installed and Established.
func NewController(cfg ControllerConfig) controller.Controller {
	pollInterval := cfg.WaitingPollInterval
	if pollInterval == 0 {
		pollInterval = defaultWaitingPollInterval
	}
	drainPeriod := cfg.DrainPeriod
	if drainPeriod == 0 {
		drainPeriod = defaultDrainPeriod
	}
	restartFunc := cfg.RestartFunc
	if restartFunc == nil {
		restartFunc = func() { os.Exit(0) }
	}
	m := &migrationController{
		ctx:                 cfg.Ctx,
		k8sClient:           cfg.K8sClient,
		backendClient:       cfg.BackendClient,
		rtClient:            cfg.RTClient,
		rtClientForVersion:  cfg.RTClientForVersion,
		dynamicClient:       cfg.DynamicClient,
		apiregClient:        cfg.APIRegClient,
		migrators:           cfg.Migrators,
		waitingPollInterval: pollInterval,
		drainPeriod:         drainPeriod,
		restartFunc:         restartFunc,
	}
	return controller.NewDeferredCRDController(datastoreMigrationCRDName, cfg.CRDClient, m)
}

// resyncPeriod controls how frequently the informer re-lists all resources.
const resyncPeriod = 60 * time.Second

// defaultWaitingPollInterval is how frequently the controller re-checks
// conflicts during WaitingForConflictResolution. Overridable via
// ControllerConfig.WaitingPollInterval for tests.
const defaultWaitingPollInterval = 10 * time.Second

// defaultDrainPeriod is how long the controller waits after locking the v1
// datastore before unregistering the APIService, giving in-flight IPAM
// allocations a chance to finish. Overridable via ControllerConfig.DrainPeriod.
const defaultDrainPeriod = 10 * time.Second

// requeueAfter is returned by reconcile handlers to request a delayed requeue
// without logging an error. Used when the controller is polling external state
// that isn't covered by an informer.
type requeueAfter time.Duration

func (r requeueAfter) Error() string {
	return fmt.Sprintf("requeue after %s", time.Duration(r))
}

type migrationController struct {
	ctx                 context.Context
	k8sClient           kubernetes.Interface
	backendClient       api.Client
	rtClient            rtclient.WithWatch
	rtClientForVersion  func(version string) (rtclient.WithWatch, error)
	dynamicClient       dynamic.Interface
	apiregClient        apiregv1client.ApiregistrationV1Interface
	migrators           []migrators.ResourceMigrator
	waitingPollInterval time.Duration
	drainPeriod         time.Duration
	restartFunc         func()
	queue               workqueue.TypedRateLimitingInterface[string]

	// operatorManaged is true once an Installation CR has been seen. It is not
	// cached while false, since the operator grants the RBAC to read it lazily.
	operatorManaged bool

	// servedVersion is the DatastoreMigration API version this cluster serves,
	// resolved from discovery once the CRD is established.
	servedVersion string
}

// RunWithContext is called by the DeferredCRDController once the DatastoreMigration
// CRD is established. The context is cancelled when the CRD is removed or the
// parent controller is stopped.
func (m *migrationController) RunWithContext(ctx context.Context) {
	logrus.Info("DatastoreMigration CRD established, starting migration controller")
	defer logrus.Info("Stopping migration controller")

	m.ctx = ctx

	logrus.WithField("operatorManaged", m.isOperatorManaged()).Info("Migration controller: detected install type")

	version, versionedClient, err := m.waitForServedAPI(ctx)
	if err != nil {
		logrus.WithError(err).Error("Gave up resolving the served DatastoreMigration API")
		return
	}
	m.servedVersion = version
	m.rtClient = versionedClient
	gvr := migrationv1.DatastoreMigrationGVR
	gvr.Version = version

	if version != migrationv1.Version {
		// Keep watching the pre-GA version so a migration started before the upgrade can still finish.
		logrus.WithField("version", version).Warn("Cluster serves a pre-GA DatastoreMigration API, re-apply the CRD to pick up v1")
	}

	m.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	defer m.queue.ShutDown()

	factory := dynamicinformer.NewDynamicSharedInformerFactory(m.dynamicClient, resyncPeriod)
	informer := factory.ForResource(gvr).Informer()

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
	_, err = informer.AddEventHandler(handler)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to add event handler to informer")
		return
	}

	// Watch DaemonSets and Deployments in the install namespace so changes
	// to calico-node or calico-typha (e.g., setting CALICO_API_GROUP or
	// completing a rollout) trigger a reconcile during the Converged phase.
	appsFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(m.dynamicClient, resyncPeriod, names.OwnNamespace(), nil)
	appsHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ any) { m.queue.Add(defaultMigrationName) },
		UpdateFunc: func(_, _ any) { m.queue.Add(defaultMigrationName) },
		DeleteFunc: func(_ any) { m.queue.Add(defaultMigrationName) },
	}

	dsGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
	dsInformer := appsFactory.ForResource(dsGVR).Informer()
	if _, err = dsInformer.AddEventHandler(appsHandler); err != nil {
		logrus.WithError(err).Fatal("Failed to add DaemonSet event handler")
		return
	}

	deployGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	deployInformer := appsFactory.ForResource(deployGVR).Informer()
	if _, err = deployInformer.AddEventHandler(appsHandler); err != nil {
		logrus.WithError(err).Fatal("Failed to add Deployment event handler")
		return
	}

	go informer.Run(ctx.Done())
	go dsInformer.Run(ctx.Done())
	go deployInformer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced, dsInformer.HasSynced, deployInformer.HasSynced) {
		logrus.Error("Failed to sync informer caches")
		return
	}
	logrus.Info("Migration informer caches synced")

	for m.processNextWorkItem() {
	}
}

func (m *migrationController) enqueue(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
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
		if m.ctx.Err() != nil {
			return false
		}
		var requeue requeueAfter
		if errors.As(err, &requeue) {
			m.queue.Forget(key)
			m.queue.AddAfter(key, time.Duration(requeue))
		} else if isTerminal(err) {
			logrus.WithError(err).Error("Terminal migration error, setting Failed status")
			if statusErr := m.handleTerminalError(err); statusErr != nil {
				// Failed to update status. Retry until we succeed, so that errors properly appear in the API.
				logrus.WithError(statusErr).Error("Failed to record terminal migration error in CR status, will retry")
				m.queue.AddRateLimited(key)
			} else {
				m.queue.Forget(key)
			}
		} else {
			logrus.WithError(err).Error("Migration reconcile error, will retry")
			m.handleRetryableError(err)
			m.queue.AddRateLimited(key)
		}
		return true
	}

	m.queue.Forget(key)
	return true
}

// handleTerminalError fetches the current CR and sets it to Failed with the
// error message. It returns an error if the CR can't be fetched or updated, so
// the caller can retry rather than leaving the failure visible only in the log.
func (m *migrationController) handleTerminalError(err error) error {
	dm := &migrationv1.DatastoreMigration{}
	if getErr := m.rtClient.Get(m.ctx, types.NamespacedName{Name: defaultMigrationName}, dm); getErr != nil {
		return fmt.Errorf("fetching CR for terminal error status update: %w", getErr)
	}
	m.setFailedStatus(dm, err.Error())
	if updateErr := m.updateStatus(dm); updateErr != nil {
		return fmt.Errorf("updating CR status for terminal error: %w", updateErr)
	}
	return nil
}

// handleRetryableError records the error in the CR's status message so a stuck
// migration shows why instead of showing the last progress message forever. The
// phase is left alone since the workqueue will retry.
func (m *migrationController) handleRetryableError(err error) {
	dm := &migrationv1.DatastoreMigration{}
	if getErr := m.rtClient.Get(m.ctx, types.NamespacedName{Name: defaultMigrationName}, dm); getErr != nil {
		logrus.WithError(getErr).Error("Failed to fetch CR for retryable error status update")
		return
	}
	dm.Status.Message = err.Error()
	if updateErr := m.updateStatus(dm); updateErr != nil {
		logrus.WithError(updateErr).Error("Failed to update CR status for retryable error")
	}
}

func (m *migrationController) reconcile() error {
	dm := &migrationv1.DatastoreMigration{}
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
	if dm.Spec.Type != migrationv1.DatastoreMigrationTypeAPIServerToCRDs {
		return asTerminal(fmt.Errorf("unsupported migration type: %q (only %q is supported)", dm.Spec.Type, migrationv1.DatastoreMigrationTypeAPIServerToCRDs))
	}

	// If the CR is being deleted, run the finalizer logic.
	if dm.DeletionTimestamp != nil {
		return m.handleDeletion(logCtx, dm)
	}

	switch dm.Status.Phase {
	case "", migrationv1.DatastoreMigrationPhasePending:
		return m.handlePending(logCtx, dm)
	case migrationv1.DatastoreMigrationPhaseMigrating:
		return m.handleMigrating(logCtx, dm)
	case migrationv1.DatastoreMigrationPhaseWaitingForConflictResolution:
		return m.handleWaiting(logCtx, dm)
	case migrationv1.DatastoreMigrationPhaseConverged:
		return m.handleConverged(logCtx, dm)
	case migrationv1.DatastoreMigrationPhaseComplete:
		logCtx.Debug("Migration already complete")
		return nil
	case migrationv1.DatastoreMigrationPhaseFailed:
		logCtx.Debug("Migration has failed, no further action")
		return nil
	default:
		return fmt.Errorf("unknown migration phase: %s", dm.Status.Phase)
	}
}

// conflictConditions builds the Conflict conditions for status.conditions from
// a list of detected conflicts, capped at maxConflictConditions. When conflicts
// is longer than that, a final condition summarizes the remainder so the true
// count isn't lost from the conditions list (dm.Status.Message separately
// carries the full total).
func conflictConditions(conflicts []ConflictInfo) []metav1.Condition {
	if len(conflicts) == 0 {
		return nil
	}

	now := metav1.Now()
	n := min(len(conflicts), maxConflictConditions)

	conditions := make([]metav1.Condition, 0, n+1)
	for _, ci := range conflicts[:n] {
		conditions = append(conditions, metav1.Condition{
			Type:               conditionTypeConflict,
			Status:             metav1.ConditionTrue,
			Reason:             conditionReasonResourceMismatch,
			Message:            ci.String(),
			LastTransitionTime: now,
		})
	}

	if omitted := len(conflicts) - n; omitted > 0 {
		noun := "conflicts"
		if omitted == 1 {
			noun = "conflict"
		}
		conditions = append(conditions, metav1.Condition{
			Type:               conditionTypeConflict,
			Status:             metav1.ConditionTrue,
			Reason:             conditionReasonConflictsOmitted,
			Message:            fmt.Sprintf("%d more %s not shown", omitted, noun),
			LastTransitionTime: now,
		})
	}

	return conditions
}

// handlePending validates prerequisites, locks the v1 datastore, unregisters the
// APIService, and transitions to Migrating.
func (m *migrationController) handlePending(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
	logCtx.Info("Migration is pending, validating prerequisites")

	if err := m.refusePreGAVersion(); err != nil {
		return err
	}

	// Checked before the finalizer is added so a CR that can never migrate
	// never reaches the abort path.
	v1CRDCount, err := m.countV1CRDs()
	if err != nil {
		return err
	}
	if v1CRDCount == 0 {
		return asTerminal(fmt.Errorf("no v1 CRDs (crd.projectcalico.org) found - nothing to migrate"))
	}
	logCtx.WithField("v1CRDs", v1CRDCount).Info("Found v1 CRDs to migrate")

	// Add the finalizer if not already present.
	if !hasFinalizer(dm) {
		logCtx.Info("Adding finalizer to DatastoreMigration CR")
		if err := m.addFinalizer(dm); err != nil {
			return fmt.Errorf("adding finalizer: %w", err)
		}
	}

	// Prechecks ran on the pass that took the lock, so skip them when we
	// re-enter Pending after the drain requeue.
	if dm.Status.DatastoreLockedAt == nil {
		wait, err := m.runPendingPrechecks(logCtx, dm)
		if err != nil || wait {
			return err
		}

		// Lock v1 before the APIService goes away. Otherwise v3 resolves to
		// empty CRDs while components still believe the datastore is writable.
		if err := m.lockV1Datastore(logCtx); err != nil {
			return err
		}
		now := metav1.Now()
		dm.Status.DatastoreLockedAt = &now
		dm.Status.Message = "Waiting for in-flight datastore writes to drain"
		if err := m.updateStatus(dm); err != nil {
			return err
		}
	}

	// Give in-flight IPAM allocations time to land in v1 before the aggregated
	// API server is unregistered.
	if remaining := m.drainPeriod - time.Since(dm.Status.DatastoreLockedAt.Time); remaining > 0 {
		logCtx.WithField("remaining", remaining).Info("Draining in-flight datastore writes")
		return requeueAfter(remaining)
	}

	// Save and delete the APIService to unregister the API server. This will
	// route future requests to the projectcalico.org/v3 API to CRDs instead.
	if err := m.saveAndDeleteAPIService(logCtx, dm); err != nil {
		return err
	}

	// Pre-check conflicts: detect v3 resources that differ from their v1 source
	// before starting migration. This avoids migrating into a datastore that
	// needs manual reconciliation first.
	conflicts, err := DetectConflicts(m.ctx, m.migrators)
	if err != nil {
		return fmt.Errorf("pre-checking conflicts: %w", err)
	}
	if len(conflicts) > 0 {
		logCtx.WithField("conflicts", len(conflicts)).Warn("Pre-check found conflicts, datastore stays locked until they are resolved")
		dm.Status.Phase = migrationv1.DatastoreMigrationPhaseWaitingForConflictResolution
		dm.Status.Message = fmt.Sprintf("Datastore is locked: resolve %d resource conflicts to let the migration continue", len(conflicts))
		dm.Status.Conditions = conflictConditions(conflicts)
		setPhaseMetric(migrationv1.DatastoreMigrationPhaseWaitingForConflictResolution)
		return m.updateStatus(dm)
	}

	// Transition to Migrating.
	now := metav1.Now()
	dm.Status.Phase = migrationv1.DatastoreMigrationPhaseMigrating
	dm.Status.StartedAt = &now
	setPhaseMetric(migrationv1.DatastoreMigrationPhaseMigrating)
	return m.updateStatus(dm)
}

// countV1CRDs returns the number of installed CRDs in the crd.projectcalico.org group.
func (m *migrationController) countV1CRDs() (int, error) {
	crdList, err := m.dynamicClient.Resource(crdGVR).List(m.ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("listing CRDs for pre-validation: %w", err)
	}
	count := 0
	for _, crd := range crdList.Items {
		group, _, _ := unstructured.NestedString(crd.Object, "spec", "group")
		if group == "crd.projectcalico.org" {
			count++
		}
	}
	return count, nil
}

// runPendingPrechecks validates the prerequisites for starting a migration. It
// returns true if the controller should wait for the cluster to catch up, in
// which case the CR status has already been updated.
func (m *migrationController) runPendingPrechecks(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) (bool, error) {
	// The operator creates the migration ClusterRole asynchronously when it sees
	// this CR, so we may need to wait a reconcile or two for it.
	var forbidden []string
	for _, migrator := range m.migrators {
		_, err := migrator.ListV1(m.ctx)
		if err != nil && kerrors.IsForbidden(err) {
			forbidden = append(forbidden, migrator.Kind())
		}
	}
	if len(forbidden) > 0 {
		logCtx.WithField("kinds", forbidden).Info("Waiting for migration RBAC - cannot list v1 resources for some types")
		dm.Status.Message = "Waiting for migration RBAC permissions"
		return true, m.updateStatus(dm)
	}

	// A missing or automanaged (CRD-backed) APIService is fine. It just means
	// there's no aggregated API server to unregister.
	apiSvc, err := m.apiregClient.APIServices().Get(m.ctx, apiServiceName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			logCtx.Info("No APIService v3.projectcalico.org found - no aggregated API server to unregister")
		} else {
			return false, fmt.Errorf("checking APIService: %w", err)
		}
	} else if apiSvc.Labels != nil && apiSvc.Labels["kube-aggregator.kubernetes.io/automanaged"] == "true" {
		logCtx.Info("APIService v3.projectcalico.org is CRD-backed (v3 CRDs already installed)")
	}

	installType := "manifest"
	if m.isOperatorManaged() {
		installType = "operator"
	}
	logCtx.WithFields(logrus.Fields{
		"installNamespace": names.OwnNamespace(),
		"installType":      installType,
	}).Info("Detected installation details")

	if err := m.ensureV3CRDs(logCtx); err != nil {
		return false, err
	}

	drift, err := m.checkBuiltInTiers()
	if err != nil {
		return false, fmt.Errorf("validating built-in tiers: %w", err)
	}
	if len(drift) > 0 {
		logCtx.WithField("tiers", drift).Warn("Built-in tiers do not match the values the v3 API enforces")
		dm.Status.Message = fmt.Sprintf("Correct the following v1 tiers before migration can start: %s", strings.Join(drift, "; "))
		return true, m.updateStatus(dm)
	}

	return false, nil
}

// builtInTierRequirement is the order and default action that the v3 Tier CRD's
// CEL rules pin a built-in tier to.
type builtInTierRequirement struct {
	order         float64
	defaultAction apiv3.Action
}

var builtInTierRequirements = map[string]builtInTierRequirement{
	names.DefaultTierName:      {order: apiv3.DefaultTierOrder, defaultAction: apiv3.Deny},
	names.KubeAdminTierName:    {order: apiv3.KubeAdminTierOrder, defaultAction: apiv3.Pass},
	names.KubeBaselineTierName: {order: apiv3.KubeBaselineTierOrder, defaultAction: apiv3.Pass},
}

// checkBuiltInTiers returns a description of every built-in tier in v1 that the
// v3 API would reject.
func (m *migrationController) checkBuiltInTiers() ([]string, error) {
	var tierMigrator migrators.ResourceMigrator
	for _, mig := range m.migrators {
		if mig.Kind() == apiv3.KindTier {
			tierMigrator = mig
			break
		}
	}
	if tierMigrator == nil {
		return nil, nil
	}

	tiers, err := tierMigrator.ListV1(m.ctx)
	if err != nil {
		return nil, fmt.Errorf("listing v1 tiers: %w", err)
	}

	var drift []string
	for _, obj := range tiers {
		tier, ok := obj.(*apiv3.Tier)
		if !ok {
			return nil, fmt.Errorf("unexpected type for v1 Tier: %T", obj)
		}
		want, builtIn := builtInTierRequirements[tier.Name]
		if !builtIn {
			continue
		}

		if tier.Spec.Order == nil {
			drift = append(drift, fmt.Sprintf("tier %q has no order, expected %s", tier.Name, formatTierOrder(want.order)))
		} else if *tier.Spec.Order != want.order {
			drift = append(drift, fmt.Sprintf("tier %q has order %s, expected %s", tier.Name, formatTierOrder(*tier.Spec.Order), formatTierOrder(want.order)))
		}

		// The v3 CRD defaults an unset defaultAction to Deny, so an unset value
		// is only conformant on the default tier.
		action := apiv3.Deny
		if tier.Spec.DefaultAction != nil {
			action = *tier.Spec.DefaultAction
		}
		if action != want.defaultAction {
			drift = append(drift, fmt.Sprintf("tier %q has defaultAction %q, expected %q", tier.Name, action, want.defaultAction))
		}
	}
	sort.Strings(drift)
	return drift, nil
}

// formatTierOrder renders a tier order without scientific notation, which %v
// would produce for the large built-in values.
func formatTierOrder(order float64) string {
	return strconv.FormatFloat(order, 'f', -1, 64)
}

// handleMigrating runs the core migration logic.
func (m *migrationController) handleMigrating(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
	logCtx.Info("Migration in progress")
	dm.Status.Message = "Migrating resources"

	// Step 1: Lock v1 first, in case we resumed into Migrating without Pending
	// having taken the lock.
	if err := m.lockV1Datastore(logCtx); err != nil {
		return err
	}

	// Step 2: Save and delete the APIService so v3 requests route to CRDs.
	// Repeated in case we resumed.
	if err := m.saveAndDeleteAPIService(logCtx, dm); err != nil {
		return err
	}

	// Step 3: Lock v3. This has to come after the APIService delete, since the
	// aggregated API server rejects ClusterInformation creates.
	if err := m.lockV3Datastore(logCtx, dm); err != nil {
		return err
	}

	// Step 4: Migrate all resources in order.
	allMigrators := m.migrators
	sort.Slice(allMigrators, func(i, j int) bool {
		return allMigrators[i].Order() < allMigrators[j].Order()
	})

	var allConflicts []ConflictInfo
	var objectsNeedingRemap []rtclient.Object
	uidMap := make(map[types.UID]types.UID)

	// Initialize progress tracking.
	dm.Status.Progress = migrationv1.DatastoreMigrationProgress{
		TotalTypes:   int32(len(allMigrators)),
		TypeProgress: fmt.Sprintf("0 / %d", len(allMigrators)),
		TypeDetails:  make([]migrationv1.TypeMigrationProgress, 0, len(allMigrators)),
	}

	for i, migrator := range allMigrators {
		// Update current-type progress before starting each type.
		dm.Status.Progress.CurrentType = migrator.Kind()
		dm.Status.Progress.CompletedTypes = int32(i)
		dm.Status.Progress.TypeProgress = fmt.Sprintf("%d / %d", i, len(allMigrators))
		if err := m.updateStatus(dm); err != nil {
			logCtx.WithError(err).Warn("Failed to update progress status")
		}

		typeStart := time.Now()
		result, err := MigrateResourceType(m.ctx, migrator, string(dm.UID))
		migrationTypeDuration.WithLabelValues(migrator.Kind()).Observe(time.Since(typeStart).Seconds())
		if err != nil {
			migrationResourceErrors.WithLabelValues(migrator.Kind()).Inc()
			return fmt.Errorf("migrating %s: %w", migrator.Kind(), err)
		}

		migrationResourcesTotal.WithLabelValues(migrator.Kind(), "migrated").Add(float64(result.Migrated))
		migrationResourcesTotal.WithLabelValues(migrator.Kind(), "skipped").Add(float64(result.Skipped))
		migrationResourcesTotal.WithLabelValues(migrator.Kind(), "conflict").Add(float64(len(result.Conflicts)))

		dm.Status.Progress.Migrated += int32(result.Migrated)
		dm.Status.Progress.Skipped += int32(result.Skipped)
		dm.Status.Progress.Total += int32(result.Migrated + result.Skipped + len(result.Conflicts))
		dm.Status.Progress.Conflicts += int32(len(result.Conflicts))
		dm.Status.Progress.TypeDetails = append(dm.Status.Progress.TypeDetails, migrationv1.TypeMigrationProgress{
			Kind:      migrator.Kind(),
			Migrated:  int32(result.Migrated),
			Skipped:   int32(result.Skipped),
			Conflicts: int32(len(result.Conflicts)),
		})

		allConflicts = append(allConflicts, result.Conflicts...)
		objectsNeedingRemap = append(objectsNeedingRemap, result.ObjectsWithCalicoOwnerRefs...)
		for oldUID, newUID := range result.UIDMapping {
			uidMap[oldUID] = newUID
		}
	}

	// Mark all types complete.
	dm.Status.Progress.CompletedTypes = int32(len(allMigrators))
	dm.Status.Progress.TypeProgress = fmt.Sprintf("%d / %d", len(allMigrators), len(allMigrators))
	dm.Status.Progress.CurrentType = ""

	// Second pass: remap OwnerReference UIDs on objects collected during migration.
	if err := RemapOwnerReferences(m.ctx, uidMap, objectsNeedingRemap, m.rtClient.Update); err != nil {
		return fmt.Errorf("remapping OwnerReferences: %w", err)
	}

	// Update conditions for conflicts.
	dm.Status.Conditions = conflictConditions(allConflicts)

	if len(allConflicts) > 0 {
		logCtx.WithField("conflicts", len(allConflicts)).Warn("Migration has conflicts, datastore stays locked until they are resolved")
		dm.Status.Phase = migrationv1.DatastoreMigrationPhaseWaitingForConflictResolution
		dm.Status.Message = fmt.Sprintf("Datastore is locked: resolve %d resource conflicts to let the migration continue", len(allConflicts))
		setPhaseMetric(migrationv1.DatastoreMigrationPhaseWaitingForConflictResolution)
		return m.updateStatus(dm)
	}

	// Record total migration duration.
	if dm.Status.StartedAt != nil {
		migrationDuration.Observe(time.Since(dm.Status.StartedAt.Time).Seconds())
	}

	// No conflicts — transition to Converged.
	dm.Status.Phase = migrationv1.DatastoreMigrationPhaseConverged
	dm.Status.Message = "Waiting for components to switch to v3 API group"
	setPhaseMetric(migrationv1.DatastoreMigrationPhaseConverged)
	logCtx.Info("Migration converged, unlocking datastore")

	// Step 5: Unlock the datastore.
	if err := m.unlockV3CRDDatastore(logCtx); err != nil {
		return err
	}

	return m.updateStatus(dm)
}

// handleWaiting re-checks all previously conflicting resource types by
// re-running CheckConflicts against the registry. If no conflicts remain,
// it transitions back to Migrating to complete the migration.
func (m *migrationController) handleWaiting(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
	logCtx.Info("Re-checking conflicts")

	remaining, err := DetectConflicts(m.ctx, m.migrators)
	if err != nil {
		return fmt.Errorf("re-checking conflicts: %w", err)
	}

	if len(remaining) > 0 {
		logCtx.WithField("conflicts", len(remaining)).Debug("Conflicts still present")
		dm.Status.Message = fmt.Sprintf("Datastore is locked: resolve %d resource conflicts to let the migration continue", len(remaining))
		dm.Status.Conditions = conflictConditions(remaining)

		// The poll cadence here is deliberate: this path is polling for the user
		// to resolve conflicts, and exponential backoff would delay detection of
		// that resolution by many minutes. A failed status write is surfaced in
		// the log instead of via the return value.
		if err := m.updateStatus(dm); err != nil {
			logCtx.WithError(err).Error("Failed to update conflict status, will retry")
		}
		return requeueAfter(m.waitingPollInterval)
	}

	logCtx.Info("All conflicts resolved, transitioning back to Pending for re-validation")
	dm.Status.Conditions = nil
	dm.Status.Phase = migrationv1.DatastoreMigrationPhasePending
	setPhaseMetric(migrationv1.DatastoreMigrationPhasePending)
	return m.updateStatus(dm)
}

// handleConverged waits for all components to switch to the v3 API group
// before transitioning to Complete. It checks calico-node and calico-typha
// (if present) for the CALICO_API_GROUP env var and verifies the calico-node
// rollout is fully complete.
func (m *migrationController) handleConverged(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
	ns := names.OwnNamespace()

	// Check calico-node and typha (if present) for v3 API group configuration.
	componentsToCheck := []string{"calico-node"}
	typhaDeploy, err := m.k8sClient.AppsV1().Deployments(ns).Get(m.ctx, "calico-typha", metav1.GetOptions{})
	if err != nil && !kerrors.IsNotFound(err) && !kerrors.IsForbidden(err) {
		logCtx.WithError(err).Info("Failed to check for calico-typha Deployment, will retry")
		return requeueAfter(m.waitingPollInterval)
	}
	if err == nil {
		componentsToCheck = append(componentsToCheck, "calico-typha")
	}

	// Check each component for the v3 API group env var.
	var needV3 []string
	for _, name := range componentsToCheck {
		var podSpec *corev1.PodSpec
		if name == "calico-node" {
			ds, getErr := m.k8sClient.AppsV1().DaemonSets(ns).Get(m.ctx, name, metav1.GetOptions{})
			if getErr != nil {
				logCtx.WithError(getErr).WithField("component", name).Info("Failed to get DaemonSet, will retry")
				return requeueAfter(m.waitingPollInterval)
			}
			podSpec = &ds.Spec.Template.Spec
		} else if typhaDeploy != nil {
			podSpec = &typhaDeploy.Spec.Template.Spec
		}
		if podSpec != nil && !hasV3APIGroupEnv(podSpec) {
			needV3 = append(needV3, name)
		}
	}
	if len(needV3) > 0 {
		logCtx.WithField("components", needV3).Info("Waiting for components to be configured with v3 API group")
		if m.isOperatorManaged() {
			dm.Status.Message = fmt.Sprintf("Waiting for operator to configure %s with v3 API group", joinComponents(needV3))
		} else {
			dm.Status.Message = fmt.Sprintf("Waiting for user to set CALICO_API_GROUP=projectcalico.org/v3 on %s", joinComponents(needV3))
		}
		return m.updateStatus(dm)
	}

	// Verify calico-node rollout is complete.
	ds, err := m.k8sClient.AppsV1().DaemonSets(ns).Get(m.ctx, "calico-node", metav1.GetOptions{})
	if err != nil {
		return requeueAfter(m.waitingPollInterval)
	}
	if ds.Status.ObservedGeneration != ds.Generation {
		dm.Status.Message = "Waiting for calico-node rollout to begin"
		return m.updateStatus(dm)
	}
	if ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
		dm.Status.Message = fmt.Sprintf("Waiting for calico-node rollout (%d/%d updated)", ds.Status.UpdatedNumberScheduled, ds.Status.DesiredNumberScheduled)
		return m.updateStatus(dm)
	}
	if ds.Status.NumberUnavailable > 0 {
		dm.Status.Message = fmt.Sprintf("Waiting for calico-node pods to be available (%d unavailable)", ds.Status.NumberUnavailable)
		return m.updateStatus(dm)
	}

	logCtx.Info("All components running with v3 API group, transitioning to Complete")
	now := metav1.Now()
	dm.Status.Phase = migrationv1.DatastoreMigrationPhaseComplete
	dm.Status.Message = "Migration complete"
	dm.Status.CompletedAt = &now
	setPhaseMetric(migrationv1.DatastoreMigrationPhaseComplete)
	if err := m.updateStatus(dm); err != nil {
		return err
	}

	// In manifest mode, restart so kube-controllers re-discovers the v3 API
	// group on startup. In operator mode, the operator handles the restart.
	// Skip the restart if the CR is being deleted - let the finalizer finish
	// cleanup first.
	if !m.isOperatorManaged() && dm.DeletionTimestamp == nil {
		logCtx.Info("Migration complete, restarting kube-controllers to pick up v3 API group")
		m.restartFunc()
	}
	return nil
}

// handleDeletion runs the finalizer logic when the DatastoreMigration CR is being deleted.
func (m *migrationController) handleDeletion(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
	if !hasFinalizer(dm) {
		return nil
	}

	switch dm.Status.Phase {
	case migrationv1.DatastoreMigrationPhaseComplete:
		dm.Status.Message = "Cleaning up v1 CRDs"
		if err := m.updateStatus(dm); err != nil {
			logCtx.WithError(err).Warn("Failed to update status message")
		}
		return m.handleCompletedCleanup(logCtx, dm)
	case migrationv1.DatastoreMigrationPhaseConverged:
		// Once converged, the operator may have started rolling out pods with
		// v3 mode. Aborting is unsafe — continue driving toward Complete so
		// the finalizer can run the completed cleanup path.
		logCtx.Warn("Cannot abort from Converged phase — continuing toward Complete")
		dm.Status.Message = "Deletion pending: migration is Converged and cannot be rolled back. Waiting for completion."
		if err := m.updateStatus(dm); err != nil {
			return err
		}
		return m.handleConverged(logCtx, dm)
	default:
		return m.handleAbort(logCtx, dm)
	}
}

// handleCompletedCleanup deletes v1 CRDs once the DatastoreMigration object
// has been deleted and is finalizing. If this errors, the workqueue will
// re-enqueue the item and retry since the finalizer is still present.
func (m *migrationController) handleCompletedCleanup(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
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
func (m *migrationController) handleAbort(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
	logCtx.Info("Migration incomplete, aborting and restoring pre-migration state")

	if dm.Status.StartedAt == nil {
		// Only the Migrating phase creates v3 resources and locks v1, so steps 1
		// and 2 have nothing to undo.
		logCtx.Info("Migration never started, skipping v3 resource cleanup and v1 ClusterInformation restore")
	} else {
		// Step 1: Delete v3 resources created during migration. Best-effort, since
		// they go inert once the APIService is restored.
		m.cleanupPartialV3Resources(logCtx, dm)

		// Step 2: Restore v1 ClusterInformation to DatastoreReady=true so components
		// reading from crd.projectcalico.org/v1 resume normal operation.
		// This is the only unlock: nothing on the success path clears the v1 lock,
		// so giving up here leaves the datastore locked with no CR left to retry from.
		if err := m.setV1ClusterInfoReady(logCtx, true); err != nil {
			var doesNotExist cerrors.ErrorResourceDoesNotExist
			if !errors.As(err, &doesNotExist) {
				return fmt.Errorf("restoring v1 ClusterInformation: %w", err)
			}
			logCtx.WithError(err).Info("No v1 ClusterInformation to restore")
		}
	}

	// Step 3: Undo whatever this migration did to the v3 ClusterInformation.
	m.restoreV3ClusterInfo(logCtx, dm)

	// Step 4: Restore the aggregated APIService from the saved annotation.
	if err := m.restoreAPIService(logCtx, dm); err != nil {
		logCtx.WithError(err).Error("Failed to restore APIService during abort")
		return fmt.Errorf("restoring APIService: %w", err)
	}

	return m.removeFinalizer(dm)
}

// cleanupPartialV3Resources deletes v3 resources that this migration created.
// This is best-effort: failures are logged but don't block the abort.
func (m *migrationController) cleanupPartialV3Resources(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) {
	migrationID := string(dm.UID)
	if migrationID == "" {
		logCtx.Warn("DatastoreMigration has no UID, skipping v3 resource cleanup")
		return
	}

	for _, migrator := range m.migrators {
		items, err := migrator.ListV3(m.ctx)
		if err != nil {
			logCtx.WithError(err).WithField("kind", migrator.Kind()).Warn("Failed to list v3 resources for cleanup")
			continue
		}
		deleted := 0
		for _, obj := range items {
			// Skip resources this migration didn't create, including ones left
			// behind by an earlier migration of the same cluster.
			if obj.GetAnnotations()[migratedByAnnotation] != migrationID {
				logCtx.WithFields(logrus.Fields{"kind": migrator.Kind(), "name": obj.GetName()}).Debug("Skipping v3 resource not created by this migration")
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

// restoreV3ClusterInfo reverses lockV3Datastore: delete the v3 ClusterInformation
// this migration created, unlock one it locked, leave anything else alone.
func (m *migrationController) restoreV3ClusterInfo(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) {
	migrationID := string(dm.UID)
	if migrationID == "" {
		logCtx.Warn("DatastoreMigration has no UID, leaving v3 ClusterInformation alone")
		return
	}

	ci := &apiv3.ClusterInformation{}
	if err := m.rtClient.Get(m.ctx, types.NamespacedName{Name: clusterInfoName}, ci); err != nil {
		if !kerrors.IsNotFound(err) {
			logCtx.WithError(err).Warn("Failed to read v3 ClusterInformation during abort")
		}
		return
	}

	switch {
	case ci.Annotations[migratedByAnnotation] == migrationID:
		if err := m.rtClient.Delete(m.ctx, ci); err != nil && !kerrors.IsNotFound(err) {
			logCtx.WithError(err).Warn("Failed to delete v3 ClusterInformation during abort")
			return
		}
		logCtx.Info("Deleted v3 ClusterInformation created by this migration")
	case ci.Annotations[lockedByAnnotation] == migrationID:
		delete(ci.Annotations, lockedByAnnotation)
		ci.Spec.DatastoreReady = ptr.To(true)
		if err := m.rtClient.Update(m.ctx, ci); err != nil {
			logCtx.WithError(err).Warn("Failed to unlock v3 ClusterInformation during abort")
			return
		}
		logCtx.Info("Set DatastoreReady=true on v3 ClusterInformation locked by this migration")
	default:
		logCtx.Info("v3 ClusterInformation was not created or locked by this migration, leaving it alone")
	}
}

// saveAndDeleteAPIService saves the current APIService to an annotation on the
// DatastoreMigration CR, then deletes it. If the APIService is already gone
// (e.g., controller restarted mid-migration), this is a no-op.
func (m *migrationController) saveAndDeleteAPIService(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
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
func (m *migrationController) restoreAPIService(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
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

// lockV1Datastore sets DatastoreReady=false on the v1 ClusterInformation, so
// components pause and retain cached dataplane state. Every failure here,
// including not-found, has to be retried: migrating while v1 is still writable
// loses the IPAM allocations CNI makes in the meantime.
func (m *migrationController) lockV1Datastore(logCtx *logrus.Entry) error {
	if err := m.setV1ClusterInfoReady(logCtx, false); err != nil {
		return fmt.Errorf("locking v1 ClusterInformation: %w", err)
	}
	return nil
}

// lockV3Datastore creates or updates the v3 ClusterInformation with
// DatastoreReady=false. On create it copies the full spec from the v1 resource
// so fields like ClusterGUID, ClusterType, and CalicoVersion are preserved.
func (m *migrationController) lockV3Datastore(logCtx *logrus.Entry, dm *migrationv1.DatastoreMigration) error {
	// Read the v1 ClusterInformation to use as the base for the v3 resource.
	v1Key := model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName}
	v1KVP, err := m.backendClient.Get(m.ctx, v1Key, "")
	if err != nil {
		logCtx.WithError(err).Warn("Failed to read v1 ClusterInformation, will create minimal v3 resource")
	}

	// Build the v3 ClusterInformation, copying the full spec from v1 if available.
	ci := &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{
			Name:        clusterInfoName,
			Annotations: map[string]string{migratedByAnnotation: string(dm.UID)},
		},
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
		// The resource pre-dates this migration, so abort must unlock it rather
		// than delete it.
		if existing.Annotations == nil {
			existing.Annotations = map[string]string{}
		}
		existing.Annotations[lockedByAnnotation] = string(dm.UID)

		existing.Spec.DatastoreReady = ptr.To(false)
		if updateErr := m.rtClient.Update(m.ctx, existing); updateErr != nil {
			return fmt.Errorf("updating v3 ClusterInformation: %w", updateErr)
		}
		logCtx.Info("Set DatastoreReady=false on v3 ClusterInformation")
	} else {
		logCtx.Debug("v3 ClusterInformation already locked")
	}

	return nil
}

// ensureV3CRDs checks that v3 CRDs (projectcalico.org) are installed.
// The v3 CRDs must be present before migration can proceed.
func (m *migrationController) ensureV3CRDs(logCtx *logrus.Entry) error {
	crdClient := m.dynamicClient.Resource(crdGVR)
	crdList, err := crdClient.List(m.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing CRDs: %w", err)
	}
	for _, crd := range crdList.Items {
		group, _, _ := unstructured.NestedString(crd.Object, "spec", "group")
		if group == "projectcalico.org" {
			logCtx.Info("v3 CRDs (projectcalico.org) are installed")
			return nil
		}
	}
	return fmt.Errorf("v3 CRDs (projectcalico.org) not installed — apply them before starting migration")
}

// hasV3APIGroupEnv returns true if any container in the pod spec has
// CALICO_API_GROUP=projectcalico.org/v3.
func hasV3APIGroupEnv(spec *corev1.PodSpec) bool {
	for _, c := range spec.Containers {
		for _, e := range c.Env {
			if e.Name == "CALICO_API_GROUP" && e.Value == "projectcalico.org/v3" {
				return true
			}
		}
	}
	return false
}

// joinComponents formats component names for status messages.
func joinComponents(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
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
// libcalico-go backend client.
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

	// Write a copy so a failed update doesn't leave what Get returned claiming
	// a state the datastore never reached.
	ci = ci.DeepCopy()
	ci.Spec.DatastoreReady = &ready
	updated := *kvp
	updated.Value = ci
	_, err = m.backendClient.Update(m.ctx, &updated)
	if err != nil {
		return fmt.Errorf("updating v1 ClusterInformation: %w", err)
	}
	logCtx.WithField("ready", ready).Info("Updated v1 ClusterInformation DatastoreReady")
	return nil
}

func (m *migrationController) setFailedStatus(dm *migrationv1.DatastoreMigration, message string) {
	dm.Status.Phase = migrationv1.DatastoreMigrationPhaseFailed
	dm.Status.Message = message
	setPhaseMetric(migrationv1.DatastoreMigrationPhaseFailed)
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
func (m *migrationController) updateStatus(dm *migrationv1.DatastoreMigration) error {
	return m.rtClient.Status().Update(m.ctx, dm)
}

// updateMetadata updates the metadata (annotations, finalizers, labels) of a
// DatastoreMigration CR. This uses Update (not UpdateStatus) to persist
// metadata changes like annotations and finalizers. The controller-runtime
// client updates dm in-place with the server's response.
func (m *migrationController) updateMetadata(dm *migrationv1.DatastoreMigration) error {
	return m.rtClient.Update(m.ctx, dm)
}

// addFinalizer adds the migration finalizer to the DatastoreMigration CR.
func (m *migrationController) addFinalizer(dm *migrationv1.DatastoreMigration) error {
	dm.Finalizers = append(dm.Finalizers, finalizerName)
	return m.updateMetadata(dm)
}

// removeFinalizer removes the migration finalizer, allowing the CR to be garbage collected.
func (m *migrationController) removeFinalizer(dm *migrationv1.DatastoreMigration) error {
	finalizers := make([]string, 0, len(dm.Finalizers))
	for _, f := range dm.Finalizers {
		if f != finalizerName {
			finalizers = append(finalizers, f)
		}
	}
	dm.Finalizers = finalizers
	return m.updateMetadata(dm)
}
