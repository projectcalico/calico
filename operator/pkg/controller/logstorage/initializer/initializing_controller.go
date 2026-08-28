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

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage/kibana"
)

var log = logf.Log.WithName("controller_logstorage")

const (
	DefaultElasticsearchStorageClass     = "tigera-elasticsearch"
	TigeraStatusName                     = "log-storage"
	defaultEckOperatorMemorySetting      = "512Mi"
	TigeraStatusLogStorageKubeController = "log-storage-kubecontrollers"
	TigeraStatusLogStorageAccess         = "log-storage-access"
	TigeraStatusLogStorageElastic        = "log-storage-elastic"
	TigeraStatusLogStorageSecrets        = "log-storage-secrets"
	TigeraStatusLogStorageUsers          = "log-storage-users"
	TigeraStatusLogStorageESMetrics      = "log-storage-esmetrics"
	TigeraStatusLogStorageDashboards     = "log-storage-dashboards"
)

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		return nil
	}

	// Create the reconciler
	r := &LogStorageInitializer{
		client:      mgr.GetClient(),
		scheme:      mgr.GetScheme(),
		multiTenant: opts.MultiTenant,
		externalES:  opts.ElasticExternal,
		status:      status.New(mgr.GetClient(), TigeraStatusName, opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-initializing-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-initializing-controller failed to watch LogStorage resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-initializing-controller failed to watch Installation resource: %w", err)
	}

	return nil
}

var _ reconcile.Reconciler = &LogStorageInitializer{}

// LogStorageInitializer is responsible for performing validation and defaulting on the LogStorage object,
// and creating the base namespaces for other controllers to deploy into. It updates the status of the LogStorage
// object to indicate that it has completed its work to other controllers.
type LogStorageInitializer struct {
	client      client.Client
	scheme      *runtime.Scheme
	status      status.StatusManager
	provider    operatorv1.Provider
	multiTenant bool
	externalES  bool
}

// FillDefaults populates the default values onto an LogStorage object.
func FillDefaults(opr *operatorv1.LogStorage) {
	if opr.Spec.Retention == nil {
		opr.Spec.Retention = &operatorv1.Retention{}
	}

	if opr.Spec.Retention.Flows == nil {
		var fr int32 = 8
		opr.Spec.Retention.Flows = &fr
	}
	if opr.Spec.Retention.AuditReports == nil {
		var arr int32 = 91
		opr.Spec.Retention.AuditReports = &arr
	}
	if opr.Spec.Retention.Snapshots == nil {
		var sr int32 = 91
		opr.Spec.Retention.Snapshots = &sr
	}
	if opr.Spec.Retention.ComplianceReports == nil {
		var crr int32 = 91
		opr.Spec.Retention.ComplianceReports = &crr
	}
	if opr.Spec.Retention.DNSLogs == nil {
		var dlr int32 = 8
		opr.Spec.Retention.DNSLogs = &dlr
	}
	if opr.Spec.Retention.BGPLogs == nil {
		var bgp int32 = 8
		opr.Spec.Retention.BGPLogs = &bgp
	}

	if opr.Spec.Indices == nil {
		opr.Spec.Indices = &operatorv1.Indices{}
	}

	if opr.Spec.Indices.Replicas == nil {
		var replicas int32 = render.DefaultElasticsearchReplicas
		opr.Spec.Indices.Replicas = &replicas
	}

	if opr.Spec.StorageClassName == "" {
		opr.Spec.StorageClassName = DefaultElasticsearchStorageClass
	}

	if opr.Spec.Nodes == nil {
		opr.Spec.Nodes = &operatorv1.Nodes{Count: 1}
	}

	if opr.Spec.Kibana == nil {
		opr.Spec.Kibana = &operatorv1.Kibana{}
	}
	if opr.Spec.Kibana.Spec == nil {
		opr.Spec.Kibana.Spec = &operatorv1.KibanaSpec{}
	}
	if opr.Spec.Kibana.Spec.Replicas == nil {
		var replicas int32 = 1
		opr.Spec.Kibana.Spec.Replicas = &replicas
	}

	if opr.Spec.ComponentResources == nil {
		limits := corev1.ResourceList{}
		requests := corev1.ResourceList{}
		limits[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
		requests[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
		opr.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
			{
				ComponentName: operatorv1.ComponentNameECKOperator,
				ResourceRequirements: &corev1.ResourceRequirements{
					Limits:   limits,
					Requests: requests,
				},
			},
		}
	}
}

func validateLogStorage(spec *operatorv1.LogStorageSpec) error {
	if err := validateReplicasForNodeCount(spec); err != nil {
		return err
	}

	return validateComponentResources(spec)
}

func validateReplicasForNodeCount(spec *operatorv1.LogStorageSpec) error {
	if spec.Nodes == nil || spec.Indices == nil || spec.Indices.Replicas == nil {
		return nil
	}

	replicas := int(*spec.Indices.Replicas)
	nodeCount := int(spec.Nodes.Count)
	if replicas > 0 && nodeCount <= replicas {
		return fmt.Errorf("LogStorage spec.indices.replicas (%d) must be less than spec.nodes.count (%d); replica shards cannot be allocated when there are not enough nodes. For a single-node Elasticsearch cluster, set spec.indices.replicas to 0", replicas, nodeCount)
	}

	return nil
}

func validateComponentResources(spec *operatorv1.LogStorageSpec) error {
	if spec.ComponentResources == nil {
		return fmt.Errorf("LogStorage spec.ComponentResources is nil %+v", spec)
	}
	// Currently the only supported component is ECKOperator.
	if len(spec.ComponentResources) > 1 {
		return fmt.Errorf("LogStorage spec.ComponentResources contains unsupported components %+v", spec.ComponentResources)
	}

	if spec.ComponentResources[0].ComponentName != operatorv1.ComponentNameECKOperator {
		return fmt.Errorf("LogStorage spec.ComponentResources.ComponentName %s is not supported", spec.ComponentResources[0].ComponentName)
	}

	return nil
}

func (r *LogStorageInitializer) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	ls := &operatorv1.LogStorage{}
	key := utils.DefaultEnterpriseInstanceKey
	err := r.client.Get(ctx, key, ls)
	if errors.IsNotFound(err) {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	} else if err != nil {
		// An actual error ocurred when attempting to query the LogStorage API.
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	// We found the LogStorage instance.
	r.status.OnCRFound()

	// Get Installation resource.
	installationSpec, err := utils.GetComputedInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Check if there is a management cluster connection. ManagementClusterConnection is a managed cluster only resource.
	if err = r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, &operatorv1.ManagementClusterConnection{}); err == nil {
		// LogStorage isn't valid for managed clusters.
		r.setConditionDegraded(ctx, ls, reqLogger)
		r.status.SetDegraded(operatorv1.InvalidConfigurationError, "LogStorage is not valid for a managed cluster", nil, reqLogger)
		return reconcile.Result{}, nil
	} else if !errors.IsNotFound(err) {
		// An actual error ocurred when attempting to query the ManagementClusterConnection API.
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a snapshot of the pre-defaulting LogStorage state to use when performing a
	// merge patch to update the resource later.
	preDefaultingPatchFrom := client.MergeFrom(ls.DeepCopy())

	// Default and validate the object.
	FillDefaults(ls)
	if err := validateLogStorage(&ls.Spec); err != nil {
		// Invalid - mark it as such and return.
		r.setConditionDegraded(ctx, ls, reqLogger)
		r.status.SetDegraded(operatorv1.ResourceValidationError, "An error occurred while validating LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Before we can create secrets, we need to ensure the tigera-elasticsearch namespace exists.
	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)
	components := []render.Component{render.NewSetup(&render.SetUpConfiguration{
		OpenShift:       r.provider.IsOpenShift(),
		Installation:    installationSpec,
		PullSecrets:     pullSecrets,
		Namespace:       render.ElasticsearchNamespace,
		PSS:             r.elasticsearchPSS(),
		CreateNamespace: true,
	})}

	// Multitenant clusters do not get kibana, so namespace creation can be skipped.
	if !r.multiTenant {
		components = append(components, render.NewSetup(&render.SetUpConfiguration{
			OpenShift:       r.provider.IsOpenShift(),
			Installation:    installationSpec,
			PullSecrets:     pullSecrets,
			Namespace:       kibana.Namespace,
			PSS:             render.PSSBaseline,
			CreateNamespace: true,
		}))
	}

	for _, component := range components {
		if err = hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Write the logstorage back to the datastore with its newly applied defaults.
	if err = r.client.Patch(ctx, ls, preDefaultingPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourcePatchError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}
	if err = r.setConditionReady(ctx, ls, reqLogger); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to update LogStorage status", err, reqLogger)
		return reconcile.Result{}, err
	}
	defer r.status.SetMetaData(&ls.ObjectMeta)

	// Mark the status as available.
	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

func (r *LogStorageInitializer) elasticsearchPSS() render.PodSecurityStandard {
	if r.externalES {
		return render.PSSBaseline
	}
	return render.PSSPrivileged
}

func (r *LogStorageInitializer) setConditionReady(ctx context.Context, ls *operatorv1.LogStorage, log logr.Logger) error {
	ls.Status.State = operatorv1.TigeraStatusReady
	if err := r.client.Status().Update(ctx, ls); err != nil {
		log.Error(err, "Failed to update LogStorage status")
		return err
	}
	return nil
}

func (r *LogStorageInitializer) setConditionDegraded(ctx context.Context, ls *operatorv1.LogStorage, log logr.Logger) {
	ls.Status.State = operatorv1.TigeraStatusDegraded
	if err := r.client.Status().Update(ctx, ls); err != nil {
		log.Error(err, "Failed to update LogStorage status")
	}
}
