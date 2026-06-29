// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package kubecontrollers

import (
	"context"
	"fmt"
	"time"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/tenancy"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_logstorage_kube-controllers")

type ESKubeControllersController struct {
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	clusterDomain   string
	elasticExternal bool
	multiTenant     bool
	cloud           bool
	tierWatchReady  *utils.ReadyFlag
}

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	if opts.MultiTenant {
		// This controller is no longer required for multi-tenant environmants
		// Single tenant and zero tenant will still run es-kube-controllers.
		// Single tenant need elasticsearch configuration setup for kibana users,
		// while zero tenant also require the license push to the managed clusters.
		return nil
	}

	// Create the reconciler
	r := &ESKubeControllersController{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		clusterDomain:   opts.ClusterDomain,
		status:          status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageKubeController, opts.KubernetesVersion),
		elasticExternal: opts.ElasticExternal,
		multiTenant:     opts.MultiTenant,
		cloud:           opts.Cloud,
		tierWatchReady:  &utils.ReadyFlag{},
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-kubecontrollers-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch LogStorage resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.Installation{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch Installation resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageKubeController); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}

	// Watch secrets this controller cares about.
	secretsToWatch := []string{
		render.TigeraElasticsearchGatewaySecret,
		monitor.PrometheusClientTLSSecretName,
	}

	// Determine namespaces to watch.
	_, _, namespacesToWatch := tenancy.GetWatchNamespaces(r.multiTenant, render.ElasticsearchNamespace)
	for _, ns := range namespacesToWatch {
		for _, name := range secretsToWatch {
			if err := utils.AddSecretsWatch(c, name, ns); err != nil {
				return fmt.Errorf("log-storage-kubecontrollers failed to watch Secret: %w", err)
			}
		}
	}

	// The namespace(s) we need to monitor depend upon what tenancy mode we're running in.
	// For single-tenant, everything is installed in the calico-system namespace.
	// Make a helper for determining which namespaces to use based on tenancy mode.
	esKubeControllersNamespace := utils.NewNamespaceHelper(opts.MultiTenant, common.CalicoNamespace, "")
	if err := utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, esKubeControllersNamespace.InstallNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch the Service resource: %w", err)
	}
	if err := utils.AddDeploymentWatch(c, esgateway.DeploymentName, esKubeControllersNamespace.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddDeploymentWatch(c, kubecontrollers.EsKubeController, esKubeControllersNamespace.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-access-controller failed to watch the Service resource: %w", err)
	}
	if opts.Cloud && opts.ElasticExternal {
		// This ConfigMap is needed for utils.GetCloudConfig
		if err = utils.AddConfigMapWatch(c, cloudconfig.CloudConfigConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-kubecontrollers failed to watch the ConfigMap resource: %w", err)
		}
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, eventHandler)
	if err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to create periodic reconcile watch: %w", err)
	}

	// Catch if something modifies the resources that this controller consumes.
	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch the Service resource: %w", err)
	}
	if err := utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, render.ElasticsearchNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-kubecontrollers failed to watch the ConfigMap resource: %w", err)
	}
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: esgateway.PolicyName, Namespace: render.ElasticsearchNamespace},
	})

	// Start goroutines to establish watches against projectcalico.org/v3 resources.
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, r.tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: kubecontrollers.EsKubeControllerNetworkPolicyName, Namespace: esKubeControllersNamespace.InstallNamespace()},
	})

	return nil
}

func (r *ESKubeControllersController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(r.multiTenant, common.CalicoNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage - ESKubeControllers")

	// Get LogStorage resource.
	logStorage := &operatorv1.LogStorage{}
	key := utils.DefaultEnterpriseInstanceKey
	err := r.client.Get(ctx, key, logStorage)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	// We found the LogStorage instance (and Tenant instance if in multi-tenant mode).
	r.status.OnCRFound()

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if logStorage.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Get Installation resource.
	variant, installationSpec, err := utils.GetInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}
	if managementClusterConnection != nil {
		// TODO: Handle switch from standalone -> managed
		reqLogger.V(1).Info("Not installing es-kube-controllers on managed cluster")
		return reconcile.Result{}, nil
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !r.elasticExternal {
		// Wait for Elasticsearch to be installed and available
		elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
			return reconcile.Result{}, err
		}
		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
	}

	// Get secrets needed for kube-controllers to talk to elastic. This is needed for zero-tenants and single-tenants
	// that deploy es-kube-controllers and need to talk to es-gateway
	var kubeControllersUserSecret *core.Secret
	kubeControllersUserSecret, err = utils.GetSecret(ctx, r.client, kubecontrollers.ElasticsearchKubeControllersUserSecret, helper.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get kube controllers gateway secret", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Collect the certificates we need to provision es-kube-controllers. These will have been provisioned already by the ES secrets controller.
	opts := []certificatemanager.Option{
		certificatemanager.WithLogger(reqLogger),
	}
	cm, err := certificatemanager.Create(r.client, installationSpec, r.clusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to load CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, logStorage)

	// Get the Authentication resource.
	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// ESGateway is required in order for kube-controllers to operate successfully, since es-kube-controllers talks to ES
	// via this gateway. However, in multi-tenant mode, es-kube-controllers doesn't talk to elasticsearch,
	// so this is only needed in single-tenant clusters and zero tenants clusters
	gwNSHelper := utils.NewSingleTenantNamespaceHelper(render.ElasticsearchNamespace)
	// Query the trusted bundle from the namespace.
	gwTrustedBundle, err := cm.LoadTrustedBundle(ctx, r.client, gwNSHelper.InstallNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting trusted bundle in %s", gwNSHelper.InstallNamespace()), err, reqLogger)
		return reconcile.Result{}, err
	}
	if err := r.createESGateway(
		ctx,
		gwNSHelper,
		installationSpec,
		variant,
		pullSecrets,
		hdler,
		reqLogger,
		gwTrustedBundle,
		logStorage,
	); err != nil {
		return reconcile.Result{}, err
	}

	// Query the trusted bundle from the namespace.
	trustedBundle, err := cm.LoadTrustedBundle(ctx, r.client, helper.InstallNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting trusted bundle in %s", helper.InstallNamespace()), err, reqLogger)
		return reconcile.Result{}, err
	}

	// Determine the namespaces to which we must bind the cluster role.
	namespaces, err := helper.TenantNamespaces(r.client)
	if err != nil {
		return reconcile.Result{}, err
	}

	kubeControllersCfg := kubecontrollers.KubeControllersConfiguration{
		K8sServiceEp:                 k8sapi.Endpoint,
		K8sServiceEpPodNetwork:       k8sapi.PodNetworkEndpoint,
		Installation:                 installationSpec,
		ManagementCluster:            managementCluster,
		ClusterDomain:                r.clusterDomain,
		Authentication:               authentication,
		KubeControllersGatewaySecret: kubeControllersUserSecret,
		LogStorageExists:             logStorage != nil,
		TrustedBundle:                trustedBundle,
		Namespace:                    helper.InstallNamespace(),
		BindingNamespaces:            namespaces,
		Tenant:                       nil,
		Cloud:                        r.cloud,
	}
	if r.cloud {
		if result, proceed, err := r.esKubeControllersAddCloudModificationsToConfig(&kubeControllersCfg, reqLogger, ctx); err != nil || !proceed {
			return result, err
		}
	}
	esKubeControllerComponents := kubecontrollers.NewElasticsearchKubeControllers(&kubeControllersCfg)

	imageSet, err := imageset.GetImageSet(ctx, r.client, variant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error validating ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ResolveImages(imageSet, esKubeControllerComponents); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error resolving ImageSet for elasticsearch kube-controllers components", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range []render.Component{esKubeControllerComponents} {
		if err := hdler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating  elasticsearch kube-controllers resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}
