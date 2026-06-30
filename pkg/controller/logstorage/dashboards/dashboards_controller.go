// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package dashboards

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/dashboards"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	lscommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var log = logf.Log.WithName("controller_logstorage_dashboards")

type DashboardsSubController struct {
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	provider        operatorv1.Provider
	clusterDomain   string
	multiTenant     bool
	elasticExternal bool
	cloud           bool
	tierWatchReady  *utils.ReadyFlag
}

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists || opts.MultiTenant {
		return nil
	}

	r := &DashboardsSubController{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		status:          status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageDashboards, opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		provider:        opts.DetectedProvider,
		tierWatchReady:  &utils.ReadyFlag{},
		multiTenant:     opts.MultiTenant,
		elasticExternal: opts.ElasticExternal,
		cloud:           opts.Cloud,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-dashboards-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-dashboards-controller failed to watch LogStorage resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.Installation{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-dashboards-controller failed to watch Installation resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-dashboards-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageDashboards); err != nil {
		return fmt.Errorf("logstorage-dashboards-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-dashboards-controller failed to watch Tenant resource: %w", err)
		}
	}

	// The namespace(s) we need to monitor depend upon what tenancy mode we're running in.
	// For single-tenant, everything is installed in the tigera-manager namespace.
	// Make a helper for determining which namespaces to use based on tenancy mode.
	helper := utils.NewNamespaceHelper(opts.MultiTenant, render.ElasticsearchNamespace, "")

	// Watch secrets this controller cares about.
	secretsToWatch := []string{
		dashboards.ElasticCredentialsSecret,
	}

	// Determine namespaces to watch.
	namespacesToWatch := []string{helper.TruthNamespace(), helper.InstallNamespace()}
	if helper.TruthNamespace() == helper.InstallNamespace() {
		namespacesToWatch = []string{helper.InstallNamespace()}
	}
	for _, ns := range namespacesToWatch {
		for _, name := range secretsToWatch {
			if err := utils.AddSecretsWatch(c, name, ns); err != nil {
				return fmt.Errorf("log-storage-dashboards-controller failed to watch Secret: %w", err)
			}
		}
	}

	// Catch if something modifies the resources that this controller consumes.
	if err := utils.AddServiceWatch(c, kibana.ServiceName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-dashboards-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, helper.InstallNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-dashboards-controller failed to watch the Service resource: %w", err)
	}

	// Check if something modifies resources this controller creates.
	err = c.WatchObject(&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Namespace: helper.InstallNamespace(),
		Name:      dashboards.Name,
	}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-dashboards-controller failed to watch installer job: %v", err)
	}

	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, r.tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: dashboards.PolicyName, Namespace: helper.InstallNamespace()},
	})

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, eventHandler)
	if err != nil {
		return fmt.Errorf("log-storage-dashboards-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (d DashboardsSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(d.multiTenant, render.ElasticsearchNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage - Dashboards")

	// We skip requests without a namespace specified in multi-tenant setups.
	if d.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// When running in multi-tenant mode, we need to install Dashboards in tenant Namespaces.
	// We use the tenant API to determine the set of namespaces that should have a K8S job that installs dashboards.
	tenant, _, err := utils.GetTenant(ctx, d.multiTenant, d.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		d.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get Installation resource.
	variant, installationSpec, err := utils.GetInstallationSpec(context.Background(), d.client)
	if err != nil {
		if errors.IsNotFound(err) {
			d.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		d.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !d.tierWatchReady.IsReady() {
		d.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	if err := d.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			d.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			d.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, d.client)
	if err != nil {
		d.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}
	if managementClusterConnection != nil {
		// Dashboard job installer is only relevant for management and standalone clusters. If this is a managed cluster, we can
		// simply return early.
		reqLogger.V(1).Info("Not installing dashboard job installer on managed cluster")
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, d.client)
	if err != nil {
		d.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get LogStorage resource.
	logStorage := &operatorv1.LogStorage{}
	key := utils.DefaultEnterpriseInstanceKey
	err = d.client.Get(ctx, key, logStorage)
	if err != nil {
		if errors.IsNotFound(err) {
			d.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		d.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	d.status.OnCRFound()

	// Determine where to access Kibana.
	kibanaHost := "tigera-secure-kb-http.tigera-kibana.svc"
	kibanaPort := uint16(5601)
	kibanaScheme := "https"

	var externalKibanaSecret *corev1.Secret
	if !d.elasticExternal {
		// Wait for Elasticsearch to be installed and available.
		elasticsearch, err := utils.GetElasticsearch(ctx, d.client)
		if err != nil {
			d.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
			return reconcile.Result{}, err
		}
		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			d.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
	} else {
		// External ES & Kibana. Two ways to obtain the tenant's Kibana endpoint:
		//   - multi-tenant (incl. enterprise) and non-cloud single-tenant: the Tenant CR must carry it.
		//     This is the pre-existing enterprise behavior, preserved by the `!d.cloud` clause.
		//   - Calico Cloud single-tenant: there is no Tenant CR, so it's derived from the cloud config map.
		if d.multiTenant || !d.cloud {
			// The Tenant resource must specify the Kibana endpoint.
			if tenant == nil || tenant.Spec.Elastic == nil || tenant.Spec.Elastic.KibanaURL == "" {
				reqLogger.Error(nil, "Kibana URL must be specified for this tenant")
				d.status.SetDegraded(operatorv1.ResourceValidationError, "Kibana URL must be specified for this tenant", nil, reqLogger)
				return reconcile.Result{}, nil
			}
		} else {
			// Calico Cloud single-tenant cluster connected to an external ES & Kibana. Read the tenant
			// configuration from the CloudConfig ConfigMap.
			cloudConfig, err := utils.GetCloudConfig(ctx, d.client)
			if err != nil {
				d.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read cloud config", err, reqLogger)
				return reconcile.Result{}, err
			}
			tenant = cloudConfig.ToTenant()
		}

		// Determine the host and port from the URL.
		url, err := url.Parse(tenant.Spec.Elastic.KibanaURL)
		if err != nil {
			reqLogger.Error(err, "Kibana URL is invalid")
			d.status.SetDegraded(operatorv1.ResourceValidationError, "Kibana URL is invalid", err, reqLogger)
			return reconcile.Result{}, nil
		}
		kibanaScheme = url.Scheme
		kibanaHost = strings.TrimSuffix(url.Hostname(), "/")
		kibanaPort, err = parsePort(url.Port())
		if err != nil {
			reqLogger.Error(err, "Failed to extract domain or unit16 port for Kibana")
			d.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to parse kibana domain or port", err, reqLogger)
			return reconcile.Result{}, nil
		}

		if tenant.ElasticMTLS() {
			// If mTLS is enabled, get the secret containing the CA and client certificate.
			externalKibanaSecret = &corev1.Secret{}
			err = d.client.Get(ctx, client.ObjectKey{Name: logstorage.ExternalCertsSecret, Namespace: common.OperatorNamespace()}, externalKibanaSecret)
			if err != nil {
				reqLogger.Error(err, "Failed to read external Kibana client certificate secret")
				d.status.SetDegraded(operatorv1.ResourceReadError, "Waiting for external Kibana client certificate secret to be available", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}

	// Query the username and password this Dashboards Installer instance should use to authenticate with Elasticsearch.
	// For multi-tenant systems, credentials are created by the elasticsearch users controller.
	// For single-tenant system, these are created by es-kube-controllers.
	key = types.NamespacedName{Name: dashboards.ElasticCredentialsSecret, Namespace: helper.InstallNamespace()}
	credentials := corev1.Secret{}
	if err = d.client.Get(ctx, key, &credentials); err != nil && !errors.IsNotFound(err) {
		d.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting Secret %s", key), err, reqLogger)
		return reconcile.Result{}, err
	} else if errors.IsNotFound(err) {
		d.status.SetDegraded(operatorv1.ResourceNotFound, fmt.Sprintf("Waiting for Dashboards credential Secret %s", key), err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Collect the certificates we need to provision Dashboards. These will have been provisioned already by the ES secrets controller.
	opts := []certificatemanager.Option{
		certificatemanager.WithLogger(reqLogger),
		certificatemanager.WithTenant(tenant),
	}
	cm, err := certificatemanager.Create(d.client, installationSpec, d.clusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		d.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Query the trusted bundle from the namespace.
	trustedBundle, err := cm.LoadTrustedBundle(ctx, d.client, helper.InstallNamespace())
	if err != nil {
		d.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
		return reconcile.Result{}, err
	}

	cfg := &dashboards.Config{
		Installation:               installationSpec,
		PullSecrets:                pullSecrets,
		Namespace:                  helper.InstallNamespace(),
		TrustedBundle:              trustedBundle,
		IsManaged:                  managementClusterConnection != nil,
		Tenant:                     tenant,
		KibanaHost:                 kibanaHost,
		KibanaScheme:               kibanaScheme,
		KibanaPort:                 kibanaPort,
		ExternalKibanaClientSecret: externalKibanaSecret,
		Credentials:                []*corev1.Secret{&credentials},
		KibanaEnabled:              lscommon.KibanaEnabled(logStorage, d.multiTenant),
	}
	dashboardsComponent := dashboards.Dashboards(cfg)

	if err := imageset.ApplyImageSet(ctx, d.client, variant, dashboardsComponent); err != nil {
		d.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	// In standard installs, the LogStorage owns the dashboards. For multi-tenant, it's owned by the Tenant instance.
	var hdler utils.ComponentHandler
	if d.multiTenant {
		hdler = utils.NewComponentHandler(reqLogger, d.client, d.scheme, tenant)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, d.client, d.scheme, logStorage)
	}
	if err := hdler.CreateOrUpdateOrDelete(ctx, dashboardsComponent, d.status); err != nil {
		d.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	d.status.ReadyToMonitor()
	d.status.ClearDegraded()

	return reconcile.Result{}, nil
}

func parsePort(port string) (uint16, error) {
	kibanaPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}
	if kibanaPort > math.MaxInt16 {
		return 0, fmt.Errorf("the Kibana port is larger them max %d", math.MaxInt16)
	}
	return uint16(kibanaPort), nil
}
