// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package elastic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	cmnv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"
	"github.com/go-logr/logr"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_logstorage_elastic")

const (
	LogStorageFinalizer = "tigera.io/eck-cleanup"
)

// ElasticSubController is a sub-controller of the main LogStorage controller
// responsible for managing the Elasticsearch service used by Calico.
type ElasticSubController struct {
	client         client.Client
	scheme         *runtime.Scheme
	status         status.StatusManager
	provider       operatorv1.Provider
	esCliCreator   utils.ElasticsearchClientCreator
	clusterDomain  string
	tierWatchReady *utils.ReadyFlag
	multiTenant    bool
	cloud          bool
}

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}
	if opts.ElasticExternal {
		// This controller installs the Elastic operator and an Elasticsearch instance, which is not
		// needed when using an external Elastic cluster.
		return nil
	}

	// Create the reconciler
	r := &ElasticSubController{
		client:         mgr.GetClient(),
		scheme:         mgr.GetScheme(),
		esCliCreator:   utils.NewElasticClient,
		tierWatchReady: &utils.ReadyFlag{},
		status:         status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageElastic, opts.KubernetesVersion),
		clusterDomain:  opts.ClusterDomain,
		provider:       opts.DetectedProvider,
		multiTenant:    opts.MultiTenant,
		cloud:          opts.Cloud,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-elastic-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch Installation resource: %w", err)
	}
	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch ImageSet: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageElastic); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if err = c.WatchObject(&operatorv1.Authentication{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch Authentication resource: %w", err)
	}

	// Start goroutines to establish watches against projectcalico.org/v3 resources.
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, r.tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: render.ElasticsearchPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: kibana.PolicyName, Namespace: kibana.Namespace},
		{Name: eck.OperatorPolicyName, Namespace: eck.OperatorNamespace},
		{Name: render.ElasticsearchInternalPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.ElasticsearchNamespace},
		{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: kibana.Namespace},
	})

	// Watch for changes in storage classes, as new storage classes may be made available for LogStorage.
	err = c.WatchObject(&storagev1.StorageClass{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch StorageClass resource: %w", err)
	}

	if err = c.WatchObject(&apps.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.OperatorName},
	}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch StatefulSet resource: %w", err)
	}
	if err = c.WatchObject(&esv1.Elasticsearch{
		ObjectMeta: metav1.ObjectMeta{Namespace: render.ElasticsearchNamespace, Name: render.ElasticsearchName},
	}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch Elasticsearch resource: %w", err)
	}
	if err = c.WatchObject(&kbv1.Kibana{
		ObjectMeta: metav1.ObjectMeta{Namespace: kibana.Namespace, Name: kibana.CRName},
	}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch Kibana resource: %w", err)
	}

	// Watch all the elasticsearch user secrets in the operator namespace.
	if err = utils.AddSecretWatchWithLabel(c, common.OperatorNamespace(), logstoragecommon.TigeraElasticsearchUserSecretLabel); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch Secret resource: %w", err)
	}

	// Establish watches for secrets in the tigera-operator namespace.
	for _, secretName := range []string{
		render.TigeraElasticsearchGatewaySecret,
		kibana.TigeraKibanaCertSecret,
		render.OIDCSecretName,
		render.DexObjectName,
		esmetrics.ElasticsearchMetricsServerTLSSecret,
		render.TigeraLinseedSecret,
		certificatemanagement.CASecretName,
		monitor.PrometheusClientTLSSecretName,
		render.ElasticsearchAdminUserSecret,
		render.TigeraElasticsearchInternalCertSecret,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch Secret resource: %w", err)
		}
	}

	// Establish watches for secrets in the tigera-elasticsearch namespace.
	for _, secretName := range []string{
		render.ElasticsearchAdminUserSecret,
		render.TigeraElasticsearchInternalCertSecret,
		render.OIDCUsersESSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, render.ElasticsearchNamespace); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch Secret resource: %w", err)
		}
	}

	// Establish a watch on the tenant CA secret across all namespaces if multi-tenancy is enabled.
	if opts.MultiTenant {
		if err = utils.AddSecretsWatch(c, certificatemanagement.TenantCASecretName, ""); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch Secret resource: %w", err)
		}
	}

	// Establish watches for ConfigMaps in the tigera-elasticsearch namespace.
	for _, name := range []string{
		render.OIDCUsersConfigMapName,
	} {
		if err = utils.AddConfigMapWatch(c, name, render.ElasticsearchNamespace, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-elastic-controller failed to watch ConfigMap resource: %w", err)
		}
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch ConfigMap resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, eck.LicenseConfigMapName, eck.OperatorNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch ConfigMap resource: %w", err)
	}

	// Watch services that this controller cares about.
	if err := utils.AddServiceWatch(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.LinseedServiceName, render.ElasticsearchNamespace); err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to watch the Service resource: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-elastic-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *ElasticSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Elasticsearch")

	// Get LogStorage resource.
	ls := &operatorv1.LogStorage{}
	key := utils.DefaultEnterpriseInstanceKey
	err := r.client.Get(ctx, key, ls)
	if err != nil {
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}

		// No LogStorage resource. Nothing to do.
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	// We found the LogStorage instance.
	r.status.OnCRFound()

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if ls.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Set or remove the finalizer from the LogStorage object as needed.
	if err = r.handleLogStorageFinalizer(ctx, ls, reqLogger); err != nil {
		// Note: we don't set degraded status here because handleLogStorageFinalizer() already does that.
		return reconcile.Result{}, err
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
	if !variant.IsEnterprise() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for network to be an enterprise variant", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}
	if managementClusterConnection != nil {
		// LogStorage is not support on a managed cluster.
		r.status.SetDegraded(operatorv1.ResourceNotReady, "LogStorage is not supported on a managed cluster", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurring while retrieving the pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get the keypairs we need for rendering components. These are created separately by the ES secrets controller.
	cm, err := certificatemanager.Create(r.client, installationSpec, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	cm.AddToStatusManager(r.status, render.ElasticsearchNamespace)

	esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	elasticKeyPair, err := cm.GetKeyPair(r.client, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), esDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Elasticsearch secrets", err, log)
		return reconcile.Result{}, err
	}
	kbDNSNames := dns.GetServiceDNSNames(kibana.ServiceName, kibana.Namespace, r.clusterDomain)
	kibanaKeyPair, err := cm.GetKeyPair(r.client, kibana.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
	if err != nil {
		log.Error(err, err.Error())
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Kibana secrets", err, log)
		return reconcile.Result{}, err
	}

	kibanaEnabled := logstoragecommon.KibanaEnabled(ls, r.multiTenant)

	// Wait for dependencies to exist.
	if elasticKeyPair == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for elastic key pair to be available", err, log)
		return reconcile.Result{}, nil
	}
	if kibanaEnabled && kibanaKeyPair == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Waiting for kibana key pair to be available", err, log)
		return reconcile.Result{}, nil
	}

	// Define variables to be filled in below, conditional on cluster type.
	var esLicenseType render.ElasticsearchLicenseType
	var clusterConfig *relasticsearch.ClusterConfig
	var esAdminUserSecret *corev1.Secret

	flowShards := logstoragecommon.CalculateFlowShards(ls.Spec.Nodes, logstoragecommon.DefaultElasticsearchShards)
	clusterConfig = relasticsearch.NewClusterConfig(render.DefaultElasticsearchClusterName, ls.Replicas(), logstoragecommon.DefaultElasticsearchShards, flowShards)

	// Check if there is a StorageClass available to run Elasticsearch on.
	if err = r.client.Get(ctx, client.ObjectKey{Name: ls.Spec.StorageClassName}, &storagev1.StorageClass{}); err != nil {
		if errors.IsNotFound(err) {
			err := fmt.Errorf("couldn't find storage class %s, this must be provided", ls.Spec.StorageClassName)
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Failed to get storage class", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get storage class", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get the admin user secret to copy to the operator namespace.
	esAdminUserSecret, err = utils.GetSecret(ctx, r.client, render.ElasticsearchAdminUserSecret, render.ElasticsearchNamespace)
	if err != nil {
		reqLogger.Error(err, "failed to get Elasticsearch admin user secret")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch admin user secret", err, reqLogger)
		return reconcile.Result{}, err
	}
	if esAdminUserSecret != nil {
		esAdminUserSecret = rsecret.CopyToNamespace(common.OperatorNamespace(), esAdminUserSecret)[0]
	}

	esLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, reqLogger)
	if err != nil {
		// If LicenseConfigMapName is not found, it means ECK operator is not running yet, log the information and proceed
		if errors.IsNotFound(err) {
			reqLogger.Info("ConfigMap not found yet", "name", eck.LicenseConfigMapName)
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get elastic license", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
		return reconcile.Result{}, err
	}

	var kibanaCR *kbv1.Kibana
	if kibanaEnabled {
		kibanaCR, err = r.getKibana(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Kibana", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// If Authentication spec present, we use it to configure dex as an authentication proxy.
	if authentication != nil && authentication.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready - authentication status: %s", authentication.Status.State), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	var baseURL string
	if authentication != nil && authentication.Spec.ManagerDomain != "" {
		baseURL = authentication.Spec.ManagerDomain
		if u, err := url.Parse(baseURL); err == nil {
			if u.Scheme == "" {
				baseURL = fmt.Sprintf("https://%s", baseURL)
			}
		} else {
			reqLogger.Error(err, "Parsing Authentication ManagerDomain failed so baseUrl is not set")
		}
	}

	var unusedTLSSecret *corev1.Secret
	if installationSpec.CertificateManagement != nil {
		// Eck requires us to provide a TLS secret for Kibana and Elasticsearch. It will also inspect that it has a
		// certificate and private key. However, when certificate management is enabled, we do not want to use a
		// private key stored in a secret. For this reason, we mount a dummy that the actual Elasticsearch and Kibana
		// pods are never using.
		unusedTLSSecret, err = utils.GetSecret(ctx, r.client, relasticsearch.UnusedCertSecret, common.OperatorNamespace())
		if unusedTLSSecret == nil {
			unusedTLSSecret, err = certificatemanagement.CreateSelfSignedSecret(relasticsearch.UnusedCertSecret, common.OperatorNamespace(), relasticsearch.UnusedCertSecret, []string{})
			unusedTLSSecret.Data[corev1.TLSCertKey] = installationSpec.CertificateManagement.CACert
		}
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve secret %s/%s", common.OperatorNamespace(), relasticsearch.UnusedCertSecret), err, reqLogger)
			return reconcile.Result{}, nil
		}
	}

	esService, err := r.getElasticsearchService(ctx)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve the Elasticsearch service", err, reqLogger)
		return reconcile.Result{}, err
	}

	var kbService *corev1.Service
	if kibanaEnabled {
		// For now, Kibana is only supported in single tenant configurations.
		kbService, err = r.getKibanaService(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve the Kibana service", err, reqLogger)
			return reconcile.Result{}, err
		}

		if r.cloud {
			// Read the cloud-kibana-config ConfigMap and parse it into a global map in the render package. The render code will read this map
			// and use it to override the default Kibana configuration.
			// TODO: We should instead be passing this via arguments to the render code.
			kbCm := &corev1.ConfigMap{}
			if err = r.client.Get(ctx, types.NamespacedName{Name: "cloud-kibana-config", Namespace: common.OperatorNamespace()}, kbCm); err != nil {
				if !errors.IsNotFound(err) {
					return reconcile.Result{}, fmt.Errorf("failed to read cloud-kibana-config ConfigMap: %s", err.Error())
				}
			} else {
				kibana.CloudKibanaConfigOverrides = map[string]interface{}{}
				if err = json.Unmarshal([]byte(kbCm.Data["config"]), &kibana.CloudKibanaConfigOverrides); err != nil {
					r.status.SetDegraded(operatorv1.InvalidConfigurationError, "Failed to unmarshal config in cloud-kibana-config ConfigMap", err, reqLogger)
					return reconcile.Result{}, err
				}
			}
		}
	}

	// Query the trusted bundle from the namespace.
	trustedBundle, err := cm.LoadTrustedBundle(ctx, r.client, render.ElasticsearchNamespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
		return reconcile.Result{}, err
	}

	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)

	components := []render.Component{
		eck.ECK(&eck.Configuration{
			LogStorage:         ls,
			Installation:       installationSpec,
			ManagementCluster:  managementCluster,
			PullSecrets:        pullSecrets,
			Provider:           r.provider,
			ElasticLicenseType: esLicenseType,
		}),
		render.LogStorage(&render.ElasticsearchConfiguration{
			LogStorage:              ls,
			Installation:            installationSpec,
			ManagementCluster:       managementCluster,
			Elasticsearch:           elasticsearch,
			ClusterConfig:           clusterConfig,
			ElasticsearchUserSecret: esAdminUserSecret,
			ElasticsearchKeyPair:    elasticKeyPair,
			PullSecrets:             pullSecrets,
			Provider:                r.provider,
			ESService:               esService,
			ClusterDomain:           r.clusterDomain,
			ElasticLicenseType:      esLicenseType,
			TrustedBundle:           trustedBundle,
			UnusedTLSSecret:         unusedTLSSecret,
		}),
		kibana.Kibana(&kibana.Configuration{
			LogStorage:      ls,
			Installation:    installationSpec,
			Kibana:          kibanaCR,
			KibanaKeyPair:   kibanaKeyPair,
			PullSecrets:     pullSecrets,
			Provider:        r.provider,
			KbService:       kbService,
			ClusterDomain:   r.clusterDomain,
			BaseURL:         baseURL,
			TrustedBundle:   trustedBundle,
			UnusedTLSSecret: unusedTLSSecret,
			Enabled:         kibanaEnabled,
		}),
	}

	for _, component := range components {
		if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	for _, component := range components {
		if err := hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	if kibanaEnabled && kibanaCR == nil {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Kibana cluster to be created", nil, reqLogger)
		return reconcile.Result{}, nil
	} else if kibanaEnabled && kibanaCR.Status.AssociationStatus != cmnv1.AssociationEstablished {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Kibana association to be established", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// In multi-tenant mode, ILM programming is created out of band
	if !r.multiTenant {
		if err := r.applyILMPolicies(ls, reqLogger, ctx); err != nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Error applying ILM policies", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if kibanaEnabled && esLicenseType == render.ElasticsearchLicenseTypeBasic {
		// es-kube-controllers creates the ConfigMap and Secret needed for SSO into Kibana.
		// If elastisearch uses basic license, degrade logstorage if the ConfigMap and Secret
		// needed for logging user into Kibana is not available.
		if err = r.checkOIDCUsersEsResource(ctx); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get oidc user Secret and ConfigMap", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

// isTerminating returns true if the LogStorage instance is terminating.
func isTerminating(ls *operatorv1.LogStorage) bool {
	return ls != nil && ls.DeletionTimestamp != nil
}

func (r *ElasticSubController) handleLogStorageFinalizer(ctx context.Context, ls *operatorv1.LogStorage, reqLogger logr.Logger) error {
	// Add a finalizer to the LogStorage resource. This ensures we have an opportunity to clean up the resulting
	// Elasticsearch and Kibana custom resources when the LogStorage resource is deleted.
	prePatch := client.MergeFrom(ls.DeepCopy())

	// Determine if we're terminating, and thus if we need to clean up our finalizers. We add a finalizer to the LogStorage
	// so that we can block deletion of it until downstream resources have termianted. Specifically, the Elasticsearch and Kibana
	// instances. So, check if those have been deleted before removing the finalizer.
	if isTerminating(ls) {
		// The LogStorage instance is terminating. Check whether ES and Kibana CRs exist.
		elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
			return err
		}
		kibana := &kbv1.Kibana{}
		err = r.client.Get(ctx, client.ObjectKey{Name: kibana.Name, Namespace: kibana.Namespace}, kibana)
		if errors.IsNotFound(err) {
			kibana = nil
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Kibana", err, reqLogger)
			return err
		}

		if elasticsearch != nil || kibana != nil {
			// One or both of ES and Kibana are still present. Don't remove the finalizer just yet.
			return nil
		}

		// Remove the finalizer if both ES and Kibana have been cleaned up.
		ls.SetFinalizers(stringsutil.RemoveStringInSlice(LogStorageFinalizer, ls.GetFinalizers()))

		// Write the logstorage back to the datastore
		if patchErr := r.client.Patch(ctx, ls, prePatch); patchErr != nil {
			reqLogger.Error(patchErr, "Error patching LogStorage to remove finalizer")
			r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching to remove finalizer", patchErr, reqLogger)
			return err
		}
	} else if ls != nil {
		// Not terminating, make sure the finalizer is present.
		if !stringsutil.StringInSlice(LogStorageFinalizer, ls.GetFinalizers()) {
			ls.SetFinalizers(append(ls.GetFinalizers(), LogStorageFinalizer))
		}
		if err := r.client.Patch(ctx, ls, prePatch); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "Failed to set finalizer on LogStorage", err, reqLogger)
			return err
		}
	}
	return nil
}

func (r *ElasticSubController) checkOIDCUsersEsResource(ctx context.Context) error {
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersConfigMapName, Namespace: render.ElasticsearchNamespace}, &corev1.ConfigMap{}); err != nil {
		return err
	}

	if err := r.client.Get(ctx, types.NamespacedName{Name: render.OIDCUsersESSecretName, Namespace: render.ElasticsearchNamespace}, &corev1.Secret{}); err != nil {
		return err
	}
	return nil
}

func (r *ElasticSubController) applyILMPolicies(ls *operatorv1.LogStorage, reqLogger logr.Logger, ctx context.Context) error {
	// ES should be in ready phase when execution reaches here, apply ILM polices
	esClient, err := r.esCliCreator(r.client, ctx, relasticsearch.ECKElasticEndpoint(), false)
	if err != nil {
		return err
	}

	if err = esClient.SetILMPolicies(ctx, ls, r.cloud); err != nil {
		return err
	}
	return nil
}

func (r *ElasticSubController) getElasticsearchService(ctx context.Context) (*corev1.Service, error) {
	svc := corev1.Service{}
	err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace}, &svc)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &svc, nil
}

func (r *ElasticSubController) getKibana(ctx context.Context) (*kbv1.Kibana, error) {
	kb := kbv1.Kibana{}
	err := r.client.Get(ctx, client.ObjectKey{Name: kibana.CRName, Namespace: kibana.Namespace}, &kb)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &kb, nil
}

func (r *ElasticSubController) getKibanaService(ctx context.Context) (*corev1.Service, error) {
	svc := corev1.Service{}
	err := r.client.Get(ctx, client.ObjectKey{Name: kibana.ServiceName, Namespace: kibana.Namespace}, &svc)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &svc, nil
}
