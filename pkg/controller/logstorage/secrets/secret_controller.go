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

package secrets

import (
	"context"
	"fmt"
	"sort"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	logstoragecommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	entcertificatemanager "github.com/tigera/operator/pkg/enterprise/certificatemanager"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_logstorage_secrets")

// SecretSubController is a sub controller for managing secrets related to Elasticsearch and log storage components.
// It provisions secrets and the trusted bundle into the requisite namespace(s) for other controllers to consume.
type SecretSubController struct {
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	clusterDomain   string
	multiTenant     bool
	elasticExternal bool
}

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		return nil
	}

	// Create the reconciler
	r := &SecretSubController{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		clusterDomain:   opts.ClusterDomain,
		multiTenant:     opts.MultiTenant,
		status:          status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageSecrets, opts.KubernetesVersion),
		elasticExternal: opts.ElasticExternal,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-secrets-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = eutils.EnqueueAllTenants(mgr.GetClient())
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch LogStorage resource: %w", err)
	}
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Installation resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageSecrets); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-secrets-controller failed to watch Tenant resource: %w", err)
		}
	}

	// Make a helper for determining which namespaces to use based on tenancy mode.
	// In multi-tenant mode, we need to watch all namespaces for secrets. In single-tenant mode,
	// we only need to watch the elasticsearch namespace. Both need tigera-operator.
	helper := eutils.NewNamespaceHelper(opts.MultiTenant, render.ElasticsearchNamespace, "")

	// Watch all the elasticsearch user secrets in the truth namespace.
	if err = utils.AddSecretWatchWithLabel(c, helper.TruthNamespace(), logstoragecommon.TigeraElasticsearchUserSecretLabel); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Secrets: %w", err)
	}
	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedCertConfigMapName, helper.InstallNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch ConfigMap resource: %w", err)
	}
	if err = utils.AddSecretsWatchWithHandler(c, certificatemanagement.CASecretName, common.OperatorNamespace(), eventHandler); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Secret: %w", err)
	}
	if err = utils.AddSecretsWatch(c, render.TigeraElasticsearchGatewaySecret, helper.TruthNamespace()); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Secret: %w", err)
	}
	if err = utils.AddSecretsWatch(c, kibana.TigeraKibanaCertSecret, helper.TruthNamespace()); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Secret: %w", err)
	}
	if err = utils.AddSecretsWatch(c, render.TigeraLinseedSecret, helper.TruthNamespace()); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Secret: %w", err)
	}
	if err = utils.AddSecretsWatch(c, esmetrics.ElasticsearchMetricsServerTLSSecret, helper.TruthNamespace()); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Secret: %w", err)
	}
	if err = utils.AddSecretsWatchWithHandler(c, monitor.PrometheusClientTLSSecretName, helper.TruthNamespace(), eventHandler); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Secret: %w", err)
	}
	if err := utils.AddServiceWatchWithHandler(c, render.ElasticsearchServiceName, render.ElasticsearchNamespace, eventHandler); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch the Service resource: %w", err)
	}
	if err := utils.AddServiceWatch(c, esgateway.ServiceName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Service: %w", err)
	}
	if err := utils.AddServiceWatch(c, render.LinseedServiceName, helper.InstallNamespace()); err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to watch Service: %w", err)
	}
	if opts.MultiTenant {
		if err = utils.AddSecretsWatch(c, certificatemanagement.TenantCASecretName, ""); err != nil {
			return fmt.Errorf("log-storage-secrets-controller failed to watch Secret: %w", err)
		}
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, eventHandler)
	if err != nil {
		return fmt.Errorf("log-storage-secrets-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

func (r *SecretSubController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := eutils.NewNamespaceHelper(r.multiTenant, render.ElasticsearchNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage Secrets")

	// Get LogStorage resource.
	ls := &operatorv1.LogStorage{}
	key := utils.DefaultEnterpriseInstanceKey
	err := r.client.Get(ctx, key, ls)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	}

	// We found the LogStorage instance.
	r.status.OnCRFound()

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}
	tenant, _, err := eutils.GetTenant(ctx, r.multiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}
	if r.multiTenant && tenant == nil {
		// Skip multi-tenant requests without a Tenant.
		return reconcile.Result{}, nil
	}

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if ls.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Get Installation resource.
	installationSpec, err := utils.GetInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Secrets only need to be provisioned into management or standalone clusters.
	if managementClusterConnection != nil {
		return reconcile.Result{}, nil
	}

	managementCluster, err := eutils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	// In a multi-tenant system, secrets are organized in the following way:
	// - Each tenant has its own CA, in that tenant's namespace, used for signing tenant certificates.
	// - Elasticsearch has its own CA and KeyPair, that is global.
	// So, we create two certificate managers - one for managing per-tenant keypairs signed with the per-tenant CA,
	// and another for cluster-scoped keypairs signed with the root operator CA.
	var operatorSigner, cm certificatemanager.CertificateManager

	// Create a cluster-scoped certificate manager from the tigera-operator CA, used for signing KeyPairs for use by Elasticsearch.
	operatorSigner, err = certificatemanager.Create(r.client, installationSpec, r.clusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error building certificate manager", err, reqLogger)
		return reconcile.Result{}, err
	}
	operatorSigner.AddToStatusManager(r.status, render.ElasticsearchNamespace)

	// Provision secrets and the trusted bundle into the cluster.
	hdler := utils.NewComponentHandler(reqLogger, r.client, r.scheme, ls)

	// Internal ES modes:
	// - Zero-tenant: everything installed in tigera-elasticsearch/tigera-kibana Namespaces. We need a single trusted bundle in each.
	// - Single-tenant: everything installed in tigera-elasticsearch/tigera-kibana Namespaces. We need a single trusted bundle in each.
	//
	// External ES modes:
	// - Single-tenant: everything installed in tigera-elasticsearch/tigera-kibana Namespaces. We need a single trusted bundle in each.
	// - Multi-tenant: nothing installed in tigera-elasticsearch Namespace. The trusted bundle isn't created by this controller, but per-tenant keypairs are.
	if !r.elasticExternal {
		// This branch provisions the necessary KeyPairs for the internal ES cluster and Kibana, and installs a trusted bundle into tigera-kibana.
		// The trusted bundle for the tigera-elasticsearch namespace will be created further below as part of generateTigeraSecrets(), as it
		// needs to include the public certificates from other Tigera components.

		// Generate Elasticsearch / Kibana secrets for the tigera-elasticsearch and tigera-kibana namespaces.
		elasticKeys, err := r.generateInternalElasticSecrets(reqLogger, operatorSigner)
		if err != nil {
			return reconcile.Result{}, err
		}

		// Create Elasticsearch keypair into the tigera-elasticsearch Namespace.
		if err = hdler.CreateOrUpdateOrDelete(ctx, elasticKeys.internalESComponent(), r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Multitenant clusters do not get kibana, so TLS assets creation can be skipped.
		if !r.multiTenant {
			// Render the key pair and trusted bundle into the Kibana namespace.
			if err = hdler.CreateOrUpdateOrDelete(ctx, elasticKeys.internalKibanaComponent(elasticKeys.trustedBundle(operatorSigner)), r.status); err != nil {
				r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}
	reqLogger.Info("Rendering secrets for Tigera ES components")

	// For single-tenant systems, we use the same root CA and thus the same certificate manager to sign all secrets.
	cm = operatorSigner
	if r.multiTenant {
		// Override with a tenant-scoped certificate manager which uses the CA in the tenant's namespace.
		opts := []certificatemanager.Option{certificatemanager.WithLogger(reqLogger)}
		cm, err = entcertificatemanager.Create(r.client, installationSpec, r.clusterDomain, helper.InstallNamespace(), tenant, opts...)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error building certificate manager", err, reqLogger)
			return reconcile.Result{}, err
		}
		cm.AddToStatusManager(r.status, helper.InstallNamespace())
	}

	// Create secrets for Tigera components.
	keyPairs, err := r.generateSecrets(reqLogger, helper, cm, managementCluster, installationSpec)
	if err != nil {
		// Status manager is handled already, so we can just return
		return reconcile.Result{}, err
	}
	if keyPairs == nil {
		// Waiting for keys to be ready.
		reqLogger.Info("Waiting for key pairs to be ready")
		return reconcile.Result{}, nil
	}

	// Create the KeyPairs into the correct Namespace. For single/zero-tenant, this is the tigera-elasticsearch Namespace. For multi-tenant,
	// this is the tenant's Namespace.
	if err = hdler.CreateOrUpdateOrDelete(ctx, keyPairs.component(keyPairs.trustedBundle(cm), helper), r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

// generateInternalElasticSecrets generates key pairs for the internal ES cluster and Kibana managed by tigera-operator via ECK
// when configured to use an internal ES.
func (r *SecretSubController) generateInternalElasticSecrets(log logr.Logger, cm certificatemanager.CertificateManager) (*elasticKeyPairCollection, error) {
	collection := elasticKeyPairCollection{log: log}

	// Generate a keypair for elasticsearch.
	//
	// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	// Elasticsearch is always in the tigera-elasticsearch namespace, and is shared across tenants, so should always be stored in the
	// tigera-operator namespace.
	esDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, r.clusterDomain)
	elasticKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), esDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Elasticsearch secrets", err, log)
		return nil, err
	}
	collection.elastic = elasticKeyPair

	// Multitenant clusters do not get kibana, so TLS assets creation can be skipped.
	if !r.multiTenant {
		// Generate a keypair for Kibana.
		//
		// This fetches the existing key pair from the tigera-operator namespace if it exists, or generates a new one in-memory otherwise.
		// It will be provisioned into the cluster in the render stage later on.
		kbDNSNames := dns.GetServiceDNSNames(kibana.ServiceName, kibana.Namespace, r.clusterDomain)
		kibanaKeyPair, err := cm.GetOrCreateKeyPair(r.client, kibana.TigeraKibanaCertSecret, common.OperatorNamespace(), kbDNSNames)
		if err != nil {
			log.Error(err, err.Error())
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to create Kibana secrets", err, log)
			return nil, err
		}
		collection.kibana = kibanaKeyPair

		// Add the ui-apis certificate to the collection. This is needed in case the user has enabled Kibana with mTLS.
		cert, err := cm.GetCertificate(r.client, render.ManagerInternalTLSSecretName, render.ManagerNamespace)
		if err != nil && !errors.IsNotFound(err) {
			return nil, err
		} else {
			collection.upstreamCerts = append(collection.upstreamCerts, cert)
		}
	}

	// Collect the Linseed certificate, which must be trusted by Elasticsearch.
	cert, err := cm.GetCertificate(r.client, render.TigeraLinseedSecret, render.ElasticsearchNamespace)
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	} else {
		collection.upstreamCerts = append(collection.upstreamCerts, cert)
	}

	return &collection, nil
}

// generateSecrets creates keypairs for Tigera components within the LogStorage subsystem.
func (r *SecretSubController) generateSecrets(
	log logr.Logger,
	helper eutils.NamespaceHelper,
	cm certificatemanager.CertificateManager,
	managementCluster *operatorv1.ManagementCluster,
	install *operatorv1.InstallationSpec,
) (*keyPairCollection, error) {
	// Start by collecting upstream certificates that we need to trust, before generating keypairs.
	collection, err := r.collectUpstreamCerts(log, helper, cm, install)
	if err != nil {
		return nil, err
	}

	if !r.multiTenant {
		// Create a server key pair for the ES metrics server.
		metricsDNSNames := dns.GetServiceDNSNames(esmetrics.ElasticsearchMetricsName, helper.InstallNamespace(), r.clusterDomain)
		metricsServerKeyPair, err := cm.GetOrCreateKeyPair(r.client, esmetrics.ElasticsearchMetricsServerTLSSecret, helper.TruthNamespace(), metricsDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error finding or creating TLS certificate", err, log)
			return nil, err
		}
		collection.keypairs = append(collection.keypairs, metricsServerKeyPair)

		// For legacy reasons, es-gateway is sitting behind two services: tigera-secure-es-http (where originally ES resided)
		// and tigera-secure-es-gateway-http.
		gatewayDNSNames := append(
			dns.GetServiceDNSNames(render.ElasticsearchServiceName, helper.InstallNamespace(), r.clusterDomain),
			dns.GetServiceDNSNames(esgateway.ServiceName, helper.InstallNamespace(), r.clusterDomain)...,
		)
		gatewayKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraElasticsearchGatewaySecret, helper.TruthNamespace(), gatewayDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
			return nil, err
		}
		collection.keypairs = append(collection.keypairs, gatewayKeyPair)
	}

	// Create a server key pair for Linseed to present to clients.
	//
	// This fetches the existing key pair from the truth namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, helper.InstallNamespace(), r.clusterDomain)
	linseedKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedSecret, helper.TruthNamespace(), linseedDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return nil, err
	}
	collection.keypairs = append(collection.keypairs, linseedKeyPair)

	if managementCluster != nil {
		// Create a key pair for Linseed to use for tokens.
		linseedTokenKP, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedTokenSecret, helper.TruthNamespace(), []string{render.TigeraLinseedTokenSecret})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
			return nil, err
		}
		collection.keypairs = append(collection.keypairs, linseedTokenKP)
	}

	return collection, nil
}

// collectUpstreamCerts collects certificates generated by upstream components to be added to the trusted bundle
// provisioned by this controller.
func (r *SecretSubController) collectUpstreamCerts(log logr.Logger, helper eutils.NamespaceHelper, cm certificatemanager.CertificateManager, install *operatorv1.InstallationSpec) (*keyPairCollection, error) {
	collection := keyPairCollection{log: log}

	// Get upstream certificates that we depend on, but aren't created by this controller. Some of these are
	// only relevant for certain cluster types, so we will build the collection even if they aren't present and
	// add them in later if they appear.
	//
	// These certificates are used as part of the trusted bundle for verifying TLS connections. Generally, these will be
	// redundant because all certificates will be signed by the root CA. However, in some scenarios custom certificates may
	// be used, in which case they must be present in the bundle.
	//
	// Each entry is the name of the secret, and the value is the Namespace to query it from.
	certs := map[string]string{
		// Get certificate for TLS on Prometheus metrics endpoints. This is created in the monitor controller.
		monitor.PrometheusClientTLSSecretName: common.OperatorNamespace(),

		// Get certificate for ui-apis, which Linseed and es-gateway need to trust.
		render.ManagerInternalTLSSecretName: helper.TruthNamespace(),

		// Get certificate for fluent-bit, which Linseed needs to trust in a standalone or management cluster.
		logcollector.FluentBitTLSSecretName: common.OperatorNamespace(),

		// Get certificate for intrusion detection controller, which Linseed needs to trust in a standalone or management cluster.
		render.IntrusionDetectionTLSSecretName: helper.TruthNamespace(),

		// Get certificate for DPI, which Linseed needs to trust in a standalone or management cluster.
		render.DPITLSSecretName: helper.TruthNamespace(),

		// Get certificate for policy-recommendation, which Linseed needs to trust.
		render.PolicyRecommendationTLSSecretName: helper.TruthNamespace(),

		// es-gateay and Linseed need to trust certificates signed by the root tigera-operator CA.
		certificatemanagement.CASecretName: common.OperatorNamespace(),
	}

	if r.isEKSLogForwardingEnabled(install) {
		certs[logcollector.EKSLogForwarderTLSSecretName] = common.OperatorNamespace()
	}

	if r.elasticExternal {
		// For external ES, we don't need to generate a keypair for ES itself. Instead, a public certificate
		// for the external ES and Kibana instances must be provided. Load and include in these into
		// the trusted bundle for Linseed and es-gateway.
		certs[logstorage.ExternalESPublicCertName] = common.OperatorNamespace()
		certs[logstorage.ExternalKBPublicCertName] = common.OperatorNamespace()
	} else {
		// For internal ES, the operator creates a keypair for ES and Kibana itself earlier in the execution of this controller.
		// Include these in the trusted bundle as well, so that Linseed and es-gateway can trust them.
		certs[render.TigeraElasticsearchInternalCertSecret] = common.OperatorNamespace()
		certs[kibana.TigeraKibanaCertSecret] = common.OperatorNamespace()
	}

	// Sort the keys then add them to the upstreamCerts in that order so the keys are always in the same order
	keys := make([]string, 0, len(certs))
	for k := range certs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, certName := range keys {
		certNamespace := certs[certName]
		cert, err := cm.GetCertificate(r.client, certName, certNamespace)
		if err != nil {
			if certificatemanager.IsCertExtKeyUsageError(err) {
				// This secret is missing required key usages. Another controller will need to replace this secret with a
				// new valid secret, before this controller will read and use it. The other controller may depend on this
				// controller completing successfully. Therefore, we skip and continue.
				log.Info(fmt.Sprintf("skipping %s/%s secret it will be added when it is updated: %s", common.OperatorNamespace(), certName, err))
			} else {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get certificate", err, log)
				return nil, err
			}
		} else if cert == nil {
			msg := fmt.Sprintf("%s/%s secret not available yet, will add it if/when it becomes available", certNamespace, certName)
			log.Info(msg)
		} else {
			log.V(2).Info("Adding upstream certificate", "cert", certName)
			collection.upstreamCerts = append(collection.upstreamCerts, cert)
		}
	}

	return &collection, nil
}

func (r *SecretSubController) isEKSLogForwardingEnabled(install *operatorv1.InstallationSpec) bool {
	if install.KubernetesProvider.IsEKS() {
		instance := &operatorv1.LogCollector{}
		err := r.client.Get(context.Background(), utils.DefaultEnterpriseInstanceKey, instance)
		if err != nil {
			log.Error(err, "Error loading logcollector, Unable to check whether EKS Log Forwarding is enabled")
			return false
		}

		if instance.Spec.AdditionalSources != nil {
			if instance.Spec.AdditionalSources.EksCloudwatchLog != nil {
				return true
			}
		}
	}
	return false
}

// elasticKeyPairCollection is a helper struct for managing elastic and kibana key pairs.
type elasticKeyPairCollection struct {
	// Context logger to use.
	log logr.Logger

	elastic       certificatemanagement.KeyPairInterface
	kibana        certificatemanagement.KeyPairInterface
	upstreamCerts []certificatemanagement.CertificateInterface
}

// trustedBundle creates a certificate bundle using the keypairs and certificates from the collection.
func (c *elasticKeyPairCollection) trustedBundle(cm certificatemanager.CertificateManager) certificatemanagement.TrustedBundle {
	certs := []certificatemanagement.CertificateInterface{c.elastic, c.kibana}
	certs = append(certs, c.upstreamCerts...)
	return cm.CreateTrustedBundle(certs...)
}

func (c *elasticKeyPairCollection) internalESComponent() render.Component {
	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      render.ElasticsearchNamespace,
		TruthNamespace: common.OperatorNamespace(),
		ServiceAccounts: []string{
			render.ElasticsearchObjectName,
		},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			// We do not want to delete the elastic keypair secret from the tigera-elasticsearch namespace when CertificateManagement is
			// enabled. Instead, it will be replaced with a dummy secret that serves merely to pass ECK's validation checks.
			rcertificatemanagement.NewKeyPairOption(c.elastic, true, c.elastic != nil && !c.elastic.UseCertificateManagement()),
		},

		// We don't create a trusted bundle as part of the elastic component - this is just to install the keypair secret.
		// Internal ES is always zero-tenant or single-tenant, and thus always runs components in the tigera-elasticsearch namespace.
		// As such, the trusted bundle for elasticsearch, Linseed, es-gateway, etc. is shared between all components.
		// The trusted bundle will be installed later, and include other upstream certificates to support the aforementioend
		// components as well.
		TrustedBundle: nil,
	})
}

func (c *elasticKeyPairCollection) internalKibanaComponent(bundle certificatemanagement.TrustedBundle) render.Component {
	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       kibana.Namespace,
		ServiceAccounts: []string{kibana.ObjectName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			// We do not want to delete the secret from the tigera-elasticsearch when CertificateManagement is
			// enabled. Instead, it will be replaced with a TLS secret that serves merely to pass ECK's validation
			// checks.
			rcertificatemanagement.NewKeyPairOption(c.kibana, true, c.kibana != nil && !c.kibana.UseCertificateManagement()),
		},
		TrustedBundle: bundle,
	})
}

// A helper struct for managing the multitude of Tigera component secrets that are managed by or
// used by this controller.
type keyPairCollection struct {
	// Context logger to use.
	log logr.Logger

	// Certificates that need to be added to the trusted bundle, but
	// aren't actually generated by this controller.
	// Prometheus, ui-apis, fluent-bit, all compliance components.
	upstreamCerts []certificatemanagement.CertificateInterface

	// Key pairs that are generated by this controller. These need to be
	// provisioned into a namespace, as well as added to the trusted bundle.
	keypairs []certificatemanagement.KeyPairInterface
}

// trustedBundle creates a certificate bundle using the keypairs and certificates from the collection.
func (c *keyPairCollection) trustedBundle(cm certificatemanager.CertificateManager) certificatemanagement.TrustedBundle {
	certs := []certificatemanagement.CertificateInterface{}
	for _, key := range c.keypairs {
		certs = append(certs, key.(certificatemanagement.CertificateInterface))
	}
	certs = append(certs, c.upstreamCerts...)
	return cm.CreateTrustedBundle(certs...)
}

func (c keyPairCollection) component(bundle certificatemanagement.TrustedBundle, request eutils.NamespaceHelper) render.Component {
	// Create a render.Component to provision or update key pairs and the trusted bundle.
	kpos := []rcertificatemanagement.KeyPairOption{}

	// For each keypair collection provided, create a KeyPairOption to provision the keys into
	// both the truth namespace and the install namespace.
	for _, kp := range c.keypairs {
		kpos = append(kpos, rcertificatemanagement.NewKeyPairOption(kp, true, true))
	}

	tb := bundle
	if request.MultiTenant() {
		// Multi-tenant management clusters don't use the trusted bundle generated by this controller. Rather, since each
		// tenant has its own namespace, we generate a trusted bundle separately for each tenant in the top-level secrets controller.
		// This ensures that other controllers with a limited understanding of what is needed in the bundle don't fight over ownership.
		// See pkg/controller/secrets/tenant_controller.go for more details on trusted bundle management in multi-tenant clusters.
		tb = nil
	}

	return rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      request.InstallNamespace(),
		TruthNamespace: request.TruthNamespace(),
		ServiceAccounts: []string{
			linseed.ServiceAccountName,
			esgateway.ServiceAccountName,
			esmetrics.ElasticsearchMetricsName,
		},
		KeyPairOptions: kpos,
		TrustedBundle:  tb,
	})
}
