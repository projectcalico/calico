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

package manager

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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
	"github.com/tigera/operator/pkg/controller/compliance"
	lscommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	rmanager "github.com/tigera/operator/pkg/render/manager"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const (
	ResourceName        = "manager"
	TrustedBundlePrefix = render.ManagerName
)

var log = logf.Log.WithName("controller_manager")

// Add creates a new Manager Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}

	licenseAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}

	// create the reconciler
	reconciler := newReconciler(mgr, opts, licenseAPIReady, tierWatchReady)

	// Create a new controller
	c, err := ctrlruntime.NewController("manager-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create manager-controller: %w", err)
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
	}

	// Make a helper for determining which namespaces to use based on tenancy mode.
	helper := utils.NewNamespaceHelper(opts.MultiTenant, render.ManagerNamespace, "")

	if err := utils.AddSecretsWatch(c, render.VoltronLinseedTLS, helper.InstallNamespace()); err != nil {
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)
	policiesToWatch := []types.NamespacedName{
		{Name: render.ManagerPolicyName, Namespace: helper.InstallNamespace()},
	}
	// The default-deny policy in calico-system is owned by the Installation
	// controller; only watch it here when we render it ourselves, i.e. in
	// multi-tenant mode where the Manager lives in a tenant namespace.
	if helper.InstallNamespace() != common.CalicoNamespace {
		policiesToWatch = append(policiesToWatch, types.NamespacedName{
			Name:      networkpolicy.CalicoComponentDefaultDenyPolicyName,
			Namespace: helper.InstallNamespace(),
		})
	}
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, policiesToWatch)

	// Watch for changes to primary resource Manager
	err = c.WatchObject(&operatorv1.Manager{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	err = c.WatchObject(&operatorv1.TLSTerminatedRoute{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch TLSTerminatedRoutes: %w", err)
	}

	err = c.WatchObject(&operatorv1.TLSPassThroughRoute{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch TLSPassThroughRoutes: %w", err)
	}

	// Watch for other operator.tigera.io resources.
	if err = c.WatchObject(&operatorv1.Installation{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch Installation resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.APIServer{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch APIServer resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.Compliance{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch APIServer resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.NonClusterHost{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.Authentication{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("manager-controller failed to watch manager Tigerastatus: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ImageSet{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch ImageSet: %w", err)
	}
	if err = c.WatchObject(&operatorv1.LogStorage{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch LogStorage resource: %w", err)
	}
	if opts.MultiTenant {
		if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("manager-controller failed to watch Tenant resource: %w", err)
		}
	}

	// Watch any secrets that this controller depends upon.
	namespacesToWatch := []string{helper.TruthNamespace(), helper.InstallNamespace()}
	if helper.TruthNamespace() == helper.InstallNamespace() {
		namespacesToWatch = []string{helper.InstallNamespace()}
	}
	for _, namespace := range namespacesToWatch {
		for _, secretName := range []string{
			// We need to watch for es-gateway certificate because ui-apis still creates a
			// client to talk to elastic via es-gateway
			render.ManagerTLSSecretName, relasticsearch.PublicCertSecret,
			render.VoltronTunnelSecretName, render.VoltronAdditionalTunnelSecretName,
			render.ComplianceServerCertSecret, render.PacketCaptureServerCert,
			render.ManagerInternalTLSSecretName, monitor.PrometheusServerTLSSecretName, certificatemanagement.CASecretName,
		} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("manager-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	if err = utils.AddConfigMapWatch(c, tigerakvc.StaticWellKnownJWKSConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("manager-controller failed to watch ConfigMap resource %s: %w", tigerakvc.StaticWellKnownJWKSConfigMapName, err)
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err = utils.AddNamespaceWatch(c, common.TigeraPrometheusNamespace); err != nil {
		return fmt.Errorf("manager-controller failed to watch the '%s' namespace: %w", common.TigeraPrometheusNamespace, err)
	}

	if !opts.ElasticExternal {
		if err = utils.AddConfigMapWatch(c, eck.LicenseConfigMapName, eck.OperatorNamespace, eventHandler); err != nil {
			return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
		}
	}

	if opts.Cloud {
		if err = addCloudWatch(c, eventHandler, opts.ElasticExternal); err != nil {
			return fmt.Errorf("manager-controller failed to add CC watches: %v", err)
		}
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, licenseAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	c := &ReconcileManager{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		status:          status.New(mgr.GetClient(), "manager", opts.KubernetesVersion),
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		opts:            opts,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

var _ reconcile.Reconciler = &ReconcileManager{}

// ReconcileManager reconciles a Manager object.
type ReconcileManager struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	opts            options.ControllerOptions
}

// Reconcile reads that state of the cluster for a Manager object and makes changes based on the state read
// and what is in the Manager.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileManager) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	// Perform any common preparation that needs to be done for single-tenant and multi-tenant scenarios.
	helper := utils.NewNamespaceHelper(r.opts.MultiTenant, render.ManagerNamespace, request.Namespace)
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace(), "multi-tenant", r.opts.MultiTenant)
	logc.Info("Reconciling Manager")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.opts.MultiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// Check if this is a tenant-scoped request.
	tenant, _, err := utils.GetTenant(ctx, r.opts.MultiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		logc.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, logc)
		return reconcile.Result{}, err
	}

	// Fetch the Manager instance that corresponds with this reconcile trigger.
	instance, err := utils.GetManager(ctx, r.client, r.opts.MultiTenant, request.Namespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Manager", err, logc)
		return reconcile.Result{}, err
	}
	if instance == nil {
		logc.Info("Manager object not found")
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}
	logc.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating Manager status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create Manager status conditions.")
			return reconcile.Result{}, err
		}
	}

	if !utils.IsProjectCalicoV3Available(r.client, r.opts, logc) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, logc)
		return reconcile.Result{}, nil
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, logc)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// TODO: Do we need a license per-tenant in the management cluster?
	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, logc)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	variant, installationSpec, err := utils.GetInstallationSpec(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, logc)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, logc)
		return reconcile.Result{}, err
	}

	// When creating the certificate manager, pass in the logger and tenant (if one exists).
	opts := []certificatemanager.Option{
		certificatemanager.WithLogger(logc),
		certificatemanager.WithTenant(tenant),
	}
	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.opts.ClusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, logc)
		return reconcile.Result{}, err
	}
	dnsNames := dns.GetServiceDNSNames(render.ManagerServiceName, helper.InstallNamespace(), r.opts.ClusterDomain)

	// Continue to add in the legacy names and namespaces of manager components to cover version skew scenarios. These
	// can be removed in v3.26 when the oldest version we will officially support will use the newer names and namespace
	var legacyInstallNamespace string
	if r.opts.MultiTenant {
		legacyInstallNamespace = helper.InstallNamespace()
	} else {
		legacyInstallNamespace = render.LegacyManagerNamespace
	}
	legacyDNSNames := dns.GetServiceDNSNames(render.LegacyManagerServiceName, legacyInstallNamespace, r.opts.ClusterDomain)
	dnsNames = append(dnsNames, legacyDNSNames...)

	// Get or create a certificate for clients of the manager pod ui-apis container.
	tlsSecret, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		render.ManagerTLSSecretName,
		helper.TruthNamespace(),
		append([]string{"localhost"}, dnsNames...))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating manager TLS certificate", err, logc)
		return reconcile.Result{}, err
	}

	// Get or create a certificate for the manager pod to use within the cluster.
	internalTrafficSecret, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		render.ManagerInternalTLSSecretName,
		helper.TruthNamespace(),
		dnsNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.CertificateError, fmt.Sprintf("Error ensuring internal manager TLS certificate %q exists and has valid DNS names", render.ManagerInternalTLSSecretName), err, logc)
		return reconcile.Result{}, err
	}

	// Determine if compliance is enabled.
	complianceLicenseFeatureActive := utils.IsFeatureActive(license, common.ComplianceFeature)
	complianceCR, err := compliance.GetCompliance(ctx, r.client, r.opts.MultiTenant, request.Namespace)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying compliance: ", err, logc)
		return reconcile.Result{}, err
	}

	// Build a trusted bundle containing all of the certificates of components that communicate with the manager pod.
	// This bundle contains the root CA used to sign all operator-generated certificates, as well as the explicitly named
	// certificates, in case the user has provided their own cert in lieu of the default certificate.

	var trustedSecretNames []string
	if !r.opts.MultiTenant {
		// For multi-tenant systems, we don't support user-provided certs for all components. So, we don't need to include these,
		// and the bundle will simply use the root CA for the tenant. For single-tenant systems, we need to include these in case
		// any of them haven't been signed by the root CA.
		trustedSecretNames = []string{
			render.CalicoAPIServerTLSSecretName,
			render.TigeraLinseedSecret,
		}

		packetcaptureapi, err := utils.GetPacketCaptureAPI(ctx, r.client)
		if err != nil && !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying PacketCapture CR", err, logc)
			return reconcile.Result{}, err
		}
		if packetcaptureapi != nil {
			trustedSecretNames = append(trustedSecretNames, render.PacketCaptureServerCert)
		}

		// This is necessary because prior to v3.13 secrets were not signed by a single CA, so we need to include each individually
		// in the trusted bundle
		esgwCertificate, err := certificateManager.GetCertificate(r.client, relasticsearch.PublicCertSecret, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve / validate  %s", relasticsearch.PublicCertSecret), err, logc)
			return reconcile.Result{}, err
		}
		if esgwCertificate != nil {
			trustedSecretNames = append(trustedSecretNames, relasticsearch.PublicCertSecret)
		}

		// If external prometheus is enabled, the secret will be signed by the Calico CA and no secret will be created. We can skip
		// adding it to the bundle, as trusting the CA will suffice.
		monitorCR := &operatorv1.Monitor{}
		if err := r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, monitorCR); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying required Monitor resource: ", err, logc)
			return reconcile.Result{}, err
		}
		if monitorCR.Spec.ExternalPrometheus == nil {
			trustedSecretNames = append(trustedSecretNames, monitor.PrometheusServerTLSSecretName)
		}

		if complianceLicenseFeatureActive && complianceCR != nil {
			// Check that compliance is running.
			if complianceCR.Status.State != operatorv1.TigeraStatusReady {
				r.status.SetDegraded(operatorv1.ResourceNotReady, "Compliance is not ready", nil, logc)
				return reconcile.Result{}, nil
			}
			trustedSecretNames = append(trustedSecretNames, render.ComplianceServerCertSecret)
		}
	}

	var authenticationCR *operatorv1.Authentication
	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err = utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, logc)
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready authenticationCR status: %s", authenticationCR.Status.State), nil, logc)
		return reconcile.Result{}, nil
	} else if utils.DexEnabled(authenticationCR) {
		trustedSecretNames = append(trustedSecretNames, render.DexTLSSecretName)
	}

	bundleMaker, err := certificateManager.CreateNamedTrustedBundleFromSecrets(TrustedBundlePrefix, r.client,
		helper.TruthNamespace(), false, trustedSecretNames...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating trusted bundle for manager", err, logc)
	}

	// Handle all the resources that are specific to Calico Cloud. For non-cloud installs this is
	// skipped entirely, leaving mcr at its zero value and enterprise behavior unchanged.
	var mcr render.ManagerCloudResources
	if r.opts.Cloud {
		var reconcileResult *reconcile.Result
		bundleMaker, mcr, tenant, reconcileResult, err = r.handleCloudReconcile(
			ctx,
			logc,
			helper,
			tenant,
			authenticationCR,
			certificateManager,
			bundleMaker,
			trustedSecretNames,
			request.Namespace,
		)
		if err != nil {
			// status degraded should already be set by r.handleCloudReconcile
			return reconcile.Result{}, err
		} else if reconcileResult != nil {
			return *reconcileResult, nil
		}
	}

	certificateManager.AddToStatusManager(r.status, helper.InstallNamespace())

	// Check that Prometheus is running
	// TODO: We'll need to run an instance of Prometheus per-tenant? Or do we use labels to delimit metrics?
	//       Probably the former.
	ns := &corev1.Namespace{}
	if err = r.client.Get(ctx, client.ObjectKey{Name: common.TigeraPrometheusNamespace}, ns); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "tigera-prometheus namespace does not exist Dependency on tigera-prometheus not satisfied", nil, logc)
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying prometheus", err, logc)
		}
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, logc)
		return reconcile.Result{}, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, logc)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, logc)
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, logc)
		return reconcile.Result{}, err
	}

	// Es-proxy needs to trust Voltron for cross-cluster requests.
	bundleMaker.AddCertificates(internalTrafficSecret)

	var linseedVoltronServerCert certificatemanagement.KeyPairInterface
	var tunnelServerCert certificatemanagement.KeyPairInterface
	var tunnelSecretPassthrough render.Component

	if managementCluster != nil {
		preDefaultPatchFrom := client.MergeFrom(managementCluster.DeepCopy())
		fillDefaults(managementCluster)

		// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
		// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
		if err := r.client.Patch(ctx, managementCluster, preDefaultPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "", err, logc)
			return reconcile.Result{}, err
		}

		// Create a certificate for Voltron to use when serving TLS connections from managed clusters destined
		// to Linseed. This certificate is used only for connections received over Voltron's mTLS tunnel targeting tigera-linseed.
		// The public cert from this keypair is sent by es-kube-controllers to managed clusters so that linseed clients in those clusters
		// can authenticate the certificate presented by Voltron.
		linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, render.ElasticsearchNamespace, r.opts.ClusterDomain)
		linseedVoltronServerCert, err = certificateManager.GetOrCreateKeyPair(
			r.client,
			render.VoltronLinseedTLS,
			helper.TruthNamespace(),
			linseedDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating Voltron Linseed TLS certificate", err, logc)
			return reconcile.Result{}, err
		}

		// Query the tunnel server certificate used by Voltron to serve mTLS connections from managed clusters.
		tunnelSecretName := managementCluster.Spec.TLS.SecretName
		// For multi-tenant clusters, ensure that we have a CA that can be used to sign the tunnel server cert within this tenant's namespace.
		// For single-tenant cluster, ensure that we have a CA that can be used to sign the tunnel server cert in operator namespace.
		// This certificate will also be presented by Voltron to prove its identity to managed clusters.
		tunnelCASecret, err := utils.GetSecret(ctx, r.client, tunnelSecretName, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to fetch the tunnel secret", err, logc)
			return reconcile.Result{}, err
		}

		// Single tenant MCM clusters will use "voltron" as a server name to establish mTLS connection
		serverName := "voltron"
		if r.opts.MultiTenant {
			// Multi-tenant MCM clusters will use the tenat ID as a server name to establish mTLS connection
			serverName = tenant.Spec.ID
		}

		if tunnelCASecret == nil {
			tunnelCASecret, err = certificatemanagement.CreateSelfSignedSecret(tunnelSecretName, helper.TruthNamespace(), "tigera-voltron", []string{serverName})
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the tunnel secret", err, logc)
				return reconcile.Result{}, err
			}
		} else {
			// Check controller references and remove any old APIServer ownership, since ownership of this resource has moved
			// to the manager controller instead. Without this, we will hit an error when trying to update the secret as it will
			// have two controllers set.
			for i := 0; i < len(tunnelCASecret.OwnerReferences); i++ {
				ref := tunnelCASecret.OwnerReferences[i]
				if ref.Kind == "APIServer" && ref.Controller != nil && *ref.Controller {
					tunnelCASecret.OwnerReferences = append(tunnelCASecret.OwnerReferences[:i], tunnelCASecret.OwnerReferences[i+1:]...)
					i--
				}
			}
		}

		// We use the CA as the server cert.
		tunnelServerCert = certificatemanagement.NewKeyPair(tunnelCASecret, nil, "")
		tunnelSecretPassthrough = render.NewCreationPassthrough(tunnelCASecret)
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.opts.ClusterDomain, r.opts.Cloud && !r.opts.MultiTenant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to process the authentication CR.", err, logc)
		return reconcile.Result{}, err
	}

	elasticLicenseType := render.ElasticsearchLicenseTypeBasic
	if !r.opts.ElasticExternal && managementClusterConnection == nil {
		if elasticLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, logc); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch license", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered component.
	defaultHandler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Set replicas to 1 for management or managed clusters.
	// TODO Remove after MCM tigera-manager HA deployment is supported.
	replicas := installationSpec.ControlPlaneReplicas
	if managementCluster != nil || managementClusterConnection != nil {
		var mcmReplicas int32 = 1
		replicas = &mcmReplicas
	}

	trustedBundle := bundleMaker.(certificatemanagement.TrustedBundleRO)
	if r.opts.MultiTenant {
		// For multi-tenant systems, we load the pre-created bundle for this tenant instead of using the one we built here.
		// Multi-tenant managers need the bundle variant that includes system root certificates, in order to verify external auth providers.
		trustedBundle, err = certificateManager.LoadMultiTenantTrustedBundleWithRootCertificates(ctx, r.client, helper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, logc)
			return reconcile.Result{}, err
		}
		bundleMaker = nil
	}

	// Determine the namespaces to which we must bind the cluster role.
	namespaces, err := helper.FilteredTenantNamespaces(r.client, utils.ManagedEnterpriseOnly)
	if err != nil {
		return reconcile.Result{}, err
	}
	ossTenantNamespaces, err := helper.FilteredTenantNamespaces(r.client, utils.ManagedCalicoOnly)
	if err != nil {
		return reconcile.Result{}, err
	}

	routeConfig, err := getVoltronRouteConfig(ctx, r.client, helper.InstallNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.InternalServerError, "Failed to create Voltron Route Configuration", err, logc)
		return reconcile.Result{}, err
	}

	// Check if non-cluster host feature is enabled.
	nonclusterhost, err := utils.GetNonClusterHost(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query NonClusterHost resource", err, logc)
		return reconcile.Result{}, err
	}
	if nonclusterhost != nil {
		if _, _, _, err := url.ParseEndpoint(nonclusterhost.Spec.Endpoint); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read parse endpoint from NonClusterHost resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	// If an additional tunnel CA secret has been provisioned in the truth namespace, Voltron
	// will mount it and serve TLS from it. This is only relevant for management clusters
	// (Voltron is what consumes the additional CA). The secret is managed out-of-band; the
	// controller just watches and consumes it.
	var additionalTunnelServerCert certificatemanagement.KeyPairInterface
	if managementCluster != nil {
		additionalTunnelServerCert, err = r.resolveAdditionalTunnelCert(ctx, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error resolving additional tunnel CA", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Determine if Kibana is enabled based on multi-tenancy and LogStorage replicas.
	kibanaEnabled := !r.opts.MultiTenant
	if kibanaEnabled {
		ls := &operatorv1.LogStorage{}
		if err := r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, ls); err != nil {
			if !errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query LogStorage resource", err, logc)
				return reconcile.Result{}, err
			}
		} else {
			kibanaEnabled = lscommon.KibanaEnabled(ls, r.opts.MultiTenant)
		}
	}

	managerCfg := &render.ManagerConfiguration{
		VoltronRouteConfig:         routeConfig,
		KeyValidatorConfig:         keyValidatorConfig,
		TrustedCertBundle:          trustedBundle,
		TLSKeyPair:                 tlsSecret,
		VoltronLinseedKeyPair:      linseedVoltronServerCert,
		PullSecrets:                pullSecrets,
		OpenShift:                  r.opts.DetectedProvider.IsOpenShift(),
		Installation:               installationSpec,
		ManagementCluster:          managementCluster,
		NonClusterHost:             nonclusterhost,
		TunnelServerCert:           tunnelServerCert,
		AdditionalTunnelServerCert: additionalTunnelServerCert,
		InternalTLSKeyPair:         internalTrafficSecret,
		ClusterDomain:              r.opts.ClusterDomain,
		ESLicenseType:              elasticLicenseType,
		Replicas:                   replicas,
		Compliance:                 complianceCR,
		ComplianceLicenseActive:    complianceLicenseFeatureActive,
		ComplianceNamespace:        utils.NewNamespaceHelper(r.opts.MultiTenant, render.ComplianceNamespace, request.Namespace).InstallNamespace(),
		Namespace:                  helper.InstallNamespace(),
		TruthNamespace:             helper.TruthNamespace(),
		Tenant:                     tenant,
		ExternalElastic:            r.opts.ElasticExternal,
		BindingNamespaces:          namespaces,
		OSSTenantNamespaces:        ossTenantNamespaces,
		Manager:                    instance,
		Authentication:             authenticationCR,
		KibanaEnabled:              kibanaEnabled,
		CACertCommonName:           certificateManager.CACertCommonName(),
		Cloud:                      r.opts.Cloud,
		CloudResources:             mcr,
	}

	// Render the desired objects from the CRD and create or update them.
	component, err := render.Manager(managerCfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering Manager", err, logc)
		return reconcile.Result{}, err
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		// Install manager components.
		component,

		// Installs KeyPairs and trusted bundle (if not pre-installed)
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       helper.InstallNamespace(),
			TruthNamespace:  helper.TruthNamespace(),
			ServiceAccounts: []string{render.ManagerServiceAccount},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(tlsSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(linseedVoltronServerCert, true, true),
				rcertificatemanagement.NewKeyPairOption(internalTrafficSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(tunnelServerCert, false, true),
				rcertificatemanagement.NewKeyPairOption(additionalTunnelServerCert, false, true),
			},
			TrustedBundle: bundleMaker,
		}),
	}

	if tunnelSecretPassthrough != nil {
		components = append(components, tunnelSecretPassthrough)
	}

	for _, component := range components {
		if err := defaultHandler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Check BYO certificate expiry warnings.
	certificatemanagement.CheckKeyPairWarnings(map[string]certificatemanagement.KeyPairInterface{
		render.ManagerTLSSecretName:         tlsSecret,
		render.ManagerInternalTLSSecretName: internalTrafficSecret,
		render.VoltronLinseedTLS:            linseedVoltronServerCert,
	}, r.status)

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	instance.Status.State = operatorv1.TigeraStatusReady
	if r.status.IsAvailable() {
		if err = r.client.Status().Update(ctx, instance); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func fillDefaults(mc *operatorv1.ManagementCluster) {
	if mc.Spec.TLS == nil {
		mc.Spec.TLS = &operatorv1.TLS{}
	}
	if mc.Spec.TLS.SecretName == "" {
		mc.Spec.TLS.SecretName = render.VoltronTunnelSecretName
	}
}

func getVoltronRouteConfig(ctx context.Context, cli client.Client, managerNamespace string) (*rmanager.VoltronRouteConfig, error) {
	terminatedRouteList := &operatorv1.TLSTerminatedRouteList{}
	if err := cli.List(ctx, terminatedRouteList, client.InNamespace(managerNamespace)); err != nil {
		return nil, err
	}

	passThroughRouteList := &operatorv1.TLSPassThroughRouteList{}
	if err := cli.List(ctx, passThroughRouteList, client.InNamespace(managerNamespace)); err != nil {
		return nil, err
	}

	if len(terminatedRouteList.Items) == 0 && len(passThroughRouteList.Items) == 0 {
		return nil, nil
	}

	builder := rmanager.NewVoltronRouteConfigBuilder()
	for _, route := range terminatedRouteList.Items {
		if route.Spec.CABundle != nil {
			cm := &corev1.ConfigMap{}
			// Verify that the ConfigMap exists in the manager namespace.
			if err := cli.Get(ctx, client.ObjectKey{Name: route.Spec.CABundle.Name, Namespace: managerNamespace}, cm); err != nil {
				return nil, fmt.Errorf("failed to retrieve the ConfigMap containing the CA for TLS terminated route %s: %w", route.Name, err)
			}

			// Add the config map to the builder to rerender the annotations if it changes.
			builder.AddConfigMap(cm)
		}

		if route.Spec.ForwardingMTLSCert != nil {
			certSecret := &corev1.Secret{}
			// Verify that the MTLS cert secret exist in the manager namespace.
			if err := cli.Get(ctx, client.ObjectKey{Name: route.Spec.ForwardingMTLSCert.Name, Namespace: managerNamespace}, certSecret); err != nil {
				return nil, fmt.Errorf("failed to retrieve the Secret containing the MTLS certificate for TLS terminated route %s: %w", route.Name, err)
			}

			builder.AddSecret(certSecret)
		}

		if route.Spec.ForwardingMTLSKey != nil {
			keySecret := &corev1.Secret{}
			// Verify that the MTLS secrets exist in the manager namespace.
			if err := cli.Get(ctx, client.ObjectKey{Name: route.Spec.ForwardingMTLSKey.Name, Namespace: managerNamespace}, keySecret); err != nil {
				return nil, fmt.Errorf("failed to retrieve the Secret containing the MTLS key for TLS terminated route %s: %w", route.Name, err)
			}

			builder.AddSecret(keySecret)
		}

		builder.AddTLSTerminatedRoute(route)
	}

	for _, route := range passThroughRouteList.Items {
		builder.AddTLSPassThroughRoute(route)
	}

	return builder.Build()
}

// resolveAdditionalTunnelCert looks up the additional tunnel CA secret in the truth namespace.
// When the secret is present, a KeyPair is returned so that Voltron mounts the CA and gets the
// corresponding environment variables set. When the secret is absent, (nil, nil) is returned and
// Voltron runs without the additional CA. The secret is created and rotated out-of-band; this
// controller only consumes it.
func (r *ReconcileManager) resolveAdditionalTunnelCert(
	ctx context.Context,
	truthNamespace string,
) (certificatemanagement.KeyPairInterface, error) {
	secret, err := utils.GetSecret(ctx, r.client, render.VoltronAdditionalTunnelSecretName, truthNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s secret: %w", render.VoltronAdditionalTunnelSecretName, err)
	}
	if secret == nil {
		return nil, nil
	}
	return certificatemanagement.NewKeyPair(secret, nil, ""), nil
}
