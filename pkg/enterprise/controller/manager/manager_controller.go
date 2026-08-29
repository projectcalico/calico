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
	stderrors "errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/gatewayapi"
	lscommon "github.com/tigera/operator/pkg/controller/logstorage/common"
	"github.com/tigera/operator/pkg/controller/logstorage/esutils"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	entcertificatemanager "github.com/tigera/operator/pkg/enterprise/certificatemanager"
	eutils "github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/rbacmanagement"
	rgateway "github.com/tigera/operator/pkg/render/gateway"
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
		eventHandler = eutils.EnqueueAllTenants(mgr.GetClient())
	}

	// Make a helper for determining which namespaces to use based on tenancy mode.
	helper := eutils.NewNamespaceHelper(opts.MultiTenant, render.ManagerNamespace, "")

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
	if err = c.WatchObject(&operatorv1.GatewayAPI{}, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch GatewayAPI resource: %w", err)
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
			render.PacketCaptureServerCert,
			render.ManagerInternalTLSSecretName, monitor.PrometheusServerTLSSecretName, certificatemanagement.CASecretName,
		} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("manager-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	// The gateway TLS secret is watched across all namespaces: the truth copy
	// lives in the operator namespace, the rendered copy in the
	// user-configurable gateway namespace.
	if err = utils.AddSecretsWatch(c, ManagerGatewayTLSSecretName, ""); err != nil {
		return fmt.Errorf("manager-controller failed to watch the secret '%s': %w", ManagerGatewayTLSSecretName, err)
	}

	// Gateway and HTTPRoute status transitions must re-run
	// gatewayUnhealthyReason so the Degraded state tracks gateway health.
	// The watch arms once the Gateway API CRDs exist. Gateway health lives
	// in status, which does not bump the generation, so the default
	// generation-based predicate would drop these events — match by name
	// and accept every event instead.
	gatewayWatchPredicate := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetName() == ManagerGatewayResourcePrefix+"-gateway" ||
			o.GetName() == ManagerGatewayResourcePrefix+"-route"
	})
	go utils.WaitToAddResourceWatch(c, opts.K8sClientset, log, nil, []client.Object{
		&gapi.Gateway{
			TypeMeta:   metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerGatewayResourcePrefix + "-gateway"},
		},
		&gapi.HTTPRoute{
			TypeMeta:   metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: ManagerGatewayResourcePrefix + "-route"},
		},
	}, gatewayWatchPredicate)

	if err = utils.AddConfigMapWatch(c, tigerakvc.StaticWellKnownJWKSConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("manager-controller failed to watch ConfigMap resource %s: %w", tigerakvc.StaticWellKnownJWKSConfigMapName, err)
	}

	// Watched so that toggling the RBAC management UI re-renders the access gated on it.
	if err = utils.AddConfigMapWatch(c, rbacmanagement.ConfigMapName, common.CalicoNamespace, eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch ConfigMap resource %s: %w", rbacmanagement.ConfigMapName, err)
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace(), eventHandler); err != nil {
		return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %w", err)
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
	helper := eutils.NewNamespaceHelper(r.opts.MultiTenant, render.ManagerNamespace, request.Namespace)
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace(), "multi-tenant", r.opts.MultiTenant)
	logc.Info("Reconciling Manager")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.opts.MultiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// Check if this is a tenant-scoped request.
	tenant, _, err := eutils.GetTenant(ctx, r.opts.MultiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		logc.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, logc)
		return reconcile.Result{}, err
	}

	// Fetch the Manager instance that corresponds with this reconcile trigger.
	instance, err := eutils.GetManager(ctx, r.client, r.opts.MultiTenant, request.Namespace)
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
	if _, err := utils.FetchLicenseKey(ctx, r.client); err != nil {
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
	installationSpec, err := utils.GetComputedInstallationSpec(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, logc)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, logc)
		return reconcile.Result{}, err
	}

	opts := []certificatemanager.Option{certificatemanager.WithLogger(logc)}
	certificateManager, err := entcertificatemanager.Create(r.client, installationSpec, r.opts.ClusterDomain, helper.TruthNamespace(), tenant, opts...)
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

		packetcaptureapi, err := eutils.GetPacketCaptureAPI(ctx, r.client)
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
	}

	var authenticationCR *operatorv1.Authentication
	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err = eutils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, logc)
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready authenticationCR status: %s", authenticationCR.Status.State), nil, logc)
		return reconcile.Result{}, nil
	} else if eutils.DexEnabled(authenticationCR) {
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

	managementCluster, err := eutils.GetManagementCluster(ctx, r.client)
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

	keyValidatorConfig, err := eutils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.opts.ClusterDomain, r.opts.Cloud && !r.opts.MultiTenant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to process the authentication CR.", err, logc)
		return reconcile.Result{}, err
	}

	elasticLicenseType := render.ElasticsearchLicenseTypeBasic
	if !r.opts.ElasticExternal && managementClusterConnection == nil {
		if elasticLicenseType, err = esutils.GetElasticLicenseType(ctx, r.client, logc); err != nil {
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
		trustedBundle, err = entcertificatemanager.LoadTenantBundleWithSystemRootCertificates(ctx, certificateManager, r.client, helper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, logc)
			return reconcile.Result{}, err
		}
		bundleMaker = nil
	}

	// Determine the namespaces to which we must bind the cluster role.
	namespaces, err := eutils.HelperNamespaces(ctx, r.client, helper, eutils.ManagedEnterpriseOnly)
	if err != nil {
		return reconcile.Result{}, err
	}
	ossTenantNamespaces, err := eutils.HelperNamespaces(ctx, r.client, helper, eutils.ManagedCalicoOnly)
	if err != nil {
		return reconcile.Result{}, err
	}

	routeConfig, err := getVoltronRouteConfig(ctx, r.client, helper.InstallNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.InternalServerError, "Failed to create Voltron Route Configuration", err, logc)
		return reconcile.Result{}, err
	}

	// Check if non-cluster host feature is enabled.
	nonclusterhost, err := eutils.GetNonClusterHost(ctx, r.client)
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

	rbacManagementEnabled, err := utils.RBACManagementEnabled(ctx, r.client, installationSpec.Variant, tenant.MultiTenant())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading the RBAC management UI ConfigMap", err, logc)
		return reconcile.Result{}, err
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
		Namespace:                  helper.InstallNamespace(),
		TruthNamespace:             helper.TruthNamespace(),
		Tenant:                     tenant,
		ExternalElastic:            r.opts.ElasticExternal,
		BindingNamespaces:          namespaces,
		OSSTenantNamespaces:        ossTenantNamespaces,
		Manager:                    instance,
		Authentication:             authenticationCR,
		KibanaEnabled:              kibanaEnabled,
		RBACManagementEnabled:      rbacManagementEnabled,
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

	if err = imageset.ApplyImageSet(ctx, r.client, r.opts.Variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	// Resolve gateway components. Cleanup is label-driven: every Gateway
	// carrying this component's label outside the desired namespace (or in
	// any namespace, when spec.ingressGateway is nil) marks leftover resources to
	// tear down. No state is stored — each reconcile converges from what is
	// observed on the cluster.
	var gatewayComponents []render.Component
	var gatewayTLSKeyPair certificatemanagement.KeyPairInterface
	if r.opts.MultiTenant {
		// Multi-tenant CIG is not supported: resource names and the cleanup
		// label carry no tenant identity, so tenants would fight over the
		// same Gateway and could delete each other's resources — including
		// the GatewayAPI controller's per-namespace SA and RoleBinding.
		// Nothing is ever created, so there is nothing to clean up either.
		if instance.Spec.IngressGateway != nil {
			r.status.SetDegraded(operatorv1.InvalidConfigurationError, "spec.ingressGateway is not supported in multi-tenant clusters", nil, logc)
			return reconcile.Result{}, nil
		}
	} else if instance.Spec.IngressGateway != nil {
		gwComp, gwKeyPair, result, err := r.resolveGateway(ctx, instance, authenticationCR, certificateManager, helper, logc)
		if err != nil {
			return result, err
		}
		if gwComp == nil {
			return result, nil
		}
		gatewayTLSKeyPair = gwKeyPair

		gwNS := instance.Spec.IngressGateway.NamespaceOrDefault()
		strays, _, err := r.managerGatewayNamespaces(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to list gateways for cleanup", err, logc)
			return reconcile.Result{}, err
		}
		for _, ns := range strays {
			if ns == gwNS {
				continue
			}
			gatewayComponents = append(gatewayComponents, rgateway.DeletionComponent(&rgateway.DeletionConfiguration{
				ResourcePrefix:      ManagerGatewayResourcePrefix,
				GatewayNamespace:    ns,
				BackendNamespace:    helper.InstallNamespace(),
				TLSSecretName:       ManagerGatewayTLSSecretName,
				Enterprise:          true,
				MoveTargetNamespace: gwNS,
			}))
		}
		gatewayComponents = append(gatewayComponents, gwComp)
	} else {
		// Tear down every labeled Gateway's namespace. The install namespace
		// is always included: it holds the Backend and ReferenceGrant, and
		// this covers partial renders that never produced a labeled Gateway.
		namespaces, gatewayCRDsPresent, err := r.managerGatewayNamespaces(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to list gateways for cleanup", err, logc)
			return reconcile.Result{}, err
		}
		if gatewayCRDsPresent && !slices.Contains(namespaces, helper.InstallNamespace()) {
			namespaces = append(namespaces, helper.InstallNamespace())
		}
		for _, ns := range namespaces {
			gatewayComponents = append(gatewayComponents, rgateway.DeletionComponent(&rgateway.DeletionConfiguration{
				ResourcePrefix:   ManagerGatewayResourcePrefix,
				GatewayNamespace: ns,
				BackendNamespace: helper.InstallNamespace(),
				TLSSecretName:    ManagerGatewayTLSSecretName,
				Enterprise:       true,
			}))
		}
	}

	keyPairOptions := []rcertificatemanagement.KeyPairOption{
		rcertificatemanagement.NewKeyPairOption(tlsSecret, true, true),
		rcertificatemanagement.NewKeyPairOption(linseedVoltronServerCert, true, true),
		rcertificatemanagement.NewKeyPairOption(internalTrafficSecret, true, true),
		rcertificatemanagement.NewKeyPairOption(tunnelServerCert, false, true),
		rcertificatemanagement.NewKeyPairOption(additionalTunnelServerCert, false, true),
	}
	if gatewayTLSKeyPair != nil {
		keyPairOptions = append(keyPairOptions, rcertificatemanagement.NewKeyPairOption(gatewayTLSKeyPair, true, false))
	}

	components := []render.Component{
		// Install manager components.
		component,

		// Installs KeyPairs and trusted bundle (if not pre-installed)
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       helper.InstallNamespace(),
			TruthNamespace:  helper.TruthNamespace(),
			ServiceAccounts: []string{render.ManagerServiceAccount},
			KeyPairOptions:  keyPairOptions,
			TrustedBundle:   bundleMaker,
		}),
	}

	if tunnelSecretPassthrough != nil {
		components = append(components, tunnelSecretPassthrough)
	}

	components = append(components, gatewayComponents...)

	for _, component := range components {
		if err := defaultHandler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	if instance.Spec.IngressGateway != nil {
		// An unhealthy gateway degrades the component without tearing down
		// deployed resources. The requeue re-checks until Envoy converges;
		// the degraded state then clears on the pass below.
		if msg := r.gatewayUnhealthyReason(ctx, instance.Spec.IngressGateway.NamespaceOrDefault()); msg != "" {
			r.status.SetDegraded(operatorv1.ResourceNotReady, msg, nil, logc)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
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

const (
	ManagerGatewayTLSSecretName  = "calico-manager-gateway-tls"
	ManagerGatewayResourcePrefix = "calico-manager"
)

// managerGatewayNamespaces returns the sorted, de-duplicated namespaces of
// Gateways carrying this component's gateway label. A missing Gateway API CRD
// yields an empty list — there is nothing to clean up on clusters without
// CIG. In multi-tenant mode the list is skipped: the label value is shared
// across tenants, so one tenant's cleanup must not see another's Gateways.
// The bool reports whether the Gateway API CRDs are installed at all: when
// they are not, no gateway object can exist and cleanup must be skipped —
// even a Delete call fails against a kind the API server does not serve.
func (r *ReconcileManager) managerGatewayNamespaces(ctx context.Context) ([]string, bool, error) {
	if r.opts.MultiTenant {
		return nil, false, nil
	}
	gwList := &gapi.GatewayList{}
	if err := r.client.List(ctx, gwList, client.MatchingLabels{rgateway.GatewayLabel: ManagerGatewayResourcePrefix}); err != nil {
		var noMatch *apimeta.NoKindMatchError
		if stderrors.As(err, &noMatch) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var namespaces []string
	for _, gw := range gwList.Items {
		if !slices.Contains(namespaces, gw.Namespace) {
			namespaces = append(namespaces, gw.Namespace)
		}
	}
	slices.Sort(namespaces)
	return namespaces, true, nil
}

// resolveGateway validates the Manager spec.ingressGateway configuration, resolves the
// GatewayClass, provisions the TLS keypair, and returns a gateway render component.
func (r *ReconcileManager) resolveGateway(
	ctx context.Context,
	instance *operatorv1.Manager,
	authenticationCR *operatorv1.Authentication,
	certManager certificatemanager.CertificateManager,
	helper eutils.NamespaceHelper,
	logc logr.Logger,
) (render.Component, certificatemanagement.KeyPairInterface, reconcile.Result, error) {
	gw := instance.Spec.IngressGateway

	// Fetch GatewayAPI CR.
	gatewayAPI, msg, err := gatewayapi.GetGatewayAPI(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "GatewayAPI CR not found; gateway resources will not be rendered", err, logc)
			return nil, nil, reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, msg, err, logc)
		return nil, nil, reconcile.Result{}, err
	}

	// Resolve gatewayClassName.
	gatewayClassName, err := resolveGatewayClassName(gw, gatewayAPI)
	if err != nil {
		r.status.SetDegraded(operatorv1.InvalidConfigurationError, "Failed to resolve gateway class", err, logc)
		return nil, nil, reconcile.Result{}, err
	}

	// OIDC hostname check. managerDomain is a base URL (https://host[:port]);
	// only the host must match spec.ingressGateway.hostname — scheme and port are
	// ignored.
	if authenticationCR != nil && authenticationCR.Spec.ManagerDomain != "" {
		if managerDomainHost(authenticationCR.Spec.ManagerDomain) != gw.Hostname {
			err := fmt.Errorf("Authentication.spec.managerDomain %q does not match spec.ingressGateway.hostname %q — OIDC redirects will fail",
				authenticationCR.Spec.ManagerDomain, gw.Hostname)
			r.status.SetDegraded(operatorv1.InvalidConfigurationError, "Gateway hostname mismatch", err, logc)
			return nil, nil, reconcile.Result{}, err
		}
	}

	// Create the gateway namespace if it does not exist. calico-system is
	// skipped: the Installation controller owns it.
	if gwNS := gw.NamespaceOrDefault(); gwNS != common.CalicoNamespace {
		if err := r.ensureGatewayNamespace(ctx, gwNS); err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, fmt.Sprintf("Failed to create gateway namespace %q", gwNS), err, logc)
			return nil, nil, reconcile.Result{}, err
		}
	}

	// Provision TLS keypair for the gateway listener.
	gwTLSKeyPair, err := certManager.GetOrCreateKeyPair(
		r.client,
		ManagerGatewayTLSSecretName,
		helper.TruthNamespace(),
		[]string{gw.Hostname})
	if err != nil {
		r.status.SetDegraded(operatorv1.CertificateError, "Error getting or creating gateway TLS certificate", err, logc)
		return nil, nil, reconcile.Result{}, err
	}

	gwCfg := &rgateway.Configuration{
		Hostname:                     gw.Hostname,
		GatewayNamespace:             gw.NamespaceOrDefault(),
		GatewayClassName:             gatewayClassName,
		BackendServiceName:           render.ManagerServiceName,
		BackendPort:                  render.ManagerPort,
		BackendNamespace:             helper.InstallNamespace(),
		BackendCABundleConfigMapName: certificatemanagement.TrustedCertConfigMapName,
		TLSKeyPair:                   gwTLSKeyPair,
		ResourcePrefix:               ManagerGatewayResourcePrefix,
		Enterprise:                   true,
		OpenShift:                    r.opts.DetectedProvider.IsOpenShift(),
	}

	return rgateway.Component(gwCfg), gwTLSKeyPair, reconcile.Result{}, nil
}

// ensureGatewayNamespace creates the gateway namespace if it does not exist.
// The namespace is created without an owner reference and is never deleted by
// the operator: a user-provided namespace may hold other workloads.
func (r *ReconcileManager) ensureGatewayNamespace(ctx context.Context, name string) error {
	err := r.client.Get(ctx, types.NamespacedName{Name: name}, &corev1.Namespace{})
	if err == nil || !errors.IsNotFound(err) {
		return err
	}
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"name": name},
		},
	}
	if err := r.client.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// gatewayUnhealthyReason reads the Gateway and HTTPRoute status conditions
// and returns why the gateway is not ready, or "" when every condition is
// healthy. Per the design, an unhealthy gateway degrades the component — the
// caller sets Degraded and requeues; deployed resources are never torn down.
// NotFound is reported too: the requeue re-checks once the cache catches up
// with the resources this reconcile just applied.
func (r *ReconcileManager) gatewayUnhealthyReason(ctx context.Context, gatewayNS string) string {
	gatewayName := ManagerGatewayResourcePrefix + "-gateway"
	routeName := ManagerGatewayResourcePrefix + "-route"

	gw := &gapi.Gateway{}
	if err := r.client.Get(ctx, client.ObjectKey{Name: gatewayName, Namespace: gatewayNS}, gw); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Sprintf("Gateway %s/%s not found yet", gatewayNS, gatewayName)
		}
		return fmt.Sprintf("Failed to read Gateway %s/%s status: %v", gatewayNS, gatewayName, err)
	}

	if msg := unhealthyCondition(gw.Status.Conditions, string(gapi.GatewayConditionAccepted), "Gateway not accepted"); msg != "" {
		return msg
	}
	if msg := unhealthyCondition(gw.Status.Conditions, string(gapi.GatewayConditionProgrammed), "Gateway not programmed"); msg != "" {
		return msg
	}

	route := &gapi.HTTPRoute{}
	if err := r.client.Get(ctx, client.ObjectKey{Name: routeName, Namespace: gatewayNS}, route); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Sprintf("HTTPRoute %s/%s not found yet", gatewayNS, routeName)
		}
		return fmt.Sprintf("Failed to read HTTPRoute %s/%s status: %v", gatewayNS, routeName, err)
	}
	for _, ps := range route.Status.Parents {
		if msg := unhealthyCondition(ps.Conditions, string(gapi.RouteConditionAccepted), "HTTPRoute not accepted"); msg != "" {
			return msg
		}
		if msg := unhealthyCondition(ps.Conditions, string(gapi.RouteConditionResolvedRefs), "HTTPRoute refs not resolved"); msg != "" {
			return msg
		}
	}

	return ""
}

// unhealthyCondition returns a message when the named condition exists and is
// not True. A missing condition is healthy: the controller has not written
// its verdict yet, and Accepted/Programmed gate readiness once it does.
func unhealthyCondition(conditions []metav1.Condition, condType, msgPrefix string) string {
	for _, cond := range conditions {
		if cond.Type == condType && cond.Status != metav1.ConditionTrue {
			return fmt.Sprintf("%s: %s", msgPrefix, cond.Message)
		}
	}
	return ""
}

// managerDomainHost extracts the host from a managerDomain-style value —
// scheme and port, when present, are dropped.
func managerDomainHost(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

// resolveGatewayClassName determines the GatewayClass name to use based on the
// user's spec.ingressGateway.gatewayClassName or the GatewayAPI CR's configured classes.
func resolveGatewayClassName(gw *operatorv1.IngressGatewaySpec, gatewayAPI *operatorv1.GatewayAPI) (string, error) {
	if gw.GatewayClassName != nil && *gw.GatewayClassName != "" {
		name := *gw.GatewayClassName
		for _, c := range gatewayAPI.Spec.GatewayClasses {
			if c.Name == name {
				return name, nil
			}
		}
		return "", fmt.Errorf("GatewayClass %q not found; verify GatewayAPI CR includes this class", name)
	}

	classes := gatewayAPI.Spec.GatewayClasses
	switch len(classes) {
	case 0:
		return "", fmt.Errorf("no GatewayClasses configured on GatewayAPI CR")
	case 1:
		return classes[0].Name, nil
	default:
		return "", fmt.Errorf("multiple GatewayClasses configured on GatewayAPI CR; set spec.ingressGateway.gatewayClassName to select one")
	}
}
