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

package compliance

import (
	"context"
	"fmt"

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
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/tenancy"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const ResourceName = "compliance"

var log = logf.Log.WithName("controller_compliance")

// Add creates a new Compliance Controller and adds it to the Manager. The Manager will set fields on the Controller
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
	complianceController, err := ctrlruntime.NewController("compliance-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
		if err = complianceController.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("compliance-controller failed to watch Tenant resource: %w", err)
		}
	}

	installNS, _, watchNamespaces := tenancy.GetWatchNamespaces(opts.MultiTenant, render.ComplianceNamespace)

	go utils.WaitToAddLicenseKeyWatch(complianceController, opts.K8sClientset, log, licenseAPIReady)

	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, complianceController, opts.K8sClientset, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(complianceController, opts.K8sClientset, log, []types.NamespacedName{
		{Name: render.ComplianceAccessPolicyName, Namespace: installNS},
		{Name: render.ComplianceServerPolicyName, Namespace: installNS},
		{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: installNS},
	})

	if opts.Cloud && opts.ElasticExternal {
		// This ConfigMap is needed for utils.GetCloudConfig
		if err = utils.AddConfigMapWatch(complianceController, cloudconfig.CloudConfigConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("compliance-controller failed to watch the ConfigMap resource: %w", err)
		}
	}

	// Watch for changes to primary resource Compliance
	err = complianceController.WatchObject(&operatorv1.Compliance{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = complianceController.WatchObject(&operatorv1.Installation{}, eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch Installation resource: %w", err)
	}

	if err = complianceController.WatchObject(&operatorv1.ImageSet{}, eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch ImageSet: %w", err)
	}

	if err = complianceController.WatchObject(&operatorv1.APIServer{}, eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch APIServer resource: %w", err)
	}

	// Watch the given secrets in each both the compliance and operator namespaces
	for _, namespace := range watchNamespaces {
		for _, secretName := range []string{
			render.ComplianceServerCertSecret, render.ManagerInternalTLSSecretName, certificatemanagement.CASecretName,
			render.TigeraLinseedSecret, render.VoltronLinseedTLS,
			render.VoltronLinseedPublicCert,
		} {
			if err = utils.AddSecretsWatch(complianceController, secretName, namespace); err != nil {
				return fmt.Errorf("compliance-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	// Watch for changes to primary resource ManagementCluster
	if err = complianceController.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	if err = complianceController.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch primary resource: %w", err)
	}

	if err = complianceController.WatchObject(&operatorv1.Authentication{}, eventHandler); err != nil {
		return fmt.Errorf("compliance-controller failed to watch resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(complianceController, ResourceName); err != nil {
		return fmt.Errorf("compliance-controller failed to watch compliance Tigerastatus: %w", err)
	}

	return nil
}

// newReconciler returns a new *reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, licenseAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileCompliance{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		status:          status.New(mgr.GetClient(), "compliance", opts.KubernetesVersion),
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		opts:            opts,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// blank assignment to verify that ReconcileCompliance implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileCompliance{}

// ReconcileCompliance reconciles a Compliance object
type ReconcileCompliance struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	opts            options.ControllerOptions
}

func GetCompliance(ctx context.Context, cli client.Client, mt bool, ns string) (*operatorv1.Compliance, error) {
	key := client.ObjectKey{Name: "tigera-secure"}
	if mt {
		key.Namespace = ns
	}
	instance := &operatorv1.Compliance{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a Compliance object and makes changes based on the state read
// and what is in the Compliance.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCompliance) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(r.opts.MultiTenant, render.ComplianceNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling Compliance")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.opts.MultiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// Check if this is a tenant-scoped request.
	tenant, _, err := utils.GetTenant(ctx, r.opts.MultiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch the Compliance instance
	instance, err := GetCompliance(ctx, r.client, r.opts.MultiTenant, request.Namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Compliance config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying compliance", err, reqLogger)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating Compliance status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create Compliance status conditions.")
			return reconcile.Result{}, err
		}
	}

	if !utils.IsProjectCalicoV3Available(r.client, r.opts, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		} else {
			log.Error(err, "Error querying calico-system tier")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Query for the installation object.
	variant, installationSpec, err := utils.GetInstallationSpec(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve pull secrets", err, reqLogger)
		return reconcile.Result{}, err
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

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, err
	}

	var opts []certificatemanager.Option

	opts = append(opts, certificatemanager.WithTenant(tenant), certificatemanager.WithLogger(reqLogger))

	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.opts.ClusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	var managerInternalTLSSecret certificatemanagement.CertificateInterface
	if managementCluster != nil {
		managerInternalTLSSecret, err = certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", render.ManagerInternalTLSSecretName), err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// The location of the Linseed certificate varies based on if this is a managed cluster or not.
	// For standalone and management clusters, we just use Linseed's actual certificate.
	linseedCertLocation := render.TigeraLinseedSecret
	if managementClusterConnection != nil {
		// For managed clusters, we need to add the certificate of the Voltron endpoint. This certificate is copied from the
		// management cluster into the managed cluster by kube-controllers.
		linseedCertLocation = render.VoltronLinseedPublicCert
	}
	linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertLocation, helper.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Failed to retrieve / validate  %s", render.TigeraLinseedSecret), err, reqLogger)
		return reconcile.Result{}, err
	} else if linseedCertificate == nil {
		log.Info("Linseed certificate is not available yet, waiting until it becomes available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Linseed certificate is not available yet, waiting until it becomes available", nil, reqLogger)
		return reconcile.Result{}, nil
	}
	// Get the key pairs for each component, generating them as needed.
	type complianceKeyPair struct {
		SecretName string
		Interface  certificatemanagement.KeyPairInterface
	}
	snapshotterKeyPair := complianceKeyPair{SecretName: render.ComplianceSnapshotterSecret}
	benchmarkerKeyPair := complianceKeyPair{SecretName: render.ComplianceBenchmarkerSecret}
	reporterKeyPair := complianceKeyPair{SecretName: render.ComplianceReporterSecret}
	controllerKeyPair := complianceKeyPair{SecretName: render.ComplianceControllerSecret}
	for _, kp := range []*complianceKeyPair{&snapshotterKeyPair, &benchmarkerKeyPair, &reporterKeyPair, &controllerKeyPair} {
		// These key pairs are only used as client credentials for mTLS with Linseed, and so do not need DNS names listed
		// as they do not act as server certs.
		dnsNames := []string{"localhost"}
		kp.Interface, err = certificateManager.GetOrCreateKeyPair(r.client, kp.SecretName, helper.TruthNamespace(), dnsNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", kp.SecretName), err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	var complianceServerKeyPair certificatemanagement.KeyPairInterface
	if managementClusterConnection == nil {
		complianceServerKeyPair, err = certificateManager.GetOrCreateKeyPair(
			r.client,
			render.ComplianceServerCertSecret,
			helper.TruthNamespace(),
			dns.GetServiceDNSNames(render.ComplianceServiceName, helper.InstallNamespace(), r.opts.ClusterDomain))
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", render.ComplianceServerCertSecret), err, reqLogger)
			return reconcile.Result{}, err
		}
	}
	certificateManager.AddToStatusManager(r.status, helper.InstallNamespace())

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready - authenticationCR status: %s", authenticationCR.Status.State), nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Build the trusted bundle now that the authenticationCR is known, so we can pick the right
	// variant in one place. Default is the standard bundle; multi-tenant loads the per-tenant bundle
	// with root certs; Calico Cloud management clusters use the system-root variant so
	// compliance-server can verify an external OIDC provider. The bundle is not used until lower in
	// the function, so building it here (rather than earlier) is safe.
	bundleMaker := certificateManager.CreateTrustedBundle(managerInternalTLSSecret, linseedCertificate)
	trustedBundle := bundleMaker.(certificatemanagement.TrustedBundleRO)
	if r.opts.MultiTenant {
		// For multi-tenant systems, we load the pre-created bundle for this tenant instead of using the one we built here.
		// Multi-tenant compliance need the bundle variant that includes system root certificates, in order to verify external auth providers.
		trustedBundle, err = certificateManager.LoadMultiTenantTrustedBundleWithRootCertificates(ctx, r.client, helper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
			return reconcile.Result{}, err
		}
		bundleMaker = nil
	} else if r.opts.Cloud && managementCluster != nil && authenticationCR != nil && authenticationCR.Spec.OIDC != nil &&
		authenticationCR.Spec.OIDC.Type == operatorv1.OIDCTypeTigera {
		bundleMaker, err = certificateManager.CreateTrustedBundleWithSystemRootCertificates(managerInternalTLSSecret, linseedCertificate)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "failed to create trusted bundle with system root certs", err, reqLogger)
			return reconcile.Result{}, err
		}
		trustedBundle = bundleMaker.(certificatemanagement.TrustedBundleRO)
	}

	// Determine the namespaces to which we must bind the cluster role.
	// For multi-tenant, the cluster role will be bind to the service account in the tenant namespace
	// For single-tenant or zero-tenant, the cluster role will be bind to the service account in the tigera-compliance
	// namespace
	bindNamespaces, err := helper.TenantNamespaces(r.client)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.opts.ClusterDomain, r.opts.Cloud && !r.opts.MultiTenant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to process the authentication CR.", err, reqLogger)
		return reconcile.Result{}, err
	}

	if r.opts.Cloud && r.opts.ElasticExternal && !r.opts.MultiTenant {
		// For Calico Cloud single-tenant clusters sharing an external ES, extract the tenant
		// information from the cloud config map.
		cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				reqLogger.Info("Failed to retrieve External Elasticsearch config map")
				r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve External Elasticsearch config map", err, reqLogger)
				return reconcile.Result{}, nil
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read External Elasticsearch config map", err, reqLogger)
			return reconcile.Result{}, err
		}
		tenant = cloudConfig.ToTenant()
	}

	reqLogger.V(3).Info("rendering components")

	setUp := render.NewSetup(&render.SetUpConfiguration{
		OpenShift:       r.opts.DetectedProvider.IsOpenShift(),
		Installation:    installationSpec,
		PullSecrets:     pullSecrets,
		Namespace:       helper.InstallNamespace(),
		PSS:             render.PSSPrivileged,
		CreateNamespace: !tenant.MultiTenant(),
	})

	hasNoLicense := !utils.IsFeatureActive(license, common.ComplianceFeature)
	openshift := r.opts.DetectedProvider.IsOpenShift()
	complianceCfg := &render.ComplianceConfiguration{
		TrustedBundle:               trustedBundle,
		Installation:                installationSpec,
		ServerKeyPair:               complianceServerKeyPair,
		ControllerKeyPair:           controllerKeyPair.Interface,
		BenchmarkerKeyPair:          benchmarkerKeyPair.Interface,
		SnapshotterKeyPair:          snapshotterKeyPair.Interface,
		ReporterKeyPair:             reporterKeyPair.Interface,
		PullSecrets:                 pullSecrets,
		OpenShift:                   openshift,
		ManagementCluster:           managementCluster,
		ManagementClusterConnection: managementClusterConnection,
		KeyValidatorConfig:          keyValidatorConfig,
		ClusterDomain:               r.opts.ClusterDomain,
		HasNoLicense:                hasNoLicense,
		Namespace:                   helper.InstallNamespace(),
		BindingNamespaces:           bindNamespaces,
		Tenant:                      tenant,
		Compliance:                  instance,
		ExternalElastic:             r.opts.ElasticExternal,
		Cloud:                       r.opts.Cloud,
	}

	// Render the desired objects from the CRD and create or update them.
	comp, err := render.Compliance(complianceCfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering Compliance", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, comp); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}
	certificateComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       helper.InstallNamespace(),
		TruthNamespace:  helper.TruthNamespace(),
		ServiceAccounts: []string{render.ComplianceServerServiceAccount, render.ComplianceBenchmarkerServiceAccount, render.ComplianceSnapshotterServiceAccount, render.ComplianceControllerServiceAccount, render.ComplianceReporterServiceAccount},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(complianceServerKeyPair, true, true),
			rcertificatemanagement.NewKeyPairOption(controllerKeyPair.Interface, true, true),
			rcertificatemanagement.NewKeyPairOption(benchmarkerKeyPair.Interface, true, true),
			rcertificatemanagement.NewKeyPairOption(snapshotterKeyPair.Interface, true, true),
			rcertificatemanagement.NewKeyPairOption(reporterKeyPair.Interface, true, true),
		},
		TrustedBundle: bundleMaker,
	})

	setupHandler := handler
	if tenant.MultiTenant() {
		// In standard installs, the Compliance CR owns all the objects. For multi-tenant, pull secrets are owned by the Tenant instance.
		setupHandler = utils.NewComponentHandler(log, r.client, r.scheme, tenant)
	}
	if err := setupHandler.CreateOrUpdateOrDelete(ctx, setUp, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, comp := range []render.Component{certificateComponent, comp} {
		if err := handler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating / deleting resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if hasNoLicense {
		log.V(4).Info("Compliance is not activated as part of this license")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Check BYO certificate expiry warnings.
	certificatemanagement.CheckKeyPairWarnings(map[string]certificatemanagement.KeyPairInterface{
		render.ComplianceServerCertSecret:  complianceServerKeyPair,
		render.ComplianceSnapshotterSecret: snapshotterKeyPair.Interface,
		render.ComplianceBenchmarkerSecret: benchmarkerKeyPair.Interface,
		render.ComplianceReporterSecret:    reporterKeyPair.Interface,
		render.ComplianceControllerSecret:  controllerKeyPair.Interface,
	}, r.status)

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Everything is available - update the CRD status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
