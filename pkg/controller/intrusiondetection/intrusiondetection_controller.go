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

package intrusiondetection

import (
	"context"
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
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
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/logcollector"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/tenancy"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const tigeraStatusName = "intrusion-detection"

var log = logf.Log.WithName("controller_intrusiondetection")

// Add creates a new IntrusionDetection Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}

	licenseAPIReady := &utils.ReadyFlag{}
	dpiAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}

	// Create the reconciler
	reconciler := newReconciler(mgr, opts, licenseAPIReady, dpiAPIReady, tierWatchReady)

	// Create a new controller
	c, err := ctrlruntime.NewController("intrusiondetection-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return fmt.Errorf("failed to create intrusiondetection-controller: %v", err)
	}

	installNS, truthNS, _ := tenancy.GetWatchNamespaces(opts.MultiTenant, render.IntrusionDetectionNamespace)

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenant clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = utils.EnqueueAllTenants(mgr.GetClient())
	}

	policiesToWatch := []types.NamespacedName{
		{Name: render.IntrusionDetectionControllerPolicyName, Namespace: installNS},
		{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: installNS},
	}
	if !opts.MultiTenant {
		// DPI is only supported in single-tenant mode.
		go utils.WaitToAddResourceWatch(c, opts.K8sClientset, log, dpiAPIReady,
			[]client.Object{&v3.DeepPacketInspection{TypeMeta: metav1.TypeMeta{Kind: v3.KindDeepPacketInspection}}})
		policiesToWatch = append(policiesToWatch, types.NamespacedName{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace})
	}
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, policiesToWatch)
	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)

	// Watch for changes to operator.tigera.io APIs.
	if err = c.WatchObject(&operatorv1.IntrusionDetection{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch primary resource: %v", err)
	}
	if err = c.WatchObject(&operatorv1.LogCollector{}, eventHandler); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch LogCollector resource: %v", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch primary resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.Installation{}, eventHandler); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch Installation resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.APIServer{}, eventHandler); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch APIServer resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ImageSet{}, eventHandler); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch ImageSet: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, tigeraStatusName); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch intrusion-detection Tigerastatus: %w", err)
	}

	for _, secretName := range []string{
		render.ManagerInternalTLSSecretName,
		render.NodeTLSSecretName,
		render.TyphaTLSSecretName,
		render.TigeraLinseedSecret,
		render.VoltronLinseedPublicCert,
		certificatemanagement.CASecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, truthNS); err != nil {
			return fmt.Errorf("intrusiondetection-controller failed to watch the Secret resource: %v", err)
		}
	}

	if err = utils.AddSecretsWatch(c, render.ManagerInternalTLSSecretName, installNS); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddSecretsWatch(c, render.TigeraLinseedSecret, installNS); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the Secret resource: %v", err)
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, truthNS, eventHandler); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the ConfigMap resource: %v", err)
	}

	if err = utils.AddConfigMapWatch(c, render.TyphaCAConfigMapName, truthNS, eventHandler); err != nil {
		return fmt.Errorf("intrusiondetection-controller failed to watch the ConfigMap resource: %v", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, licenseAPIReady *utils.ReadyFlag, dpiAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileIntrusionDetection{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		status:          status.New(mgr.GetClient(), tigeraStatusName, opts.KubernetesVersion),
		licenseAPIReady: licenseAPIReady,
		dpiAPIReady:     dpiAPIReady,
		tierWatchReady:  tierWatchReady,
		opts:            opts,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// blank assignment to verify that ReconcileIntrusionDetection implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileIntrusionDetection{}

// ReconcileIntrusionDetection reconciles a IntrusionDetection object
type ReconcileIntrusionDetection struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	licenseAPIReady *utils.ReadyFlag
	dpiAPIReady     *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	opts            options.ControllerOptions
}

func getIntrusionDetection(ctx context.Context, cli client.Client, mt bool, ns string) (*operatorv1.IntrusionDetection, error) {
	key := client.ObjectKey{Name: "tigera-secure"}
	if mt {
		key.Namespace = ns
	}

	instance := &operatorv1.IntrusionDetection{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a IntrusionDetection object and makes changes based on the state read
// and what is in the IntrusionDetection.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileIntrusionDetection) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := utils.NewNamespaceHelper(r.opts.MultiTenant, render.IntrusionDetectionNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling IntrusionDetection")

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

	// Fetch the IntrusionDetection instance
	instance, err := getIntrusionDetection(ctx, r.client, r.opts.MultiTenant, request.Namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(3).Info("IntrusionDetection CR not found", "err", err)
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying IntrusionDetection", err, reqLogger)
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", instance)
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating IntrusionDetection status conditions
	if request.Name == tigeraStatusName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: tigeraStatusName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create IntrusionDetection status conditions.")
			return reconcile.Result{}, err
		}
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}
	isManagedCluster := managementClusterConnection != nil

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}
	isManagementCluster := managementCluster != nil

	if err := r.fillDefaults(ctx, instance); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Unable to set defaults on IntrusionDetection", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !utils.IsProjectCalicoV3Available(r.client, r.opts, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
		return reconcile.Result{}, err
	}

	if !isManagedCluster && !r.opts.ElasticExternal {
		// Check if Elasticsearch is ready.
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
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Error querying calico-system tier", err, reqLogger)
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
	variant, installationSpec, err := utils.GetInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Query for pull secrets in operator namespace
	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Query for the LogCollector instance. We need this to determine whether or not
	// to forward IDS event logs. Since this is optional, we don't need to degrade or
	// change status if LogCollector is not found.
	lc, err := logcollector.GetLogCollector(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("(optional) LogCollector object not found, proceed without it")
		}
	}

	// When creating the certificate manager, pass in the logger and tenant (if one exists).
	opts := []certificatemanager.Option{
		certificatemanager.WithLogger(reqLogger),
		certificatemanager.WithTenant(tenant),
	}
	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.opts.ClusterDomain, helper.TruthNamespace(), opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// The location of the Linseed certificate varies based on if this is a managed cluster or not.
	linseedCertLocation := render.TigeraLinseedSecret
	if isManagedCluster {
		linseedCertLocation = render.VoltronLinseedPublicCert
	}
	linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertLocation, helper.TruthNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve / validate  %s", render.TigeraLinseedSecret), err, reqLogger)
		return reconcile.Result{}, err
	} else if linseedCertificate == nil {
		log.Info("Linseed certificate is not available yet, waiting until they become available")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Linseed certificate are not available yet, waiting until they become available", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// intrusionDetectionKeyPair is the key pair intrusion detection presents to identify itself
	dnsNames := dns.GetServiceDNSNames(render.IntrusionDetectionTLSSecretName, helper.InstallNamespace(), r.opts.ClusterDomain)
	intrusionDetectionKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.IntrusionDetectionTLSSecretName, helper.TruthNamespace(), dnsNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !r.opts.MultiTenant && !r.dpiAPIReady.IsReady() {
		// DPI is only supported in single-tenant clusters, so we don't need to check for it in multi-tenant.
		log.Info("Waiting for DeepPacketInspection API to be ready")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for DeepPacketInspection API to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Intrusion detection controller sometimes needs to make requests to outside sources. Therefore, we include
	// the system root certificate bundle.
	bundleMaker, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create tigera-ca-bundle configmap", err, reqLogger)
		return reconcile.Result{}, err
	}
	bundleMaker.AddCertificates(linseedCertificate)

	if !isManagedCluster {

		managerInternalTLSSecret, err := certificateManager.GetCertificate(r.client, render.ManagerInternalTLSSecretName, helper.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("failed to retrieve / validate  %s", render.ManagerInternalTLSSecretName), err, reqLogger)
			return reconcile.Result{}, err
		}

		bundleMaker.AddCertificates(managerInternalTLSSecret)
	}

	trustedBundle := bundleMaker.(certificatemanagement.TrustedBundleRO)
	if r.opts.MultiTenant {
		// For multi-tenant systems, we load the pre-created bundle for this tenant instead of using the one we built here.
		trustedBundle, err = certificateManager.LoadMultiTenantTrustedBundleWithRootCertificates(ctx, r.client, helper.InstallNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting trusted bundle", err, reqLogger)
			return reconcile.Result{}, err
		}
		bundleMaker = nil
	}

	if r.opts.Cloud && r.opts.ElasticExternal && !r.opts.MultiTenant {
		// For Calico Cloud single-tenant clusters sharing an external ES, extract the tenant
		// information from the cloud config map.
		cloudConfig, err := utils.GetCloudConfig(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read cloud config", err, reqLogger)
			return reconcile.Result{}, err
		}
		tenant = cloudConfig.ToTenant()
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Determine the namespaces to which we must bind the cluster role.
	namespaces, err := helper.TenantNamespaces(r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving tenant namespaces", err, reqLogger)
		return reconcile.Result{}, err
	}

	reqLogger.V(3).Info("rendering components")
	// Render the desired objects from the CRD and create or update them.
	hasNoLicense := !utils.IsFeatureActive(license, common.ThreatDefenseFeature)
	intrusionDetectionCfg := &render.IntrusionDetectionConfiguration{
		IntrusionDetection:           instance,
		LogCollector:                 lc,
		Installation:                 installationSpec,
		PullSecrets:                  pullSecrets,
		OpenShift:                    r.opts.DetectedProvider.IsOpenShift(),
		ClusterDomain:                r.opts.ClusterDomain,
		ManagedCluster:               isManagedCluster,
		ManagementCluster:            isManagementCluster,
		HasNoLicense:                 hasNoLicense,
		TrustedCertBundle:            trustedBundle,
		IntrusionDetectionCertSecret: intrusionDetectionKeyPair,
		Namespace:                    helper.InstallNamespace(),
		BindNamespaces:               namespaces,
		Tenant:                       tenant,
		ExternalElastic:              r.opts.ElasticExternal,
		SyslogForwardingIsEnabled:    syslogForwardingIsEnabled(lc),
	}
	setUp := render.NewSetup(&render.SetUpConfiguration{
		OpenShift:       r.opts.DetectedProvider.IsOpenShift(),
		Installation:    installationSpec,
		PullSecrets:     pullSecrets,
		Namespace:       helper.InstallNamespace(),
		PSS:             getPSS(lc),
		CreateNamespace: !tenant.MultiTenant(),
	})
	intrusionDetectionComponent := render.IntrusionDetection(intrusionDetectionCfg)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, intrusionDetectionComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	dpiList := &v3.DeepPacketInspectionList{}
	if err := r.client.List(ctx, dpiList); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to retrieve DeepPacketInspection resource", err, reqLogger)
		return reconcile.Result{}, err
	}
	hasNoDPIResource := len(dpiList.Items) == 0
	if !hasNoDPIResource && r.opts.MultiTenant {
		r.status.SetDegraded(operatorv1.InvalidConfigurationError, "DeepPacketInspection resource is not supported in multi-tenant mode", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	components := []render.Component{
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       helper.InstallNamespace(),
			TruthNamespace:  helper.TruthNamespace(),
			ServiceAccounts: []string{render.IntrusionDetectionName},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(intrusionDetectionCfg.IntrusionDetectionCertSecret, true, true),
			},
			TrustedBundle: bundleMaker,
		}),
		intrusionDetectionComponent,
	}

	var dpiKeyPair certificatemanagement.KeyPairInterface
	if !r.opts.MultiTenant {
		// FIXME: core controller creates TyphaNodeTLSConfig, this controller should only get it.
		// But changing the call from GetOrCreateTyphaNodeTLSConfig() to GetTyphaNodeTLSConfig()
		// makes tests fail, this needs to be looked at.
		typhaNodeTLS, err := installation.GetOrCreateTyphaNodeTLSConfig(r.client, certificateManager)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error with Typha/Felix secrets", err, reqLogger)
			return reconcile.Result{}, err
		}
		typhaNodeTLS.TrustedBundle.AddCertificates(linseedCertificate)

		// dpiKeyPair is the key pair dpi presents to identify itself
		dpiKeyPair, err = certificateManager.GetOrCreateKeyPair(r.client, render.DPITLSSecretName, helper.TruthNamespace(), []string{render.IntrusionDetectionTLSSecretName})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}

		dpiComponent := dpi.DPI(&dpi.DPIConfig{
			IntrusionDetection: instance,
			Installation:       installationSpec,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			OpenShift:          r.opts.DetectedProvider.IsOpenShift(),
			ManagedCluster:     isManagedCluster,
			ManagementCluster:  isManagementCluster,
			HasNoLicense:       hasNoLicense,
			HasNoDPIResource:   hasNoDPIResource,
			ClusterDomain:      r.opts.ClusterDomain,
			DPICertSecret:      dpiKeyPair,
		})
		if err = imageset.ApplyImageSet(ctx, r.client, variant, dpiComponent); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
			return reconcile.Result{}, err
		}
		components = append(components, dpiComponent)
		components = append(components, rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       dpi.DeepPacketInspectionNamespace,
			ServiceAccounts: []string{dpi.DeepPacketInspectionName},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(typhaNodeTLS.NodeSecret, false, true),
				rcertificatemanagement.NewKeyPairOption(dpiKeyPair, true, true),
			},
			TrustedBundle: typhaNodeTLS.TrustedBundle,
		}))
	} else {
		dpiComponent := dpi.DPI(&dpi.DPIConfig{
			IntrusionDetection: instance,
			Installation:       installationSpec,
			PullSecrets:        pullSecrets,
			OpenShift:          r.opts.DetectedProvider.IsOpenShift(),
			ManagedCluster:     isManagedCluster,
			ManagementCluster:  isManagementCluster,
			ClusterDomain:      r.opts.ClusterDomain,
			Tenant:             tenant,
		})
		components = append(components, dpiComponent)
	}

	setupHandler := handler
	if tenant.MultiTenant() {
		// In standard installs, the IntrusionDetection CR owns all the objects. For multi-tenant, pull secrets are owned by the Tenant instance.
		setupHandler = utils.NewComponentHandler(log, r.client, r.scheme, tenant)
	}
	if err := setupHandler.CreateOrUpdateOrDelete(ctx, setUp, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, comp := range components {
		if err := handler.CreateOrUpdateOrDelete(context.Background(), comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if hasNoLicense {
		log.V(4).Info("IntrusionDetection is not activated as part of this license")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Check BYO certificate expiry warnings.
	certificatemanagement.CheckKeyPairWarnings(map[string]certificatemanagement.KeyPairInterface{
		render.IntrusionDetectionTLSSecretName: intrusionDetectionKeyPair,
		render.DPITLSSecretName:                dpiKeyPair,
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

func getPSS(logCollector *operatorv1.LogCollector) render.PodSecurityStandard {
	// Configure pod security standard. If syslog forwarding is enabled, we
	// need hostpath volumes which require a privileged PSS.
	pss := render.PSSRestricted

	if syslogForwardingIsEnabled(logCollector) {
		pss = render.PSSPrivileged
	}

	return render.PodSecurityStandard(pss)
}

// Determine whether this component's configuration has syslog forwarding enabled or not.
// Look inside LogCollector spec for whether or not Syslog log type SyslogLogIDSEvents
// exists. If it does, then we need to turn on forwarding for IDS event logs.
func syslogForwardingIsEnabled(logCollector *operatorv1.LogCollector) bool {
	if logCollector != nil && logCollector.Spec.AdditionalStores != nil {
		syslog := logCollector.Spec.AdditionalStores.Syslog
		if syslog != nil {
			if syslog.LogTypes != nil {
				for _, t := range syslog.LogTypes {
					switch t {
					case operatorv1.SyslogLogIDSEvents:
						return true
					}
				}
			}
		}
	}
	return false
}

// fillDefaults updates the IntrusionDetection resource with defaults if
// ComponentResources is not populated.
func (r *ReconcileIntrusionDetection) fillDefaults(ctx context.Context, ids *operatorv1.IntrusionDetection) error {
	if ids.Spec.ComponentResources == nil {
		if !r.opts.MultiTenant {
			ids.Spec.ComponentResources = []operatorv1.IntrusionDetectionComponentResource{
				{
					ComponentName: operatorv1.ComponentNameDeepPacketInspection,
					ResourceRequirements: &corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse(dpi.DefaultMemoryLimit),
							corev1.ResourceCPU:    resource.MustParse(dpi.DefaultCPULimit),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse(dpi.DefaultMemoryRequest),
							corev1.ResourceCPU:    resource.MustParse(dpi.DefaultCPURequest),
						},
					},
				},
			}
		}
	}

	if err := r.client.Update(ctx, ids); err != nil {
		return err
	}

	return nil
}
