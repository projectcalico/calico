// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package monitor

import (
	"context"
	_ "embed"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	rauth "github.com/tigera/operator/pkg/render/common/authentication"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rsecret "github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const ResourceName = "monitor"

var log = logf.Log.WithName("controller_monitor")

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	prometheusReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}
	licenseAPIReady := &utils.ReadyFlag{}

	// Create the reconciler
	reconciler := newReconciler(mgr, opts, prometheusReady, tierWatchReady, licenseAPIReady)

	// Create a new controller
	c, err := ctrlruntime.NewController("monitor-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create monitor-controller: %w", err)
	}

	policyNames := []types.NamespacedName{
		{Name: monitor.PrometheusPolicyName, Namespace: common.TigeraPrometheusNamespace},
		{Name: monitor.PrometheusAPIPolicyName, Namespace: common.TigeraPrometheusNamespace},
		{Name: monitor.PrometheusOperatorPolicyName, Namespace: common.TigeraPrometheusNamespace},
		{Name: monitor.AlertmanagerPolicyName, Namespace: common.TigeraPrometheusNamespace},
		{Name: monitor.MeshAlertmanagerPolicyName, Namespace: common.TigeraPrometheusNamespace},
		{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: common.TigeraPrometheusNamespace},
	}

	// Watch for changes to Tier, as its status is used as input to determine whether network policy should be reconciled by this controller.
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)

	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, policyNames)

	go waitToAddPrometheusWatch(c, opts.K8sClientset, log, prometheusReady)

	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)

	return add(mgr, c)
}

func newReconciler(mgr manager.Manager, opts options.ControllerOptions, prometheusReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag, licenseAPIReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileMonitor{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "monitor", opts.KubernetesVersion),
		prometheusReady: prometheusReady,
		tierWatchReady:  tierWatchReady,
		licenseAPIReady: licenseAPIReady,
		clusterDomain:   opts.ClusterDomain,
		multiTenant:     opts.MultiTenant,
		cloud:           opts.Cloud,
	}

	r.status.AddStatefulSets([]types.NamespacedName{
		{Namespace: common.TigeraPrometheusNamespace, Name: fmt.Sprintf("prometheus-%s", monitor.CalicoNodePrometheus)},
	})

	r.status.Run(opts.ShutdownContext)
	return r
}

func add(_ manager.Manager, c ctrlruntime.Controller) error {
	var err error

	// watch for primary resource changes
	if err = c.WatchObject(&operatorv1.Monitor{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("monitor-controller failed to watch primary resource: %w", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("monitor-controller failed to watch Installation resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("monitor-controller failed to watch ImageSet: %w", err)
	}

	// ManagementClusterConnection (in addition to Installation) is used as input to determine whether network policy should be reconciled.
	err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("monitor-controller failed to watch ManagementClusterConnection resource: %w", err)
	}

	if err = c.WatchObject(&v3.FelixConfiguration{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("monitor-controller failed to watch FelixConfiguration resource: %w", err)
	}

	for _, secret := range []string{
		certificatemanagement.CASecretName,
		esmetrics.ElasticsearchMetricsServerTLSSecret,
		monitor.PrometheusServerTLSSecretName,
		render.NodePrometheusTLSServerSecret,
		kubecontrollers.KubeControllerPrometheusTLSSecret,
	} {
		if err = utils.AddSecretsWatch(c, secret, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("monitor-controller failed to watch secret: %w", err)
		}
	}

	// Namespaces are watched in case external monitoring config is used.
	err = c.WatchObject(&corev1.Namespace{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("monitor-controller failed to watch resource: %w", err)
	}

	err = c.WatchObject(&operatorv1.Authentication{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("monitor-controller failed to watch resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("monitor-controller failed to watch monitor Tigerastatus: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileMonitor implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileMonitor{}

type ReconcileMonitor struct {
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	prometheusReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	licenseAPIReady *utils.ReadyFlag
	clusterDomain   string
	multiTenant     bool
	cloud           bool
}

func (r *ReconcileMonitor) getMonitor(ctx context.Context) (*operatorv1.Monitor, error) {
	instance := &operatorv1.Monitor{}
	err := r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (r *ReconcileMonitor) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Monitor")

	instance, err := r.getMonitor(ctx)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query Monitor", err, reqLogger)
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating Monitor status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create Monitor status conditions.")
			return reconcile.Result{}, err
		}
	}
	preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())
	fillDefaults(instance)
	// Patch the monitor resource with defaults added.
	if err = r.client.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Track alertmanager statefulset health only when it has replicas.
	alertmanagerSS := types.NamespacedName{Namespace: common.TigeraPrometheusNamespace, Name: fmt.Sprintf("alertmanager-%s", monitor.CalicoNodeAlertmanager)}
	if instance.Spec.Alertmanager != nil && instance.Spec.Alertmanager.AlertmanagerSpec != nil &&
		instance.Spec.Alertmanager.AlertmanagerSpec.Replicas != nil && *instance.Spec.Alertmanager.AlertmanagerSpec.Replicas > 0 {
		r.status.AddStatefulSets([]types.NamespacedName{alertmanagerSS})
	} else {
		r.status.RemoveStatefulSets(alertmanagerSS)
	}
	if instance.Spec.ExternalPrometheus != nil {
		if err = r.client.Get(ctx, client.ObjectKey{Name: instance.Spec.ExternalPrometheus.Namespace}, &corev1.Namespace{}); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to get external prometheus namespace %s",
				instance.Spec.ExternalPrometheus.Namespace), err, reqLogger)
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

	gracePeriod := utils.ParseGracePeriod(license.Status.GracePeriod)
	licenseStatus := utils.GetLicenseStatus(license, gracePeriod)
	licenseExpired := licenseStatus == utils.LicenseStatusExpired

	// When in the grace period, schedule a requeue so the controller automatically
	// transitions to expired state when the grace period elapses.
	var graceRequeueAfter time.Duration
	if licenseStatus == utils.LicenseStatusInGracePeriod {
		reqLogger.Info("License has expired and is within the grace period. Please renew your license to avoid service disruption.")
		graceRequeueAfter = time.Until(license.Status.Expiry.Add(gracePeriod))
	}

	variant, installationSpec, err := utils.GetInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !r.prometheusReady.IsReady() {
		err = fmt.Errorf("waiting for Prometheus resources")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Prometheus resources to be ready", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	var serverTLSSecret certificatemanagement.KeyPairInterface
	if instance.Spec.ExternalPrometheus == nil || installationSpec.CertificateManagement != nil {
		// We're either not using an external prometheus in which case we simply sign the KeyPair directly using the certificateManager,
		// or we are configured to use a custom TLS secret, which is also handled under the covers by `GetOrCreateKeyPair`.
		serverTLSSecret, err = certificateManager.GetOrCreateKeyPair(r.client, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), PrometheusTLSServerDNSNames(r.clusterDomain))
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
	} else {
		// Prometheus requires to have an IP SAN in its certificate, so that it can be scraped by an external prometheus pod.
		// Since we do not know what IP the pods will have, the pod will issue a CSR on startup for a certificate containing
		// its own IP. pkg/controller/csr/csr_controller.go will then sign the certificate.
		serverTLSSecret = certificateManager.CreateCSRKeyPair(monitor.PrometheusServerTLSSecretName, common.OperatorNamespace(), PrometheusTLSServerDNSNames(r.clusterDomain))
	}

	clientTLSSecret, err := certificateManager.GetOrCreateKeyPair(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusClientTLSSecretName})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Note: fluent-bit is not in this list — its metrics endpoint is scraped
	// over plain HTTP (fluent-bit's monitoring server has no TLS support), so
	// Prometheus has no need to trust the fluent-bit certificate.
	trustedBundle := certificateManager.CreateTrustedBundle()
	for _, certificateName := range []string{
		esmetrics.ElasticsearchMetricsServerTLSSecret,
		render.NodePrometheusTLSServerSecret,
		render.CalicoAPIServerTLSSecretName,
		kubecontrollers.KubeControllerPrometheusTLSSecret,
	} {
		certificate, err := certificateManager.GetCertificate(r.client, certificateName, common.OperatorNamespace())
		if err == nil {
			trustedBundle.AddCertificates(certificate)
		} else {
			if certificatemanager.IsCertExtKeyUsageError(err) {
				// This secret is missing required key usages. Another controller will need to replace this secret with a
				// new valid secret, before this controller will read and use it. The other controller may depend on this
				// controller completing successfully. Therefore, we skip and continue.
				log.Info(fmt.Sprintf("skipping %s/%s secret it will be added when it is updated: %s", common.OperatorNamespace(), certificateName, err))
			} else {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Error fetching TLS certificate", err, reqLogger)
				return reconcile.Result{}, err
			}
		}
	}
	certificateManager.AddToStatusManager(r.status, common.TigeraPrometheusNamespace)

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}
	var keyValidatorConfig rauth.KeyValidatorConfig
	if authenticationCR != nil && authenticationCR.Status.State == operatorv1.TigeraStatusReady {
		keyValidatorConfig, err = utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain, r.cloud && !r.multiTenant)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to process the authentication CR.", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	includeV3NetworkPolicy := false
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		// The creation of the Tier depends on this controller to reconcile it's non-NetworkPolicy resources so that the
		// License becomes available (in managed clusters). Therefore, if we fail to query the Tier, we exclude NetworkPolicy
		// from reconciliation and tolerate errors arising from the Tier not being created.
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	} else {
		includeV3NetworkPolicy = true
	}

	// Create a component handler to manage the rendered component.
	hdler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	alertmanagerConfigSecret, createInOperatorNamespace, err := r.readAlertmanagerConfigSecret(ctx)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving Alertmanager configuration secret", err, reqLogger)
		return reconcile.Result{}, err
	}

	kubeControllersMetricsPort, err := utils.GetKubeControllerMetricsPort(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read KubeControllersConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	felixConfiguration, err := utils.GetFelixConfiguration(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving Felix configuration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create operator TLS keypair only when mTLS is enabled (METRICS_SCHEME=https).
	// The Service and ServiceMonitor are created whenever metrics are enabled.
	operatorMetricsEnabled := common.MetricsEnabled()
	var operatorTLSSecret certificatemanagement.KeyPairInterface
	if common.MetricsTLSEnabled() {
		operatorMetricsServiceName := common.OperatorName() + "-metrics"
		operatorTLSDNSNames := dns.GetServiceDNSNames(operatorMetricsServiceName, common.OperatorNamespace(), r.clusterDomain)
		operatorTLSSecret, err = certificateManager.GetOrCreateKeyPair(r.client, monitor.OperatorTLSSecretName, common.OperatorNamespace(), operatorTLSDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating operator metrics TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
		trustedBundle.AddCertificates(operatorTLSSecret)
	}

	monitorCfg := &monitor.Config{
		Monitor:                       instance.Spec,
		Installation:                  installationSpec,
		PullSecrets:                   pullSecrets,
		AlertmanagerConfigSecret:      alertmanagerConfigSecret,
		KeyValidatorConfig:            keyValidatorConfig,
		ServerTLSSecret:               serverTLSSecret,
		ClientTLSSecret:               clientTLSSecret,
		ClusterDomain:                 r.clusterDomain,
		TrustedCertBundle:             trustedBundle,
		OpenShift:                     r.provider.IsOpenShift(),
		KubeControllerPort:            kubeControllersMetricsPort,
		FelixPrometheusMetricsEnabled: utils.IsFelixPrometheusMetricsEnabled(felixConfiguration),
		LicenseExpired:                licenseExpired,
		OperatorMetricsEnabled:        operatorMetricsEnabled,
		OperatorNamespace:             common.OperatorNamespace(),
		OperatorName:                  common.OperatorName(),
		OperatorTLSSecret:             operatorTLSSecret,
	}

	// Render prometheus component
	components := []render.Component{
		monitor.Monitor(monitorCfg),
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       common.TigeraPrometheusNamespace,
			ServiceAccounts: []string{monitor.PrometheusServiceAccountName},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(serverTLSSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(clientTLSSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(operatorTLSSecret, true, true),
			},
			TrustedBundle: trustedBundle,
		}),
	}

	if createInOperatorNamespace {
		components = append(components, render.NewCreationPassthrough(alertmanagerConfigSecret))
	}

	// v3 NetworkPolicy will fail to reconcile if the Tier is not created, which can only occur once a License is created.
	// In managed clusters, the monitor controller is a dependency for the License to be created. In case the License is
	// unavailable and reconciliation of non-NetworkPolicy resources in the monitor controller would resolve it, we
	// render network policies last to prevent a chicken-and-egg scenario.
	if includeV3NetworkPolicy {
		components = append(components, monitor.MonitorPolicy(monitorCfg))
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err = hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	if licenseExpired {
		r.status.ClearWarning("license-grace-period")
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			"License is expired - Contact Tigera support or email licensing@tigera.io", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Check license grace period warning.
	if licenseStatus == utils.LicenseStatusInGracePeriod {
		r.status.SetWarning("license-grace-period",
			"License has expired and is within the grace period. Please renew your license to avoid service disruption.")
	} else {
		r.status.ClearWarning("license-grace-period")
	}

	// Check BYO certificate expiry warnings.
	certificatemanagement.CheckKeyPairWarnings(map[string]certificatemanagement.KeyPairInterface{
		monitor.PrometheusServerTLSSecretName: serverTLSSecret,
		monitor.PrometheusClientTLSSecretName: clientTLSSecret,
	}, r.status)

	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	instance.Status.State = operatorv1.TigeraStatusReady
	if err := r.client.Status().Update(ctx, instance); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, fmt.Sprintf("Error updating the monitor status %s", operatorv1.TigeraStatusReady), err, reqLogger)
		return reconcile.Result{}, err
	}

	return reconcile.Result{RequeueAfter: graceRequeueAfter}, nil
}

func fillDefaults(instance *operatorv1.Monitor) {
	if instance.Spec.Alertmanager == nil {
		instance.Spec.Alertmanager = &operatorv1.Alertmanager{}
	}
	if instance.Spec.Alertmanager.AlertmanagerSpec == nil {
		instance.Spec.Alertmanager.AlertmanagerSpec = &operatorv1.AlertmanagerSpec{}
	}
	if instance.Spec.Alertmanager.AlertmanagerSpec.Replicas == nil {
		var replicas int32 = 0
		instance.Spec.Alertmanager.AlertmanagerSpec.Replicas = &replicas
	}

	if instance.Spec.ExternalPrometheus != nil && instance.Spec.ExternalPrometheus.ServiceMonitor != nil {

		if len(instance.Spec.ExternalPrometheus.ServiceMonitor.Labels) == 0 {
			instance.Spec.ExternalPrometheus.ServiceMonitor.Labels = map[string]string{
				render.AppLabelName: monitor.TigeraExternalPrometheus,
			}
		}

		if len(instance.Spec.ExternalPrometheus.ServiceMonitor.Endpoints) == 0 {
			instance.Spec.ExternalPrometheus.ServiceMonitor.Endpoints = []operatorv1.Endpoint{{}}
		}

		for i, ep := range instance.Spec.ExternalPrometheus.ServiceMonitor.Endpoints {
			if len(ep.Params) == 0 {
				// The following params let us scrape all metrics.
				ep.Params = map[string][]string{"match[]": {"{__name__=~\".+\"}"}}
			}
			if ep.BearerTokenSecret.Key == "" || ep.BearerTokenSecret.Name == "" {
				ep.BearerTokenSecret = corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: monitor.TigeraExternalPrometheus,
					},
					Key: "token",
				}
			}
			instance.Spec.ExternalPrometheus.ServiceMonitor.Endpoints[i] = ep
		}
	}
}

// PrometheusTLSServerDNSNames returns all the DNS names valid for the prometheus server TLS asset.
func PrometheusTLSServerDNSNames(clusterDomain string) []string {
	return dns.GetServiceDNSNames(monitor.PrometheusServiceServiceName, common.TigeraPrometheusNamespace, clusterDomain)
}

//go:embed alertmanager-config.yaml
var alertmanagerConfig string

// readAlertmanagerConfigSecret attempts to retrieve Alertmanager configuration secret from either the Tigera Operator
// namespace or the Tigera Prometheus namespace. If it doesn't exist in either of the namespace, a new default configuration
// secret will be created.
func (r *ReconcileMonitor) readAlertmanagerConfigSecret(ctx context.Context) (*corev1.Secret, bool, error) {
	// Previous to this change, a customer was expected to deploy the Alertmanager configuration secret
	// in the tigera-prometheus namespace directly. Now that this secret is managed by the Operator,
	// the customer must deploy this secret in the tigera-operator namespace. The Operator then copies
	// the secret from the tigera-operator namespace to the tigera-prometheus namespace.
	//
	// For new installation:
	//   A new secret will be created in the tigera-operator namespace and then copied to the tigera-prometheus namespace.
	//   Monitor controller holds the ownership of this secret.
	//
	// To handle upgrades:
	//   The tigera-prometheus secret will be copied back to the tigera-operator namespace.
	//   If this secret is modified by the user, Monitor controller won't set the ownership. Otherwise, it is owned by the Monitor.
	//
	// Tigera Operator will then watch for secret changes in the tigera-operator namespace and overwrite
	// any changes for this secret in the tigera-prometheus namespace. For future Alertmanager configuration changes,
	// Monitor controller can verify the owner reference of the configuration secret and decide if we want to
	// upgrade it automatically.

	defaultConfigSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.AlertmanagerConfigSecret,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string][]byte{
			"alertmanager.yaml": []byte(alertmanagerConfig),
		},
	}

	// Read Alertmanager configuration secret as-is if it is found in the tigera-operator namespace.
	secret, err := utils.GetSecret(ctx, r.client, monitor.AlertmanagerConfigSecret, common.OperatorNamespace())
	if err != nil {
		return nil, false, err
	} else if secret != nil {
		return secret, false, nil
	}

	// When Alertmanager configuration isn't found in the tigera-operator namespace, copy it from the tigera-prometheus namespace (upgrade).
	// If it is modified by the user, Monitor controller will not set the owner reference.
	secret, err = utils.GetSecret(ctx, r.client, monitor.AlertmanagerConfigSecret, common.TigeraPrometheusNamespace)
	if err != nil {
		return nil, false, err
	} else if secret != nil {
		// Monitor controller will own the secret if it is the same.
		if reflect.DeepEqual(defaultConfigSecret.Data, secret.Data) {
			return rsecret.CopyToNamespace(common.OperatorNamespace(), secret)[0], true, nil
		}

		// If the secret isn't the same, leave it unmanaged.
		s := rsecret.CopyToNamespace(common.OperatorNamespace(), secret)[0]
		if err := r.client.Create(ctx, s); err != nil {
			return nil, false, err
		}
		return s, false, nil
	}

	// Alertmanager configuration secret is not found in the tigera-operator or tigera-prometheus namespace (new install).
	// Operator should create a new default secret and set the owner reference.
	return defaultConfigSecret, true, nil
}
