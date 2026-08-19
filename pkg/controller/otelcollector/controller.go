// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package otelcollector

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	appsv1 "k8s.io/api/apps/v1"
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
	"github.com/tigera/operator/pkg/common/validation"
	otelvalidation "github.com/tigera/operator/pkg/common/validation/enterprise/otelcollector"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/render/otelcollector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	controllerName = "log-collector-otel-controller"
	ResourceName   = "log-collector-otel"
)

var log = logf.Log.WithName(controllerName)

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		return nil
	}

	licenseAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}

	statusManager := status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts, licenseAPIReady, tierWatchReady)

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: otelcollector.OpenTelemetryCollectorPolicyName, Namespace: otelcollector.OpenTelemetryCollectorNamespace},
	})

	if err = c.WatchObject(&operatorv1.LogCollector{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	if err = utils.AddAPIServerWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch APIServer resource: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("%s failed to watch TigeraStatus: %w", controllerName, err)
	}

	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to create periodic reconcile watch: %w", controllerName, err)
	}

	// Watch the workload and ConfigMap so out-of-band edits/deletes trigger reconcile.
	if err = utils.AddNamespacedWatch(c, &appsv1.StatefulSet{
		TypeMeta:   metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: otelcollector.OpenTelemetryCollectorStatefulSetName, Namespace: otelcollector.OpenTelemetryCollectorNamespace},
	}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch StatefulSet: %w", controllerName, err)
	}

	if err = utils.AddConfigMapWatch(c, otelcollector.OpenTelemetryCollectorConfigMapName, otelcollector.OpenTelemetryCollectorNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch ConfigMap: %w", controllerName, err)
	}

	if err = utils.AddSecretsWatch(c, otelcollector.OpenTelemetryCollectorServerTLSSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch the Secret resource(%s): %w", controllerName, otelcollector.OpenTelemetryCollectorServerTLSSecretName, err)
	}

	// The operator's CA rotates ahead of expiry; without this the collector would
	// keep verifying fluent-bit against a stale CA and silently reject every
	// connection until something else restarted it.
	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch the Secret resource(%s): %w", controllerName, certificatemanagement.CASecretName, err)
	}

	// Exporter TLS and auth material is named by the user per exporter, so there is
	// no fixed name to watch. Watch the namespace instead and let the reconcile
	// decide, which also covers a Secret being renamed in the spec.
	if err = utils.AddConfigMapWatch(c, "", common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch ConfigMaps in %s: %w", controllerName, common.OperatorNamespace(), err)
	}

	if err = utils.AddSecretsWatch(c, "", common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secrets in %s: %w", controllerName, common.OperatorNamespace(), err)
	}

	return nil
}

func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	opts options.ControllerOptions,
	licenseAPIReady *utils.ReadyFlag,
	tierWatchReady *utils.ReadyFlag,
) *Reconciler {
	r := &Reconciler{
		cli:             cli,
		scheme:          schema,
		status:          statusMgr,
		opts:            opts,
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	cli             client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	opts            options.ControllerOptions
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
}

func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling OpenTelemetry")

	logCollector, err := utils.GetIfExists[operatorv1.LogCollector](ctx, utils.DefaultEnterpriseInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying LogCollector CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if logCollector == nil {
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	installationSpec, err := utils.GetInstallationSpec(ctx, r.cli)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation to be available", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Everything below renders one component, enabled or not: nothing the collector
	// owns is garbage-collected on its own, so stopping export means rendering for
	// removal rather than returning early. disabled carries which it is.
	disabled := logCollector.Spec.OpenTelemetry == nil
	if disabled {
		if err := r.applyCollector(ctx, logCollector, disabledConfig(installationSpec), reqLogger); err != nil {
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	r.status.OnCRFound()
	defer r.status.SetMetaData(&logCollector.ObjectMeta)

	if !utils.IsProjectCalicoV3Available(r.cli, r.opts, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Calico API to be ready", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.cli)
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

	// Both are definitive answers about entitlement, so stop exporting rather than
	// leaving a collector forwarding after it lapses. Transient states above -- API
	// not ready, license unreadable -- requeue instead, so a blip cannot flap it.
	if !utils.IsFeatureActive(license, common.OpenTelemetryCollectorFeature) {
		if err := r.applyCollector(ctx, logCollector, disabledConfig(installationSpec), reqLogger); err != nil {
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support OTEL", nil, reqLogger)
		return reconcile.Result{}, nil
	}
	if licenseStatus == utils.LicenseStatusExpired {
		if err := r.applyCollector(ctx, logCollector, disabledConfig(installationSpec), reqLogger); err != nil {
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			"License is expired - OpenTelemetry collector forwarding is stopped. Contact Tigera support or email licensing@tigera.io", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	var graceRequeueAfter time.Duration
	if licenseStatus == utils.LicenseStatusInGracePeriod {
		reqLogger.Info("License has expired and is within the grace period. Please renew your license to avoid service disruption.")
		graceRequeueAfter = time.Until(license.Status.Expiry.Add(gracePeriod))
	}

	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	if err := r.cli.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Error querying calico-system tier", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Reject specs the collector cannot start from, rather than rendering a config
	// it will reject at boot. Neither error can fix itself, so requeue on the CR
	// watch rather than backing off.
	if msg, err := validateSpec(logCollector.Spec.OpenTelemetry); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, msg, err, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	var receiverTLSSecret certificatemanagement.KeyPairInterface
	var trustedBundle certificatemanagement.TrustedBundle

	if logCollector.Spec.OpenTelemetry.HasDataSources() {
		certMgr, err := certificatemanager.Create(r.cli, installationSpec, r.opts.ClusterDomain, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
			return reconcile.Result{}, err
		}

		// The Prometheus serving certificate has to be trusted for the federation
		// scrape to verify; it is not in the CA bundle when Prometheus uses a
		// user-supplied cert.
		var extraCerts []certificatemanagement.CertificateInterface
		if logCollector.Spec.OpenTelemetry.MetricsEnabled() {
			prometheusCert, err := certMgr.GetCertificate(r.cli, monitor.PrometheusServerTLSSecretName, common.OperatorNamespace())
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error reading Secret %s", monitor.PrometheusServerTLSSecretName), err, reqLogger)
				return reconcile.Result{}, err
			}
			if prometheusCert == nil {
				r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for Secret %s, required to verify the Prometheus federation endpoint", monitor.PrometheusServerTLSSecretName), nil, reqLogger)
				return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
			}
			extraCerts = append(extraCerts, prometheusCert)
		}

		// Its own bundle, to avoid contamination with other services in this namespace.
		trustedBundle = certificatemanagement.CreateNamedTrustedBundle(
			otelcollector.OpenTelemetryCollectorName, certMgr.KeyPair(), false, extraCerts...)

		if logCollector.Spec.OpenTelemetry.HasLogs() {
			dnsNames := dns.GetServiceDNSNames(otelcollector.OpenTelemetryCollectorServiceName, otelcollector.OpenTelemetryCollectorNamespace, r.opts.ClusterDomain)
			receiverTLSSecret, err = certMgr.GetOrCreateKeyPair(r.cli, otelcollector.OpenTelemetryCollectorServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating OpenTelemetry receiver TLS certificate", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		certMgr.AddToStatusManager(r.status, otelcollector.OpenTelemetryCollectorNamespace)
	}

	// Per-exporter TLS and auth material. Each is named by the exporter that uses
	// it, so backends can be given different trust anchors and different client
	// identities. Exporter CAs are deliberately kept out of the trusted bundle:
	// that bundle backs the receiver's client_ca_file, so adding one there would
	// make it a valid signer for inbound client certificates.
	exporterCAs, exporterClientCerts, exporterAuthSecrets, degraded, err := r.fetchExporterMaterial(ctx, logCollector.Spec.OpenTelemetry, reqLogger)
	if degraded {
		return reconcile.Result{}, err
	}

	cfg := &otelcollector.Configuration{
		PullSecrets:         pullSecrets,
		OpenShift:           r.opts.DetectedProvider.IsOpenShift(),
		Installation:        installationSpec,
		OpenTelemetry:       logCollector.Spec.OpenTelemetry,
		ReceiverTLSSecret:   receiverTLSSecret,
		TrustedCertBundle:   trustedBundle,
		ExporterCAs:         exporterCAs,
		ExporterClientCerts: exporterClientCerts,
		ExporterAuthSecrets: exporterAuthSecrets,
		DomainEgressAllowed: utils.IsFeatureActive(license, common.EgressAccessControlFeature),
	}

	var keyPairOptions []rcertificatemanagement.KeyPairOption
	if receiverTLSSecret != nil {
		keyPairOptions = append(keyPairOptions, rcertificatemanagement.NewKeyPairOption(receiverTLSSecret, true, true))
	}

	var extra []render.Component
	if logCollector.Spec.OpenTelemetry.HasDataSources() {
		extra = append(extra, rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       otelcollector.OpenTelemetryCollectorNamespace,
			ServiceAccounts: []string{otelcollector.OpenTelemetryCollectorServiceAccountName},
			KeyPairOptions:  keyPairOptions,
			TrustedBundle:   trustedBundle,
		}))
	}

	if err := r.applyCollector(ctx, logCollector, cfg, reqLogger, extra...); err != nil {
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	return reconcile.Result{RequeueAfter: graceRequeueAfter}, nil
}

// validateSpec covers both halves of what the user can get wrong: the export
// config itself, and the StatefulSet overrides. The latter cannot move into
// OpenTelemetrySpec.Validate -- that lives in the api module, and the override
// validator is in pkg/common/validation, which imports the api module.
func validateSpec(spec *operatorv1.OpenTelemetrySpec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "Invalid OpenTelemetry configuration", err
	}
	if spec.OpenTelemetryCollectorStatefulSet != nil {
		if err := validation.ValidateReplicatedPodResourceOverrides(
			spec.OpenTelemetryCollectorStatefulSet,
			otelvalidation.ValidateOpenTelemetryCollectorStatefulSetContainer,
			validation.NoContainersDefined,
		); err != nil {
			return "Invalid statefulSet overrides", err
		}
	}
	return "", nil
}

// disabledConfig is the configuration that renders the collector for removal.
func disabledConfig(installationSpec *operatorv1.InstallationSpec) *otelcollector.Configuration {
	return &otelcollector.Configuration{
		Installation:  installationSpec,
		OpenTelemetry: &operatorv1.OpenTelemetrySpec{},
		Disabled:      true,
	}
}

// applyCollector renders and applies the component. The same call handles both
// directions: cfg.Disabled decides whether the objects are created or deleted.
func (r *Reconciler) applyCollector(ctx context.Context, logCollector *operatorv1.LogCollector, cfg *otelcollector.Configuration, reqLogger logr.Logger, extra ...render.Component) error {
	comp, err := otelcollector.OpenTelemetryCollector(cfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering OpenTelemetry collector config", err, reqLogger)
		return err
	}

	components := append([]render.Component{comp}, extra...)
	if err := imageset.ApplyImageSet(ctx, r.cli, r.opts.Variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return err
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, logCollector)
	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return err
		}
	}
	return nil
}

// fetchExporterMaterial reads the CA ConfigMap, client keypair Secret and header
// credential Secrets each exporter names. The bool reports that the reconcile has
// already been degraded and should stop.
func (r *Reconciler) fetchExporterMaterial(
	ctx context.Context, spec *operatorv1.OpenTelemetrySpec, reqLogger logr.Logger,
) (map[string]*corev1.ConfigMap, map[string]*corev1.Secret, map[string]*corev1.Secret, bool, error) {
	cas := map[string]*corev1.ConfigMap{}
	certs := map[string]*corev1.Secret{}
	auth := map[string]*corev1.Secret{}
	ns := common.OperatorNamespace()

	for _, exp := range spec.Exporters {
		if name := exp.CAConfigMap(); name != "" {
			cm := &corev1.ConfigMap{}
			if err := r.cli.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, cm); err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError,
					fmt.Sprintf("Waiting for ConfigMap %s, named by exporter %q tls.caConfigMapName", name, exp.Name), err, reqLogger)
				return nil, nil, nil, true, err
			}
			// The reference is the opt-in, so an empty one is a mistake rather than a
			// default: we would otherwise point ca_file at a path the mount never
			// materialises and the collector would fail to start.
			if len(cm.Data[corev1.TLSCertKey]) == 0 {
				r.status.SetDegraded(operatorv1.ResourceValidationError,
					fmt.Sprintf("ConfigMap %s must contain a %q key holding the CA for exporter %q", name, corev1.TLSCertKey, exp.Name), nil, reqLogger)
				return nil, nil, nil, true, nil
			}
			cas[exp.Name] = cm
		}

		if name := exp.ClientCertSecret(); name != "" {
			s := &corev1.Secret{}
			if err := r.cli.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, s); err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError,
					fmt.Sprintf("Waiting for Secret %s, named by exporter %q tls.clientCertSecretName", name, exp.Name), err, reqLogger)
				return nil, nil, nil, true, err
			}
			if len(s.Data[corev1.TLSCertKey]) == 0 || len(s.Data[corev1.TLSPrivateKeyKey]) == 0 {
				r.status.SetDegraded(operatorv1.ResourceValidationError,
					fmt.Sprintf("Secret %s must contain both %q and %q for exporter %q", name, corev1.TLSCertKey, corev1.TLSPrivateKeyKey, exp.Name), nil, reqLogger)
				return nil, nil, nil, true, nil
			}
			certs[exp.Name] = s
		}

		for _, h := range exp.AuthHeaders() {
			ref := h.ValueFrom.SecretKeyRef
			// Dedupe the fetch, not the validation: two headers may read different
			// keys of the same Secret, and skipping the second would let a missing
			// key through to render an empty credential.
			s, fetched := auth[ref.Name]
			if !fetched {
				s = &corev1.Secret{}
				if err := r.cli.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: ns}, s); err != nil {
					r.status.SetDegraded(operatorv1.ResourceReadError,
						fmt.Sprintf("Waiting for Secret %s, named by exporter %q header %q", ref.Name, exp.Name, h.Name), err, reqLogger)
					return nil, nil, nil, true, err
				}
				auth[ref.Name] = s
			}
			if len(s.Data[ref.Key]) == 0 {
				r.status.SetDegraded(operatorv1.ResourceValidationError,
					fmt.Sprintf("Secret %s must contain key %q, named by exporter %q header %q", ref.Name, ref.Key, exp.Name, h.Name), nil, reqLogger)
				return nil, nil, nil, true, nil
			}
		}
	}
	return cas, certs, auth, false, nil
}
