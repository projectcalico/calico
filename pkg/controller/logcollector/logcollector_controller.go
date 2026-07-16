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

package logcollector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tigera/operator/pkg/dns"
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
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rlogcollector "github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/url"
)

const ResourceName = "log-collector"

var log = logf.Log.WithName("controller_logcollector")

// Add creates a new LogCollector Controller and adds it to the Manager. The Manager will set fields on the Controller
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
	c, err := ctrlruntime.NewController("logcollector-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return fmt.Errorf("failed to create logcollector-controller: %v", err)
	}

	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: rlogcollector.FluentBitPolicyName, Namespace: render.LogCollectorNamespace},
	})

	if opts.MultiTenant {
		if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("logcollector-controller failed to watch Tenant resource: %w", err)
		}
	}

	return add(mgr, c)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, licenseAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	c := &ReconcileLogCollector{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		status:          status.New(mgr.GetClient(), "log-collector", opts.KubernetesVersion),
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		opts:            opts,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// add adds watches for resources that are available at startup
func add(mgr manager.Manager, c ctrlruntime.Controller) error {
	var err error

	// Watch for changes to primary resource LogCollector
	err = c.WatchObject(&operatorv1.LogCollector{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch primary resource: %v", err)
	}

	err = utils.AddAPIServerWatch(c)
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch APIServer resource: %v", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch Installation resource: %v", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch ImageSet: %w", err)
	}

	for _, secretName := range []string{
		rlogcollector.S3FluentBitSecretName, rlogcollector.EksLogForwarderSecret,
		rlogcollector.SplunkFluentBitTokenSecretName, monitor.PrometheusClientTLSSecretName,
		rlogcollector.FluentBitTLSSecretName, render.TigeraLinseedSecret, render.VoltronLinseedPublicCert, rlogcollector.EKSLogForwarderTLSSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-collector-controller failed to watch the Secret resource(%s): %v", secretName, err)
		}
	}

	if err = utils.AddConfigMapWatch(c, rlogcollector.FluentBitFilterConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch ConfigMap %s: %v", rlogcollector.FluentBitFilterConfigMapName, err)
	}

	// Watch the user-supplied CA ConfigMaps so creating or rotating a syslog or
	// Splunk CA takes effect without waiting for an unrelated reconcile.
	for _, caConfigMap := range []string{rlogcollector.SyslogCAConfigMapName, rlogcollector.SplunkCAConfigMapName} {
		if err = utils.AddConfigMapWatch(c, caConfigMap, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("logcollector-controller failed to watch ConfigMap %s: %v", caConfigMap, err)
		}
	}

	// Watch the rendered configuration ConfigMaps so tampering with them
	// triggers a reconcile that restores the rendered content.
	for _, configMapName := range []string{
		rlogcollector.FluentBitConfConfigMapName,
		rlogcollector.FluentBitConfConfigMapName + "-windows",
		rlogcollector.EKSLogForwarderConfConfigMapName,
	} {
		if err = utils.AddConfigMapWatch(c, configMapName, common.CalicoNamespace, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("logcollector-controller failed to watch ConfigMap %s: %v", configMapName, err)
		}
	}

	// Watch the workloads we render so that deleting or editing them out-of-band
	// triggers a reconcile that restores them.
	for _, dsName := range []string{render.FluentBitNodeName, render.FluentBitNodeWindowsName} {
		if err = utils.AddDaemonsetWatch(c, dsName, common.CalicoNamespace); err != nil {
			return fmt.Errorf("logcollector-controller failed to watch DaemonSet %s: %w", dsName, err)
		}
	}
	if err = utils.AddDeploymentWatch(c, render.EKSLogForwarderName, common.CalicoNamespace); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch Deployment %s: %w", render.EKSLogForwarderName, err)
	}

	err = c.WatchObject(&corev1.Node{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch the node resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch log-collector Tigerastatus: %w", err)
	}

	if err = c.WatchObject(&operatorv1.NonClusterHost{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("logcollector-controller failed to watch resource: %w", err)
	}
	return nil
}

// blank assignment to verify that ReconcileLogCollector implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogCollector{}

// ReconcileLogCollector reconciles a LogCollector object
type ReconcileLogCollector struct {
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	opts            options.ControllerOptions
}

// GetLogCollector returns the default LogCollector instance with defaults populated.
func GetLogCollector(ctx context.Context, cli client.Client) (*operatorv1.LogCollector, error) {
	// Fetch the instance. We only support a single instance named "tigera-secure".
	instance := &operatorv1.LogCollector{}
	err := cli.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil {
			_, _, _, err := url.ParseEndpoint(instance.Spec.AdditionalStores.Syslog.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("syslog config has invalid Endpoint: %s", err)
			}
		}
	}

	return instance, nil
}

// fillDefaults sets the default value of CollectProcessPath, syslog LogTypes, if not set.
// This function returns the fields which were set to a default value in the logcollector instance.
func fillDefaults(instance *operatorv1.LogCollector) []string {
	// Keep track of whether we changed the LogCollector instance during reconcile, so that we know to save it.
	// Keep track of which fields were modified (helpful for error messages)
	modifiedFields := []string{}

	if instance.Spec.CollectProcessPath == nil {
		collectProcessPath := operatorv1.CollectProcessPathEnable
		instance.Spec.CollectProcessPath = &collectProcessPath
		modifiedFields = append(modifiedFields, "CollectProcessPath")
	}
	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil {
			syslog := instance.Spec.AdditionalStores.Syslog
			// Special case: For users that have a Syslog config and are upgrading from an older release
			//  where logTypes field did not exist, we will auto-populate default values for
			// them. This should only happen on upgrade, since logTypes is a required field.
			if len(syslog.LogTypes) == 0 {
				// Set default log types to everything except for v1.SyslogLogIDSEvents (since this
				// option was not available prior to the logTypes field being introduced). This ensures
				// existing users continue to get the same expected behavior for Syslog forwarding.
				instance.Spec.AdditionalStores.Syslog.LogTypes = []operatorv1.SyslogLogType{
					operatorv1.SyslogLogAudit,
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
				}
				// Include the field that was modified (in case we need to display error messages)
				modifiedFields = append(modifiedFields, "AdditionalStores.Syslog.LogTypes")
			}
			if len(syslog.Encryption) == 0 {
				instance.Spec.AdditionalStores.Syslog.Encryption = operatorv1.EncryptionNone
				// Include the field that was modified (in case we need to display error messages)
				modifiedFields = append(modifiedFields, "AdditionalStores.Syslog.Encryption")
			}
		}
	}
	return modifiedFields
}

// Reconcile reads that state of the cluster for a LogCollector object and makes changes based on the state read
// and what is in the LogCollector.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogCollector) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogCollector")
	// Fetch the LogCollector instance
	instance, err := GetLogCollector(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("LogCollector object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for LogCollector", err, reqLogger)
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating LogCollector status conditions
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create LogCollector status conditions.")
			return reconcile.Result{}, err
		}
	}

	// Validate the syslog Endpoint scheme before defaulting. Syslog forwarding
	// is TCP or UDP (TLS is selected by the separate encryption field, not the
	// scheme); any other scheme would render a syslog output mode fluent-bit
	// rejects at startup. This runs before fillDefaults on purpose: fillDefaults
	// patches the CR, and the CRD now enforces the tcp/udp Endpoint pattern, so
	// on upgrade a stored legacy scheme would make that patch fail with an
	// opaque apiserver error instead of this clear degraded status.
	if instance.Spec.AdditionalStores != nil && instance.Spec.AdditionalStores.Syslog != nil {
		if proto, _, _, err := url.ParseEndpoint(instance.Spec.AdditionalStores.Syslog.Endpoint); err == nil && proto != "tcp" && proto != "udp" {
			r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Syslog config has invalid Endpoint scheme %q: only tcp:// and udp:// are supported", proto), nil, reqLogger)
			return reconcile.Result{}, nil
		}
	}

	// Default fields on the LogCollector instance if needed.
	preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())
	modifiedFields := fillDefaults(instance)
	if len(modifiedFields) > 0 {
		if err = r.client.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, fmt.Sprintf("Failed to set defaults for LogCollector fields: [%s]",
				strings.Join(modifiedFields, ", "),
			), err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if !utils.IsProjectCalicoV3Available(r.client, r.opts, reqLogger) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, reqLogger)
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
			log.Error(err, "Error querying calico-system tier")
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

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
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
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Try to grab the ManagementClusterConnection CR because we need it for network policy rendering,
	// as well as validation with respect to Syslog.logTypes.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		// Not finding a ManagementClusterConnection CR is not an error, as only a managed cluster will
		// have this CR available, but we should communicate any other kind of error that we encounter.
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "An error occurred while looking for a ManagementClusterConnection", err, reqLogger)
			return reconcile.Result{}, err
		}
	}
	managedCluster := managementClusterConnection != nil

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.opts.ClusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	// fluentBitKeyPair is the key pair fluent-bit presents to identify itself
	httpInputServiceNames := dns.GetServiceDNSNames(render.FluentBitInputService, render.LogCollectorNamespace, r.opts.ClusterDomain)
	fluentBitKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, rlogcollector.FluentBitTLSSecretName, common.OperatorNamespace(), append([]string{rlogcollector.FluentBitTLSSecretName}, httpInputServiceNames...))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, reqLogger)
		return reconcile.Result{}, err
	}

	prometheusCertificate, err := certificateManager.GetCertificate(r.client, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get certificate", err, reqLogger)
		return reconcile.Result{}, err
	} else if prometheusCertificate == nil {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Prometheus secrets are not available yet, waiting until they become available", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Determine whether or not this is a multi-tenant management cluster.
	multiTenantManagement := r.opts.MultiTenant && managementCluster != nil
	if instance.Spec.MultiTenantManagementClusterNamespace != "" && !multiTenantManagement {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "multiTenantManagementClusterNamespace can only be set on multi-tenant management clusters", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// The name of the Linseed certificate varies based on if this is a managed cluster or not.
	// For standalone and management clusters, we just use Linseed's actual certificate.
	linseedCertName := render.TigeraLinseedSecret
	linseedCertNamespace := common.OperatorNamespace()
	var tenant *operatorv1.Tenant
	if managedCluster {
		// For managed clusters, we need to add the certificate of the Voltron endpoint. This certificate is copied from the
		// management cluster into the managed cluster by kube-controllers.
		linseedCertName = render.VoltronLinseedPublicCert
	} else if multiTenantManagement {
		// For multi-tenant management clusters, the linseed certificate isn't in the tigera-operator namespace. Instead, each Linseed has its own
		// certificate in the namespace of the tenant it belongs to. We need to figure out which Linseed belongs to the management cluster itself,
		// and use that certificate instead. We can find this out by looking at the multiTenantManagementClusterNamespace field.
		if instance.Spec.MultiTenantManagementClusterNamespace == "" {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "multiTenantManagementClusterNamespace is not set", nil, reqLogger)
			return reconcile.Result{}, nil
		}
		linseedCertNamespace = instance.Spec.MultiTenantManagementClusterNamespace

		// Make sure that a tenant actually exists in the configured namespace before continuing.
		tenant, _, err = utils.GetTenant(ctx, r.opts.MultiTenant, r.client, instance.Spec.MultiTenantManagementClusterNamespace)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Failed to retrieve tenant in ns %s", instance.Spec.MultiTenantManagementClusterNamespace), err, reqLogger)
			return reconcile.Result{}, err
		}
	}
	linseedCertificate, err := certificateManager.GetCertificate(r.client, linseedCertName, linseedCertNamespace)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, fmt.Sprintf("Failed to retrieve / validate  %s/%s", linseedCertNamespace, linseedCertName), err, reqLogger)
		return reconcile.Result{}, err
	} else if linseedCertificate == nil {
		msg := fmt.Sprintf("Linseed certificate (%s/%s) is not yet available", linseedCertNamespace, linseedCertName)
		log.Info(msg)
		r.status.SetDegraded(operatorv1.ResourceNotReady, msg, nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Fluent Bit needs to mount system certificates in the case where Splunk, Syslog or AWS are used.
	// The bundle carries fluent-bit's own name: calico-system's shared tigera-ca-bundle is rendered by
	// the core Installation controller with a different certificate set, and the component handler
	// replaces ConfigMap data wholesale — an unnamed bundle here would fight it, and additions like
	// the syslog user CA would be lost to whichever controller wrote last.
	trustedBundle := certificatemanagement.CreateNamedTrustedBundle(render.FluentBitNodeName, certificateManager.KeyPair(), true, prometheusCertificate, linseedCertificate)

	certificateManager.AddToStatusManager(r.status, render.LogCollectorNamespace)

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

	exportLogs := utils.IsFeatureActive(license, common.ExportLogsFeature)
	if !exportLogs && instance.Spec.AdditionalStores != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Feature is not active - License does not support feature: export-logs", nil, reqLogger)
		return reconcile.Result{}, err
	}

	var s3Credential *rlogcollector.S3Credential
	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.S3 != nil {
			s3Credential, err = getS3Credential(r.client)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceValidationError, "Error with S3 credential secret", err, reqLogger)
				return reconcile.Result{}, err
			}
			if s3Credential == nil {
				r.status.SetDegraded(operatorv1.ResourceNotFound, "S3 credential secret does not exist", nil, reqLogger)
				return reconcile.Result{}, nil
			}
		}
	}

	var splunkCredential *rlogcollector.SplunkCredential
	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Splunk != nil {
			splunkCredential, err = getSplunkCredential(r.client)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceValidationError, "Error with Splunk credential secret", err, reqLogger)
				return reconcile.Result{}, err
			}
			if splunkCredential == nil {
				r.status.SetDegraded(operatorv1.ResourceNotFound, "Splunk credential secret does not exist", nil, reqLogger)
				return reconcile.Result{}, nil
			}
		}
	}

	var useSyslogCertificate bool
	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil && instance.Spec.AdditionalStores.Syslog.Encryption == operatorv1.EncryptionTLS {
			syslogCert, err := getUserCACertificate(r.client, rlogcollector.SyslogCAConfigMapName)
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, "Error loading Syslog certificate", err, reqLogger)
				return reconcile.Result{}, err
			}
			if syslogCert != nil {
				useSyslogCertificate = true
				trustedBundle.AddCertificates(syslogCert)
			}
		}
		// The Splunk output verifies https HEC endpoints against the trusted
		// bundle, so a user CA for a self-hosted Splunk rides the same way as
		// the syslog one. Plain-http endpoints do no verification, so like
		// syslog's TLS gate the CA is only loaded for https.
		if splunk := instance.Spec.AdditionalStores.Splunk; splunk != nil {
			if proto, _, _, err := url.ParseEndpoint(splunk.Endpoint); err == nil && proto == "https" {
				splunkCert, err := getUserCACertificate(r.client, rlogcollector.SplunkCAConfigMapName)
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceReadError, "Error loading Splunk certificate", err, reqLogger)
					return reconcile.Result{}, err
				}
				if splunkCert != nil {
					trustedBundle.AddCertificates(splunkCert)
				}
			}
		}
	}

	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil {
			syslog := instance.Spec.AdditionalStores.Syslog

			// If the user set Syslog.logTypes, we need to ensure that they did not include
			// the v1.SyslogLogIDSEvents option if this is a managed cluster (i.e.
			// ManagementClusterConnection CR is present). This is because IDS events
			// are only forwarded within a non-managed cluster (where LogStorage is present).
			if syslog.LogTypes != nil {
				if err == nil && managedCluster {
					for _, l := range syslog.LogTypes {
						// Set status to degraded to warn user and let them fix the issue themselves.
						if l == operatorv1.SyslogLogIDSEvents {
							r.status.SetDegraded(operatorv1.ResourceValidationError, "IDSEvents option is not supported for Syslog config in a managed cluster", nil, reqLogger)
							return reconcile.Result{}, err
						}
					}
				}
			}
		}
	}

	filters, err := getFluentBitFilters(r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving Fluent Bit filters", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Surface (non-fatally) any user-provided filter content that is not valid fluent-bit YAML —
	// e.g. a leftover fluentd <filter> block after an upgrade. The render skips such entries so
	// logs keep flowing; raise a warning on the Available condition per key and clear it once the
	// content parses, rather than degrading the whole LogCollector for an optional, malformed filter.
	invalidFilters := map[string]bool{}
	for _, key := range filters.InvalidKeys() {
		invalidFilters[key] = true
	}
	for _, key := range []string{rlogcollector.FluentBitFilterFlowName, rlogcollector.FluentBitFilterDNSName} {
		warningKey := "fluent-bit-filter-" + key
		if invalidFilters[key] {
			r.status.SetWarning(warningKey, fmt.Sprintf("Ignoring the %q entry in the %s ConfigMap: it is not valid fluent-bit YAML. Filters previously written in fluentd syntax must be rewritten as a fluent-bit YAML filter list.", key, rlogcollector.FluentBitFilterConfigMapName))
		} else {
			r.status.ClearWarning(warningKey)
		}
	}

	var eksConfig *rlogcollector.EksCloudwatchLogConfig
	var eksLogForwarderKeyPair certificatemanagement.KeyPairInterface
	if installationSpec.KubernetesProvider.IsEKS() {
		log.Info("Managed kubernetes EKS found, getting necessary credentials and config")
		if instance.Spec.AdditionalSources != nil {
			if instance.Spec.AdditionalSources.EksCloudwatchLog != nil {
				eksConfig, err = getEksCloudwatchLogConfig(r.client,
					instance.Spec.AdditionalSources.EksCloudwatchLog.FetchInterval,
					instance.Spec.AdditionalSources.EksCloudwatchLog.Region,
					instance.Spec.AdditionalSources.EksCloudwatchLog.GroupName,
					instance.Spec.AdditionalSources.EksCloudwatchLog.StreamPrefix)
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving EKS Cloudwatch Logs configuration", err, reqLogger)
					return reconcile.Result{}, err
				}

				// eksLogForwarderKeyPair is the key pair eks-log-forwarder presents to identify itself
				eksLogForwarderKeyPair, err = certificateManager.GetOrCreateKeyPair(r.client, rlogcollector.EKSLogForwarderTLSSecretName, common.OperatorNamespace(), []string{rlogcollector.EKSLogForwarderTLSSecretName})
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating eks log forwarder TLS certificate", err, reqLogger)
					return reconcile.Result{}, err
				}
			}
		}
	}

	// Check if non-cluster host feature is enabled.
	nonclusterhost, err := utils.GetNonClusterHost(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to query NonClusterHost resource", err, reqLogger)
		return reconcile.Result{}, err
	}
	if nonclusterhost != nil {
		if _, _, _, err := url.ParseEndpoint(nonclusterhost.Spec.Endpoint); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read parse endpoint from NonClusterHost resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	fluentBitCfg := &rlogcollector.FluentBitConfiguration{
		LogCollector:           instance,
		S3Credential:           s3Credential,
		SplkCredential:         splunkCredential,
		Filters:                filters,
		EKSConfig:              eksConfig,
		PullSecrets:            pullSecrets,
		Installation:           installationSpec,
		ClusterDomain:          r.opts.ClusterDomain,
		FluentBitKeyPair:       fluentBitKeyPair,
		TrustedBundle:          trustedBundle,
		ManagedCluster:         managedCluster,
		UseSyslogCertificate:   useSyslogCertificate,
		Tenant:                 tenant,
		ExternalElastic:        r.opts.ElasticExternal,
		Cloud:                  r.opts.Cloud,
		EKSLogForwarderKeyPair: eksLogForwarderKeyPair,
		NonClusterHost:         nonclusterhost,
		LicenseExpired:         licenseExpired,
	}
	// Render the fluent-bit component for Linux. The same configuration drives
	// the shared and Windows components below; each applies its OS-specific
	// logic internally (e.g. the Windows render ignores NonClusterHost).
	comp := rlogcollector.FluentBitOSSpecific(fluentBitCfg, rmeta.OSTypeLinux)

	certificateComponent := rcertificatemanagement.Config{
		Namespace:       render.LogCollectorNamespace,
		ServiceAccounts: []string{render.FluentBitNodeName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(fluentBitKeyPair, true, true),
		},
		TrustedBundle: trustedBundle,
	}

	if installationSpec.KubernetesProvider.IsEKS() {
		if instance.Spec.AdditionalSources != nil {
			if instance.Spec.AdditionalSources.EksCloudwatchLog != nil {
				certificateComponent.ServiceAccounts = append(certificateComponent.ServiceAccounts, render.EKSLogForwarderName)
				certificateComponent.KeyPairOptions = append(certificateComponent.KeyPairOptions, rcertificatemanagement.NewKeyPairOption(eksLogForwarderKeyPair, true, true))
			}
		}
	}

	setUp := render.NewSetup(&render.SetUpConfiguration{
		OpenShift:    r.opts.DetectedProvider.IsOpenShift(),
		Installation: installationSpec,
		PullSecrets:  pullSecrets,
		Namespace:    render.LogCollectorNamespace,
		PSS:          render.PSSPrivileged,
		// calico-system is created and owned by the core Installation
		// controller. Owning it from the LogCollector CR would let a routine
		// `kubectl delete logcollector` garbage-collect the entire namespace —
		// calico-node included.
		CreateNamespace: false,
	})
	components := []render.Component{
		setUp,
		// The resources shared by the Linux and Windows installations (the
		// NetworkPolicy, credential copies, managed-cluster Linseed plumbing and
		// the legacy fluentd cleanup) render once, from a single configuration,
		// so the per-OS components cannot contend over them.
		rlogcollector.FluentBitShared(fluentBitCfg),
		comp,
		rcertificatemanagement.CertificateManagement(&certificateComponent),
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, comp); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, comp := range components {
		if err := handler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Render a fluent-bit component for Windows if the cluster has Windows nodes.
	hasWindowsNodes, err := common.HasWindowsNodes(r.client)
	if err != nil {
		return reconcile.Result{}, err
	}

	if hasWindowsNodes {
		// Reuse the same configuration as the Linux and shared components; the
		// OS is what differs, and the component handles the OS-specific logic.
		comp = rlogcollector.FluentBitOSSpecific(fluentBitCfg, rmeta.OSTypeWindows)

		if err = imageset.ApplyImageSet(ctx, r.client, variant, comp); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Create a component handler to manage the rendered component.
		handler = utils.NewComponentHandler(log, r.client, r.scheme, instance)

		if err := handler.CreateOrUpdateOrDelete(ctx, comp, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if licenseExpired {
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			"License is expired - Log forwarding is stopped. Contact Tigera support or email licensing@tigera.io", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Check BYO certificate expiry warnings.
	certificatemanagement.CheckKeyPairWarnings(map[string]certificatemanagement.KeyPairInterface{
		rlogcollector.FluentBitTLSSecretName:       fluentBitKeyPair,
		rlogcollector.EKSLogForwarderTLSSecretName: eksLogForwarderKeyPair,
	}, r.status)

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Everything is available - update the CR status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{RequeueAfter: graceRequeueAfter}, nil
}

func getS3Credential(client client.Client) (*rlogcollector.S3Credential, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      rlogcollector.S3FluentBitSecretName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read secret %q: %s", rlogcollector.S3FluentBitSecretName, err)
	}

	var ok bool
	var kId []byte
	if kId, ok = secret.Data[rlogcollector.S3KeyIdName]; !ok || len(kId) == 0 {
		return nil, fmt.Errorf("expected secret %q to have a field named %q",
			rlogcollector.S3FluentBitSecretName, rlogcollector.S3KeyIdName)
	}
	var kSecret []byte
	if kSecret, ok = secret.Data[rlogcollector.S3KeySecretName]; !ok || len(kSecret) == 0 {
		return nil, fmt.Errorf("expected secret %q to have a field named %q",
			rlogcollector.S3FluentBitSecretName, rlogcollector.S3KeySecretName)
	}

	return &rlogcollector.S3Credential{
		KeyId:     kId,
		KeySecret: kSecret,
	}, nil
}

func getSplunkCredential(client client.Client) (*rlogcollector.SplunkCredential, error) {
	tokenSecret := &corev1.Secret{}
	tokenNamespacedName := types.NamespacedName{
		Name:      rlogcollector.SplunkFluentBitTokenSecretName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), tokenNamespacedName, tokenSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read secret %q: %s", rlogcollector.SplunkFluentBitTokenSecretName, err)
	}

	token, ok := tokenSecret.Data[rlogcollector.SplunkFluentBitSecretTokenKey]
	if !ok || len(token) == 0 {
		return nil, fmt.Errorf("expected secret %q to have a field named %q",
			rlogcollector.SplunkFluentBitTokenSecretName, rlogcollector.SplunkFluentBitSecretTokenKey)
	}

	return &rlogcollector.SplunkCredential{
		Token: token,
	}, nil
}

func getFluentBitFilters(client client.Client) (*rlogcollector.FluentBitFilters, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      rlogcollector.FluentBitFilterConfigMapName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read ConfigMap %q: %s", rlogcollector.FluentBitFilterConfigMapName, err)
	}

	return &rlogcollector.FluentBitFilters{
		Flow: cm.Data[rlogcollector.FluentBitFilterFlowName],
		DNS:  cm.Data[rlogcollector.FluentBitFilterDNSName],
	}, nil
}

func getEksCloudwatchLogConfig(client client.Client, interval int32, region, group, prefix string) (*rlogcollector.EksCloudwatchLogConfig, error) {
	if region == "" {
		return nil, fmt.Errorf("missing AWS region info")
	}

	if group == "" {
		return nil, fmt.Errorf("missing Cloudwatch log group name")
	}

	if prefix == "" {
		prefix = "kube-apiserver-audit-"
	}

	if interval == 0 {
		interval = 60
	}

	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      rlogcollector.EksLogForwarderSecret,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read Secret %q: %s", rlogcollector.EksLogForwarderSecret, err)
	}

	if len(secret.Data[rlogcollector.EksLogForwarderAwsId]) == 0 ||
		len(secret.Data[rlogcollector.EksLogForwarderAwsKey]) == 0 {
		return nil, fmt.Errorf("incomplete Cloudwatch credentials")
	}

	return &rlogcollector.EksCloudwatchLogConfig{
		AwsId:         secret.Data[rlogcollector.EksLogForwarderAwsId],
		AwsKey:        secret.Data[rlogcollector.EksLogForwarderAwsKey],
		AwsRegion:     region,
		GroupName:     group,
		StreamPrefix:  prefix,
		FetchInterval: interval,
	}, nil
}

// getUserCACertificate reads an optional user-supplied CA from the named
// ConfigMap in the operator namespace (key tls.crt), for stores whose TLS
// endpoint is not signed by a publicly trusted CA.
func getUserCACertificate(client client.Client, name string) (certificatemanagement.CertificateInterface, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      name,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if errors.IsNotFound(err) {
			log.Info(fmt.Sprintf("ConfigMap %q is not found, assuming the endpoint's certificate is signed by publicly trusted CA", name))
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read ConfigMap %q: %s", name, err)
	}
	if len(cm.Data[corev1.TLSCertKey]) == 0 {
		log.Info(fmt.Sprintf("ConfigMap %q does not have a field named %q, assuming the endpoint's certificate is signed by publicly trusted CA", name, corev1.TLSCertKey))
		return nil, nil
	}
	return certificatemanagement.NewCertificate(name, common.OperatorNamespace(), []byte(cm.Data[corev1.TLSCertKey]), nil), nil
}
