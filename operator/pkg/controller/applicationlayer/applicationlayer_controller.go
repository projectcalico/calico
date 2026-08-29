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

package applicationlayer

import (
	"context"
	"errors"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/gatewayapi"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/controller/utils/imageset"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/enterprise/policysync"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/applicationlayer"
	"github.com/projectcalico/calico/operator/pkg/render/applicationlayer/ruleset"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
)

const ResourceName = "applicationlayer"

var log = logf.Log.WithName("controller_applicationlayer")

// Add creates a new ApplicationLayer Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		// No need to start this controller.
		return nil
	}
	licenseAPIReady := &utils.ReadyFlag{}

	reconciler := newReconciler(mgr, opts, licenseAPIReady)

	c, err := ctrlruntime.NewController("applicationlayer-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)

	return add(mgr, c)
}

// newReconciler returns a new *reconcile.Reconciler.
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, licenseAPIReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileApplicationLayer{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "applicationlayer", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		variant:         opts.Variant,
		licenseAPIReady: licenseAPIReady,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
func add(mgr manager.Manager, c ctrlruntime.Controller) error {
	var err error

	// Watch for changes to primary resource applicationlayer.
	err = c.WatchObject(&operatorv1.ApplicationLayer{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch Installation resource: %v", err)
	}

	// Watch for configmap changes in tigera-operator namespace; the cm contains config for Coraza library:
	err = utils.AddConfigMapWatch(c, applicationlayer.WAFRulesetConfigMapName, common.OperatorNamespace(), &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf(
			"applicationlayer-controller failed to watch ConfigMap %s: %v",
			applicationlayer.WAFRulesetConfigMapName, err,
		)
	}

	// Watch mutatingwebhookconfiguration responsible for sidecar injetion
	err = utils.AddClusterWatch(c, &admregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: common.SidecarMutatingWebhookConfigName}},
		&handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch sidecar MutatingWebhookConfiguration resource: %w", err)
	}

	// Watch configmaps created for envoy and dikastes in calico-system namespace:
	maps := []string{
		applicationlayer.EnvoyConfigMapName,
		applicationlayer.WAFRulesetConfigMapName,
		applicationlayer.DefaultCoreRuleset,
	}
	for _, configMapName := range maps {
		if err = utils.AddConfigMapWatch(c, configMapName, common.CalicoNamespace, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("applicationlayer-controller failed to watch ConfigMap %s: %v", configMapName, err)
		}
	}

	// Watch for changes to FelixConfiguration.
	err = c.WatchObject(&v3.FelixConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch FelixConfiguration resource: %w", err)
	}

	// Watch for changes to GatewayAPI; its WAF data-plane extension shares the
	// FelixConfiguration WAFEventLogsFileEnabled toggle, so toggling it must re-trigger this controller.
	err = c.WatchObject(&operatorv1.GatewayAPI{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch GatewayAPI resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("applicationlayer-controller failed to watch applicationlayer Tigerastatus: %w", err)
	}

	return nil
}

// Blank assignment to verify that ReconcileCompliance implements reconcile.Reconciler.
var _ reconcile.Reconciler = &ReconcileApplicationLayer{}

// ReconcileApplicationLayer reconciles a ApplicationLayer object.
type ReconcileApplicationLayer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	variant         operatorv1.ProductVariant
	licenseAPIReady *utils.ReadyFlag
}

// Reconcile reads that state of the cluster for a ApplicationLayer object and makes changes
// based on the state read and what is in the ApplicationLayer.Spec.
func (r *ReconcileApplicationLayer) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ApplicationLayer")

	instance, err := getApplicationLayer(ctx, r.client)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("ApplicationLayer object not found")
			// Patch tproxyMode if it's  needed after crd deletion.
			gatewayWAFEnabled, gwErr := r.isGatewayWAFEnabled(ctx)
			if gwErr != nil {
				reqLogger.Error(gwErr, "Error checking GatewayAPI WAF state; skipping felix configuration patch")
			} else if err = r.patchFelixConfiguration(ctx, nil, gatewayWAFEnabled); err != nil {
				reqLogger.Error(err, "Error patching felix configuration")
			}
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for Application Layer", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating application layer status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create ApplicationLayer status conditions.")
			return reconcile.Result{}, err
		}
	}

	preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())

	updateApplicationLayerWithDefaults(instance)

	if err = validateApplicationLayer(instance); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, reqLogger)
		return reconcile.Result{}, nil
	}

	// Write the application layer back to the datastore, so the controllers depending on this can reconcile.
	if err = r.client.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to write defaults to applicationLayer", err, reqLogger)
		return reconcile.Result{}, err
	}

	installationSpec, err := utils.GetComputedInstallationSpec(ctx, r.client)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Patch felix configuration if necessary.
	gatewayWAFEnabled, err := r.isGatewayWAFEnabled(ctx)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error checking GatewayAPI WAF state", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = r.patchFelixConfiguration(ctx, instance, gatewayWAFEnabled); err != nil {
		r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching felix configuration", err, reqLogger)
		return reconcile.Result{}, err
	}

	var passthroughWAFRulesetConfig bool
	var wafRulesetConfig, defaultCoreRuleSet *corev1.ConfigMap
	if r.isWAFEnabled(&instance.Spec) || r.isSidecarInjectionEnabled(&instance.Spec) {
		if defaultCoreRuleSet, err = ruleset.GetOWASPCoreRuleSet(); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Web Application Firewall OWASP core ruleset", err, reqLogger)
			return reconcile.Result{}, err
		}

		if wafRulesetConfig, passthroughWAFRulesetConfig, err = r.getWAFRulesetConfig(ctx); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting Web Application Firewall ruleset config", err, reqLogger)
			return reconcile.Result{}, err
		}
		if err = ruleset.ValidateWAFRulesetConfig(wafRulesetConfig); err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Error validating Web Application Firewall ruleset config", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	lcSpec := instance.Spec.LogCollection
	config := &applicationlayer.Config{
		PullSecrets:                 pullSecrets,
		Installation:                installationSpec,
		OsType:                      rmeta.OSTypeLinux,
		PerHostWAFEnabled:           r.isWAFEnabled(&instance.Spec),
		PerHostLogsEnabled:          r.isLogsCollectionEnabled(&instance.Spec),
		PerHostALPEnabled:           r.isALPEnabled(&instance.Spec),
		SidecarInjectionEnabled:     r.isSidecarInjectionEnabled(&instance.Spec),
		LogRequestsPerInterval:      lcSpec.LogRequestsPerInterval,
		LogIntervalSeconds:          lcSpec.LogIntervalSeconds,
		WAFRulesetConfigMap:         wafRulesetConfig,
		DefaultCoreRulesetConfigMap: defaultCoreRuleSet,
		UseRemoteAddressXFF:         instance.Spec.EnvoySettings.UseRemoteAddress,
		NumTrustedHopsXFF:           instance.Spec.EnvoySettings.XFFNumTrustedHops,
		ApplicationLayer:            instance,
	}
	component := applicationlayer.ApplicationLayer(config)

	ch := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	if err = imageset.ApplyImageSet(ctx, r.client, r.variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if passthroughWAFRulesetConfig {
		err = ch.CreateOrUpdateOrDelete(ctx, render.NewCreationPassthrough(wafRulesetConfig), r.status)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// TODO: when there are more ApplicationLayer options then it will need to be restructured, as each of the
	// different features will not have their own CreateOrUpdateOrDelete
	if err = ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future, hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	err = r.client.Get(ctx, types.NamespacedName{Name: common.SidecarMutatingWebhookConfigName}, &admregv1.MutatingWebhookConfiguration{})
	if err != nil {
		sidecarWebhookDisabled := operatorv1.SidecarWebhookStateDisabled
		instance.Status.SidecarWebhook = &sidecarWebhookDisabled
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
	} else {
		sidecarWebhookEnabled := operatorv1.SidecarWebhookStateEnabled
		instance.Status.SidecarWebhook = &sidecarWebhookEnabled
	}

	// Everything is available - update the CRD status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// updateApplicationLayerWithDefaults populates the applicationlayer with defaults.
func updateApplicationLayerWithDefaults(al *operatorv1.ApplicationLayer) {
	var (
		defaultLogIntervalSeconds               int64 = 5
		defaultLogRequestsPerInterval           int64 = -1
		defaultLogCollectionStatusType                = operatorv1.L7LogCollectionDisabled
		defaultWebApplicationFirewallStatusType       = operatorv1.WAFDisabled
		defaultApplicationLayerPolicyStatusType       = operatorv1.ApplicationLayerPolicyDisabled
		defaultSidecarStatusType                      = operatorv1.SidecarDisabled
		defaultSidecarWebhookStateType                = operatorv1.SidecarWebhookStateDisabled
	)

	if al.Spec.LogCollection == nil {
		al.Spec.LogCollection = new(operatorv1.LogCollectionSpec)
	}

	if al.Spec.LogCollection.CollectLogs == nil {
		al.Spec.LogCollection.CollectLogs = &defaultLogCollectionStatusType
	}

	if *al.Spec.LogCollection.CollectLogs == operatorv1.L7LogCollectionEnabled {
		if al.Spec.LogCollection.LogRequestsPerInterval == nil {
			al.Spec.LogCollection.LogRequestsPerInterval = &defaultLogRequestsPerInterval
		}
		if al.Spec.LogCollection.LogIntervalSeconds == nil {
			al.Spec.LogCollection.LogIntervalSeconds = &defaultLogIntervalSeconds
		}
	}

	if al.Spec.WebApplicationFirewall == nil {
		al.Spec.WebApplicationFirewall = &defaultWebApplicationFirewallStatusType
	}

	if al.Spec.ApplicationLayerPolicy == nil {
		al.Spec.ApplicationLayerPolicy = &defaultApplicationLayerPolicyStatusType
	}

	if al.Spec.EnvoySettings == nil {
		al.Spec.EnvoySettings = &operatorv1.EnvoySettings{
			UseRemoteAddress:  false,
			XFFNumTrustedHops: 0,
		}
	}

	if al.Spec.SidecarInjection == nil {
		al.Spec.SidecarInjection = &defaultSidecarStatusType
	}

	if al.Status.SidecarWebhook == nil {
		al.Status.SidecarWebhook = &defaultSidecarWebhookStateType
	}
}

// validateApplicationLayer validates ApplicationLayer
func validateApplicationLayer(al *operatorv1.ApplicationLayer) error {
	var atLeastOneFeatureDetected bool

	if *al.Spec.LogCollection.CollectLogs == operatorv1.L7LogCollectionEnabled {
		log.Info("L7 Log Collection found enabled.")
		atLeastOneFeatureDetected = true
	}

	if *al.Spec.WebApplicationFirewall == operatorv1.WAFEnabled {
		log.Info("L7 WAF found enabled.")
		atLeastOneFeatureDetected = true
	}

	if *al.Spec.ApplicationLayerPolicy == operatorv1.ApplicationLayerPolicyEnabled {
		log.Info("L7 ALP found enabled")
		atLeastOneFeatureDetected = true
	}

	if *al.Spec.SidecarInjection == operatorv1.SidecarEnabled {
		log.Info("L7 SidecarInjection found enabled")
		atLeastOneFeatureDetected = true
	}
	// If ApplicationLayer spec exists then one of its features should be set.
	if !atLeastOneFeatureDetected {
		return errors.New("at least one of webApplicationFirewall, policy.Mode, logCollection.collectLogs or sidecarInjection must be specified in ApplicationLayer resource")
	}

	return nil
}

// getWAFRulesetConfig returns 'tigera-coreruleset-config' ConfigMap from calico-operator namespace.
// The ConfigMap is meant to contain the configuration for the Coraza library.
// If the ConfigMap does not exist a ConfigMap with the Tigera ruleset config will be returned.
func (r *ReconcileApplicationLayer) getWAFRulesetConfig(ctx context.Context) (*corev1.ConfigMap, bool, error) {
	cm := new(corev1.ConfigMap)

	if err := r.client.Get(
		ctx,
		types.NamespacedName{
			Namespace: common.OperatorNamespace(),
			Name:      applicationlayer.WAFRulesetConfigMapName,
		},
		cm,
	); err == nil {
		return cm, false, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
	}

	cm, err := ruleset.GetWAFRulesetConfig()
	if err != nil {
		return nil, false, err
	}
	return cm, true, nil
}

// getApplicationLayer returns the default ApplicationLayer instance.
func getApplicationLayer(ctx context.Context, cli client.Client) (*operatorv1.ApplicationLayer, error) {
	instance := &operatorv1.ApplicationLayer{}
	err := cli.Get(ctx, utils.DefaultEnterpriseInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (r *ReconcileApplicationLayer) isLogsCollectionEnabled(applicationLayerSpec *operatorv1.ApplicationLayerSpec) bool {
	l7Spec := applicationLayerSpec.LogCollection
	return l7Spec != nil && l7Spec.CollectLogs != nil && *l7Spec.CollectLogs == operatorv1.L7LogCollectionEnabled
}

func (r *ReconcileApplicationLayer) isALPEnabled(applicationLayerSpec *operatorv1.ApplicationLayerSpec) bool {
	return applicationLayerSpec.ApplicationLayerPolicy != nil &&
		*applicationLayerSpec.ApplicationLayerPolicy == operatorv1.ApplicationLayerPolicyEnabled
}

func (r *ReconcileApplicationLayer) isWAFEnabled(applicationLayerSpec *operatorv1.ApplicationLayerSpec) bool {
	return applicationLayerSpec.WebApplicationFirewall != nil &&
		*applicationLayerSpec.WebApplicationFirewall == operatorv1.WAFEnabled
}

func (r *ReconcileApplicationLayer) isSidecarInjectionEnabled(applicationLayerSpec *operatorv1.ApplicationLayerSpec) bool {
	return applicationLayerSpec.SidecarInjection != nil &&
		*applicationLayerSpec.SidecarInjection == operatorv1.SidecarEnabled
}

func (r *ReconcileApplicationLayer) getPolicySyncPathPrefix(fcSpec *v3.FelixConfigurationSpec, al *operatorv1.ApplicationLayer, istioNeeds bool) string {
	alNeeds := policysync.ApplicationLayerRequires(al)
	return utils.DesiredPolicySyncPathPrefix(fcSpec.PolicySyncPathPrefix, alNeeds, istioNeeds)
}

func (r *ReconcileApplicationLayer) getTProxyMode(al *operatorv1.ApplicationLayer) (bool, string) {
	if al == nil {
		return false, "Disabled"
	}

	spec := &al.Spec
	if r.isALPEnabled(spec) ||
		r.isWAFEnabled(spec) ||
		r.isLogsCollectionEnabled(spec) {
		return true, "Enabled"
	}

	// alp config is not nil, but neither of the features are enabled
	return true, "Disabled"
}

// patchFelixConfiguration takes all application layer specs as arguments and patches felix config.
// If at least one of the specs requires TPROXYMode as "Enabled" it'll be patched as "Enabled" otherwise it is "Disabled".
// gatewayWAFEnabled reflects the GatewayAPI WAF data-plane extension (design-25): its audit events flow through
// Felix's WAF event log, so it shares the WAFEventLogsFileEnabled toggle with the ApplicationLayer WAF.
func (r *ReconcileApplicationLayer) patchFelixConfiguration(ctx context.Context, al *operatorv1.ApplicationLayer, gatewayWAFEnabled bool) error {
	// Fetch the Istio CR and Installation variant so DesiredPolicySyncPathPrefix
	// can see whether the istio side still needs the field. Both reads tolerate
	// NotFound — the istio side has no claim if either is absent.
	istioCR, err := utils.GetIstio(ctx, r.client)
	if err != nil {
		return err
	}
	istioNeeds := utils.IstioRequiresPolicySync(istioCR, r.variant)

	_, err = utils.PatchFelixConfiguration(ctx, r.client, func(fc *v3.FelixConfiguration) (bool, error) {
		wafEventLogsFileEnabled := wafEventLogsFileRequired(al, gatewayWAFEnabled)

		var tproxyMode string
		if ok, v := r.getTProxyMode(al); ok {
			tproxyMode = v
		} else {
			if fc.Spec.TPROXYMode == "" {
				// Workaround: we'd like to always force the value to be the correct one, matching the operator's
				// configuration.  However, during an upgrade from a version that predates the TPROXYMode option,
				// Felix hits a bug and gets confused by the new config parameter, which in turn triggers a restart.
				// Work around that by relying on Disabled being the default value for the field instead.
				//
				// The felix bug was fixed in v3.16, v3.15.1 and v3.14.4; it should be safe to set new config fields
				// once we know we're only upgrading from those versions and above.
				//
				// WAFEventLogsFileEnabled is an independent field: still enable it when a WAF producer
				// (ApplicationLayer or the gateway data plane) requires it, without touching TPROXYMode.
				if wafEventLogsFileEnabled && (fc.Spec.WAFEventLogsFileEnabled == nil || !*fc.Spec.WAFEventLogsFileEnabled) {
					fc.Spec.WAFEventLogsFileEnabled = &wafEventLogsFileEnabled
					log.Info("Patching FelixConfiguration: ", "wafEventLogsFileEnabled", wafEventLogsFileEnabled)
					return true, nil
				}
				return false, nil
			}

			// If the mode is already set, fall through to the normal logic, it's safe to force-set the field now.
			// This also avoids churning the config if a previous version of the operator set it to Disabled already,
			// we avoid setting it back to nil.
			tproxyMode = "Disabled"
		}

		policySyncPrefix := r.getPolicySyncPathPrefix(&fc.Spec, al, istioNeeds)
		policySyncPrefixSetDesired := fc.Spec.PolicySyncPathPrefix == policySyncPrefix
		tproxyModeSetDesired := fc.Spec.TPROXYMode != "" && fc.Spec.TPROXYMode == string(tproxyMode)
		wafEventLogsFileEnabledDesired := fc.Spec.WAFEventLogsFileEnabled != nil && *fc.Spec.WAFEventLogsFileEnabled == wafEventLogsFileEnabled

		// If tproxy mode is already set to desired state return false to indicate patch not needed.
		if policySyncPrefixSetDesired && tproxyModeSetDesired && wafEventLogsFileEnabledDesired {
			return false, nil
		}

		fc.Spec.TPROXYMode = string(tproxyMode)
		fc.Spec.PolicySyncPathPrefix = policySyncPrefix
		fc.Spec.WAFEventLogsFileEnabled = &wafEventLogsFileEnabled

		log.Info(
			"Patching FelixConfiguration: ",
			"policySyncPathPrefix", fc.Spec.PolicySyncPathPrefix,
			"tproxyMode", string(tproxyMode),
			"wafEventLogsFileEnabled", wafEventLogsFileEnabled,
		)
		return true, nil
	})

	return err
}

// wafEventLogsFileRequired reports whether Felix should write WAF event logs to file, which is required
// when either the ApplicationLayer WAF/sidecar or the GatewayAPI WAF data-plane extension is enabled.
func wafEventLogsFileRequired(al *operatorv1.ApplicationLayer, gatewayWAFEnabled bool) bool {
	return gatewayWAFEnabled ||
		(al != nil && ((al.Spec.SidecarInjection != nil && *al.Spec.SidecarInjection == operatorv1.SidecarEnabled) ||
			(al.Spec.WebApplicationFirewall != nil && *al.Spec.WebApplicationFirewall == operatorv1.WAFEnabled)))
}

// isGatewayWAFEnabled reports whether the GatewayAPI WAF data-plane extension is enabled. A missing
// GatewayAPI CR is treated as disabled (no error); any other read error is returned so the caller can
// requeue rather than spuriously treating WAF as disabled and flapping FelixConfiguration.
func (r *ReconcileApplicationLayer) isGatewayWAFEnabled(ctx context.Context) (bool, error) {
	gw, msg, err := gatewayapi.GetGatewayAPI(ctx, r.client)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", msg, err)
	}
	return gw.Spec.IsWAFGatewayExtensionEnabled(), nil
}
