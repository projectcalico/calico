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

package clusterconnection

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/imageoverride"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"

	"golang.org/x/net/http/httpproxy"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	controllerName = "clusterconnection-controller"
	ResourceName   = "management-cluster-connection"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new ManagementClusterConnection Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started. This controller is meant only for enterprise users.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	statusManager := status.New(mgr.GetClient(), "management-cluster-connection", opts.KubernetesVersion)

	// Create the reconciler
	tierWatchReady := &utils.ReadyFlag{}
	clusterInfoWatchReady := &utils.ReadyFlag{}
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, tierWatchReady, clusterInfoWatchReady, opts)

	// Create a new controller
	c, err := ctrlruntime.NewController(controllerName, mgr, ctrl.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	if err = opts.Extensions.ClusterConnection().Watches(c, opts.K8sClientset); err != nil {
		return fmt.Errorf("%s failed to add variant watches: %w", controllerName, err)
	}

	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)

	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: render.GuardianPolicyName, Namespace: render.GuardianNamespace},
		{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.GuardianNamespace},
	})

	// Watch for changes to ClusterInformation, as Guardian needs to restart the tunnel
	// if the cluster's version changes.
	go utils.WaitToAddClusterInformationWatch(c, opts.K8sClientset, log, clusterInfoWatchReady)

	for _, secretName := range []string{
		goldmane.GoldmaneKeyPairSecret,
		certificatemanagement.TrustedBundleName("guardian", false),
		render.CalicoAPIServerTLSSecretName,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("failed to add watch for secret %s/%s: %w", common.OperatorNamespace(), secretName, err)
		}
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	// Watch for changes to the secrets associated with the ManagementClusterConnection.
	if err = utils.AddSecretsWatch(c, render.GuardianSecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, render.GuardianSecretName, err)
	}

	if err := utils.AddDeploymentWatch(c, render.GuardianDeploymentName, render.GuardianNamespace); err != nil {
		return fmt.Errorf("%s failed to watch Guardian deployment: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("clusterconnection-controller failed to watch management-cluster-connection Tigerastatus: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	p operatorv1.Provider,
	tierWatchReady *utils.ReadyFlag,
	clusterInfoWatchReady *utils.ReadyFlag,
	opts options.ControllerOptions,
) *ReconcileConnection {
	c := &ReconcileConnection{
		cli:                   cli,
		scheme:                schema,
		provider:              p,
		status:                statusMgr,
		tierWatchReady:        tierWatchReady,
		clusterInfoWatchReady: clusterInfoWatchReady,
		opts:                  opts,
		ext:                   opts.Extensions.ClusterConnection(),
		images:                opts.Extensions.Images(),
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileConnection{}

// ReconcileConnection reconciles a ManagementClusterConnection object
type ReconcileConnection struct {
	cli                        client.Client
	scheme                     *runtime.Scheme
	provider                   operatorv1.Provider
	status                     status.StatusManager
	tierWatchReady             *utils.ReadyFlag
	clusterInfoWatchReady      *utils.ReadyFlag
	resolvedPodProxies         []*httpproxy.Config
	lastAvailabilityTransition metav1.Time
	opts                       options.ControllerOptions
	ext                        extensions.ClusterConnectionExtension
	images                     *imageoverride.Overrides
}

// Reconcile reads that state of the cluster for a ManagementClusterConnection object and makes changes based on the
// state read and what is in the ManagementClusterConnection.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *ReconcileConnection) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling the management cluster connection")
	result := reconcile.Result{}

	installationSpec, err := utils.GetComputedInstallationSpec(ctx, r.cli)
	if err != nil {
		return result, err
	}

	// Fetch the managementClusterConnection.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying ManagementClusterConnection", err, reqLogger)
		return result, err
	} else if managementClusterConnection == nil {
		r.status.OnCRNotFound()
		f, err := r.maintainFinalizer(ctx, nil)
		// If the finalizer is still set, then requeue so we aren't dependent on the periodic reconcile to check and remove the finalizer
		if f {
			return reconcile.Result{RequeueAfter: utils.FinalizerRemovalRetry}, nil
		} else {
			return reconcile.Result{}, err
		}
	}
	r.status.OnCRFound()
	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&managementClusterConnection.ObjectMeta)

	// Changes for updating ManagementClusterConnection status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.cli.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		managementClusterConnection.Status.Conditions = status.UpdateStatusCondition(managementClusterConnection.Status.Conditions, ts.Status.Conditions)
		if err := r.cli.Status().Update(ctx, managementClusterConnection); err != nil {
			log.WithValues("reason", err).Info("Failed to create ManagementClusterConnection status conditions.")
			return reconcile.Result{}, err
		}
	}

	// Validate that the cluster information watch is ready.
	if !r.clusterInfoWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for clusterInfoWatchReady watch to be established", err, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	preDefaultPatchFrom := client.MergeFrom(managementClusterConnection.DeepCopy())
	if err = r.ext.ValidateAndDefault(managementClusterConnection); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid ManagementClusterConnection configuration", err, reqLogger)
		return reconcile.Result{}, err
	}
	fillDefaults(managementClusterConnection)
	if err = r.cli.Patch(ctx, managementClusterConnection, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, err.Error(), err, reqLogger)
	}

	if _, err = r.maintainFinalizer(ctx, managementClusterConnection); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error setting finalizer on Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	log.V(2).Info("Loaded ManagementClusterConnection config", "config", managementClusterConnection)

	certificateManager, err := certificatemanager.Create(r.cli, installationSpec, r.opts.ClusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	includeSystem := managementClusterConnection.Spec.TLS.CA == operatorv1.CATypePublic
	trustedBundle, err := certificateManager.CreateNamedTrustedBundleFromSecrets(render.GuardianDeploymentName, r.cli,
		common.OperatorNamespace(), includeSystem, render.CalicoAPIServerTLSSecretName, goldmane.GoldmaneKeyPairSecret)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the trusted bundle", err, reqLogger)
	}

	// Run the variant extension: it validates the configuration (a cluster cannot be
	// both a management and a managed cluster), adds the certificates the variant needs
	// Guardian to trust, and produces the Enterprise-specific Guardian inputs the
	// controller reads back below (the managed cluster version and the license-gated
	// egress policy flag). For the core operator this is a no-op and the render inputs
	// carries no extension data, so the OSS defaults apply.
	ci := controller.Inputs{
		RenderInputs: render.Inputs{
			Installation:  installationSpec,
			ClusterDomain: r.opts.ClusterDomain,
			TrustedBundle: trustedBundle,
		},
		Client:             r.cli,
		CertificateManager: certificateManager,
	}
	ci, _, err = r.ext.ExtendInputs(ctx, ci)
	if err != nil {
		if reason, ok := extensions.DegradedReason(err); ok {
			r.status.SetDegraded(reason, err.Error(), nil, reqLogger)
			if reason == operatorv1.ResourceNotReady {
				return reconcile.Result{}, nil
			}
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error preparing the clusterconnection extension", err, reqLogger)
		return reconcile.Result{}, err
	}
	guardianData, haveGuardianData := render.GuardianRenderDataFromInputs(ci.RenderInputs)

	// In the OSS (Whisker) path Guardian connects with its own client keypair. The
	// Enterprise path uses the tunnel secret instead, so when the extension supplied
	// its Guardian inputs we skip creating this keypair.
	var guardianKeyPair certificatemanagement.KeyPairInterface
	if !haveGuardianData {
		guardianCertificateNames := dns.GetServiceDNSNames("guardian", render.GuardianNamespace, r.opts.ClusterDomain)
		guardianCertificateNames = append(guardianCertificateNames, "localhost", "127.0.0.1")
		guardianKeyPair, err = certificateManager.GetOrCreateKeyPair(r.cli, render.GuardianKeyPairSecret, whisker.WhiskerNamespace, guardianCertificateNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating guardian TLS certificate", err, log)
			return reconcile.Result{}, err
		}
		trustedBundle.AddCertificates(guardianKeyPair)
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return result, err
	}

	// Copy the secret from the operator namespace to the guardian namespace if it is present.
	tunnelSecret := &corev1.Secret{}
	err = r.cli.Get(ctx, types.NamespacedName{Name: render.GuardianSecretName, Namespace: common.OperatorNamespace()}, tunnelSecret)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving secrets from operator namespace", err, reqLogger)
		if !k8serrors.IsNotFound(err) {
			return result, nil
		}
		return result, err
	}

	// Determine the current deployment availability.
	var currentAvailabilityTransition metav1.Time
	var currentlyAvailable bool
	guardianDeployment := v1.Deployment{}
	err = r.cli.Get(ctx, client.ObjectKey{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}, &guardianDeployment)
	if err != nil && !k8serrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read the deployment status of Guardian", err, reqLogger)
		return reconcile.Result{}, nil
	} else if err == nil {
		for _, condition := range guardianDeployment.Status.Conditions {
			if condition.Type == v1.DeploymentAvailable {
				currentAvailabilityTransition = condition.LastTransitionTime
				if condition.Status == corev1.ConditionTrue {
					currentlyAvailable = true
				}
				break
			}
		}
	}

	// Resolve the proxies used by each Guardian pod. We only update the resolved proxies if the availability of the
	// Guardian deployment has changed since our last reconcile and the deployment is currently available. We restrict
	// the resolution of pod proxies in this way to limit the number of pod queries we make.
	if !currentAvailabilityTransition.Equal(&r.lastAvailabilityTransition) && currentlyAvailable {
		// Query guardian pods.
		labelSelector := labels.SelectorFromSet(map[string]string{
			"app.kubernetes.io/name": render.GuardianDeploymentName,
		})
		pods := corev1.PodList{}
		err := r.cli.List(ctx, &pods, &client.ListOptions{
			LabelSelector: labelSelector,
			Namespace:     render.GuardianNamespace,
		})
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to list the pods of the Guardian deployment", err, reqLogger)
			return reconcile.Result{}, nil
		}

		// Resolve the proxy config for each pod. Pods without a proxy will have a nil proxy config value.
		var podProxies []*httpproxy.Config
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.Name == render.GuardianContainerName {
					var podProxyConfig *httpproxy.Config
					var httpsProxy, noProxy string
					for _, env := range container.Env {
						switch env.Name {
						case "https_proxy", "HTTPS_PROXY":
							httpsProxy = env.Value
						case "no_proxy", "NO_PROXY":
							noProxy = env.Value
						}
					}
					if httpsProxy != "" || noProxy != "" {
						podProxyConfig = &httpproxy.Config{
							HTTPSProxy: httpsProxy,
							NoProxy:    noProxy,
						}
					}

					podProxies = append(podProxies, podProxyConfig)
				}
			}
		}

		r.resolvedPodProxies = podProxies
	}
	r.lastAvailabilityTransition = currentAvailabilityTransition

	var managedClusterVersion string
	clusterInformation, err := utils.FetchClusterInformation(ctx, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying clusterInformation", err, reqLogger)
		return reconcile.Result{}, err
	}
	if haveGuardianData {
		managedClusterVersion = guardianData.Version
	} else {
		managedClusterVersion = clusterInformation.Spec.CalicoVersion
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// The Enterprise extension gates the domain-based egress rules on the license; the
	// OSS default is to leave them disabled.
	includeEgressNetworkPolicy := guardianData.IncludeEgressNetworkPolicy

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	var tierAvailable bool
	if err := r.cli.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err == nil {
		tierAvailable = true
	} else if !k8serrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
		return reconcile.Result{}, err
	}

	ch := utils.NewComponentHandler(
		log,
		r.cli,
		r.scheme,
		managementClusterConnection,
		utils.WithExtension(r.ext, ci.RenderInputs),
	)
	guardianCfg := &render.GuardianConfiguration{
		URL:                         managementClusterConnection.Spec.ManagementClusterAddr,
		PodProxies:                  r.resolvedPodProxies,
		TunnelCAType:                managementClusterConnection.Spec.TLS.CA,
		PullSecrets:                 pullSecrets,
		OpenShift:                   r.provider.IsOpenShift(),
		Installation:                installationSpec,
		TunnelSecret:                tunnelSecret,
		TrustedCertBundle:           trustedBundle,
		ManagementClusterConnection: managementClusterConnection,
		GuardianClientKeyPair:       guardianKeyPair,
		Version:                     managedClusterVersion,
		IncludeEgressNetworkPolicy:  includeEgressNetworkPolicy,
		ImageOverrides:              r.images,
	}

	certComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       render.GuardianNamespace,
		TruthNamespace:  common.OperatorNamespace(),
		ServiceAccounts: []string{render.GuardianServiceName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(guardianKeyPair, true, true),
		},
		TrustedBundle: trustedBundle,
	})
	components := []render.Component{certComponent, render.Guardian(guardianCfg)}

	// v3 NetworkPolicy will fail to reconcile if the Tier is not created, which can only occur once a License is created.
	// In managed clusters, the clusterconnection controller is a dependency for the License to be created. In case the
	// License is unavailable and reconciliation of non-NetworkPolicy resources in the clusterconnection controller
	// would resolve it, we render network policies last to prevent a chicken-and-egg scenario.
	if tierAvailable {
		policyComponent, err := render.GuardianPolicy(guardianCfg)
		if err != nil {
			log.Error(err, "Failed to create NetworkPolicy component for Guardian, policy will be omitted")
		} else {
			components = append(components, policyComponent)
		}
	}

	if err = imageset.ApplyImageSet(ctx, r.cli, r.opts.Variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return result, err
		}
	}

	r.status.ClearDegraded()

	// We should create the Guardian deployment.
	return result, nil
}

// The bool return value indicates if the finalizer is Set
func (r *ReconcileConnection) maintainFinalizer(ctx context.Context, managementClusterConnection client.Object) (bool, error) {
	// These objects require graceful termination before the CNI plugin is torn down.
	guardianDeployment := v1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.GuardianDeploymentName, Namespace: render.GuardianNamespace}}
	return utils.MaintainInstallationFinalizer(ctx, r.cli, managementClusterConnection, render.GuardianFinalizer, &guardianDeployment)
}

func fillDefaults(cr *operatorv1.ManagementClusterConnection) {
	if cr.Spec.TLS == nil {
		cr.Spec.TLS = &operatorv1.ManagementClusterTLS{}
	}
	if cr.Spec.TLS.CA == "" {
		cr.Spec.TLS.CA = operatorv1.CATypeTigera
	}
}
