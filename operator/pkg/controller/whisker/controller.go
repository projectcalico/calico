// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package whisker

import (
	"context"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/controller/utils/imageset"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcertificatemanagement "github.com/projectcalico/calico/operator/pkg/render/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/render/goldmane"
	"github.com/projectcalico/calico/operator/pkg/render/whisker"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/uigateway"
)

const (
	controllerName = "whisker-controller"
	ResourceName   = "whisker"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new Reconciler Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	statusManager := status.New(mgr.GetClient(), "whisker", opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, opts)

	c, err := ctrlruntime.NewController(controllerName, mgr, ctrl.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	if err = c.WatchObject(&operatorv1.Whisker{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	if err = c.WatchObject(&operatorv1.Goldmane{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch for goldmane resource: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	for _, secretName := range []string{
		certificatemanagement.CASecretName,
		whisker.WhiskerKeyPairSecret,
		goldmane.GoldmaneKeyPairSecret,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("failed to add watch for secret %s/%s: %w", common.OperatorNamespace(), secretName, err)
		}
	}

	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedBundleName("whisker", false), common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("failed to add watch for config map %s/%s: %w", common.OperatorNamespace(), certificatemanagement.TrustedCertConfigMapName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err := utils.AddDeploymentWatch(c, whisker.WhiskerDeploymentName, whisker.WhiskerNamespace); err != nil {
		return fmt.Errorf("%s failed to watch Whisker deployment: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("whisker-controller failed to watch Tigerastatus: %w", err)
	}

	if err = c.WatchObject(&v3.ClusterInformation{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("whisker-controller failed to watch ClusterInformation")
	}

	if err = c.WatchObject(&operatorv1.GatewayAPI{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch GatewayAPI resource: %w", controllerName, err)
	}

	if err = uigateway.AddWatches(c, opts.K8sClientset, log, whisker.GatewayResourcePrefix, whisker.GatewayTLSSecretName); err != nil {
		return fmt.Errorf("%s failed to add gateway watches: %w", controllerName, err)
	}

	if err = reconciler.ext.Watches(c); err != nil {
		return fmt.Errorf("%s failed to set up extension watches: %w", controllerName, err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("whisker-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	p operatorv1.Provider,
	opts options.ControllerOptions,
) *Reconciler {
	c := &Reconciler{
		cli:           cli,
		scheme:        schema,
		provider:      p,
		status:        statusMgr,
		clusterDomain: opts.ClusterDomain,
		variant:       opts.Variant,
		ext:           opts.Extensions.Whisker(),
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	cli           client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
	variant       operatorv1.ProductVariant
	ext           extensions.WhiskerExtension
}

// Reconcile reads that state of the cluster for a Whisker object and makes changes based on the
// state read and what is in the Whisker.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling Whisker")

	whiskerCR, err := utils.GetIfExists[operatorv1.Whisker](ctx, utils.DefaultInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Whisker CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if whiskerCR == nil {
		r.status.OnCRNotFound()

		// Gateway objects are garbage-collected with the CR, but a namespace the
		// operator created for them has no owner reference and must be torn down here.
		gwHelper := uigateway.NewHelper(r.cli, uigateway.Config{
			ResourcePrefix:   whisker.GatewayResourcePrefix,
			TLSSecretName:    whisker.GatewayTLSSecretName,
			BackendNamespace: whisker.WhiskerNamespace,
		})
		gwComponents, err := gwHelper.Teardown(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to list gateways for cleanup", err, reqLogger)
			return reconcile.Result{}, err
		}
		ch := utils.NewComponentHandler(log, r.cli, r.scheme, nil)
		for _, component := range gwComponents {
			if err := ch.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
				r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error tearing down gateway resources", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

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
	defer r.status.SetMetaData(&whiskerCR.ObjectMeta)

	installationSpec, err := utils.GetComputedInstallationSpec(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.cli, installationSpec, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the certificate manager", err, reqLogger)
		return reconcile.Result{}, err
	}

	trustedBundle, err := certificateManager.CreateNamedTrustedBundleFromSecrets(whisker.WhiskerDeploymentName, r.cli, common.OperatorNamespace(), false)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the trusted bundle", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Run the variant extension. A variant that deploys whisker-backend alone
	// reports it here, trusting the certificates of the flow source its modifier
	// wires in. For the core operator this is a no-op.
	ci := controller.Inputs{
		RenderInputs: render.Inputs{
			Installation:  installationSpec,
			ClusterDomain: r.clusterDomain,
			TrustedBundle: trustedBundle,
		},
		Client:             r.cli,
		CertificateManager: certificateManager,
	}
	ci, extraKeyPairs, err := r.ext.ExtendInputs(ctx, ci)
	if err != nil {
		if reason, ok := extensions.DegradedReason(err); ok {
			r.status.SetDegraded(reason, err.Error(), nil, reqLogger)
			if reason == operatorv1.ResourceNotReady {
				// The controller watches what the extension is waiting on, so let the
				// watch trigger the next reconcile.
				return reconcile.Result{}, nil
			}
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error preparing the whisker extension", err, reqLogger)
		return reconcile.Result{}, err
	}
	trustedBundle = ci.RenderInputs.TrustedBundle
	data, _ := whisker.RenderDataFromInputs(ci.RenderInputs)

	// Whisker reads flows from Goldmane, and serves its UI over a key pair of its
	// own, unless the variant deploys the backend alone or nothing at all. A
	// disabled whisker still runs the rest of the reconcile: that is what removes
	// whatever an earlier configuration deployed.
	var whiskerKeyPair certificatemanagement.KeyPairInterface
	if !data.BackendOnly && !data.Disabled {
		if goldmaneCR, err := utils.GetIfExists[operatorv1.Goldmane](ctx, utils.DefaultInstanceKey, r.cli); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for Goldmane CR", err, reqLogger)
			return reconcile.Result{}, err
		} else if goldmaneCR == nil {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Goldmane CR not present; Goldmane is pre requisite for Whisker", err, reqLogger)
			return reconcile.Result{}, nil
		}

		goldmaneCertificate, err := certificateManager.GetCertificate(r.cli, goldmane.GoldmaneKeyPairSecret, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve %s", goldmane.GoldmaneKeyPairSecret), err, reqLogger)
			return reconcile.Result{}, err
		}
		trustedBundle.AddCertificates(goldmaneCertificate)

		whiskerCertificateNames := dns.GetServiceDNSNames(whisker.WhiskerName, whisker.WhiskerNamespace, r.clusterDomain)
		whiskerCertificateNames = append(whiskerCertificateNames, "localhost")
		whiskerKeyPair, err = certificateManager.GetOrCreateKeyPair(r.cli, whisker.WhiskerKeyPairSecret, whisker.WhiskerNamespace, whiskerCertificateNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating whisker TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	var backendKeyPair certificatemanagement.KeyPairInterface
	if !data.Disabled {
		whiskerBackendCertificateNames := dns.GetServiceDNSNames("whisker-backend", whisker.WhiskerNamespace, r.clusterDomain)
		whiskerBackendCertificateNames = append(whiskerBackendCertificateNames, "localhost", "127.0.0.1")
		backendKeyPair, err = certificateManager.GetOrCreateKeyPair(r.cli, whisker.WhiskerBackendKeyPairSecret, whisker.WhiskerNamespace, whiskerBackendCertificateNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating whisker-backend TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Key pairs an earlier configuration issued and this one does not use. The
	// component removes its own objects; the key pairs are the controller's,
	// because only it can tell an issued pair from one the user provided.
	var stale []client.Object
	if data.BackendOnly || data.Disabled {
		objs, err := staleKeyPair(r.cli, certificateManager, whisker.WhiskerKeyPairSecret)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading the whisker key pair", err, reqLogger)
			return reconcile.Result{}, err
		}
		stale = append(stale, objs...)
	}
	if data.Disabled {
		objs, err := staleKeyPair(r.cli, certificateManager, whisker.WhiskerBackendKeyPairSecret)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading the whisker-backend key pair", err, reqLogger)
			return reconcile.Result{}, err
		}
		stale = append(stale, objs...)
		stale = append(stale, trustedBundle.ConfigMap(whisker.WhiskerNamespace))
	}

	preDefaultPatchFrom := client.MergeFrom(whiskerCR.DeepCopy())

	// update Installation with defaults
	updateWhiskerWithDefaults(whiskerCR)

	// Write the whisker CR configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	if err := r.cli.Patch(ctx, whiskerCR, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	if _, err := r.maintainFinalizer(ctx, whiskerCR); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error setting finalizer on Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Render from a copy, so a variant that does not support a field can unset it
	// while the CR on the API keeps what the user asked for.
	renderCR := whiskerCR.DeepCopy()
	if err := r.ext.ValidateAndDefault(renderCR, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Invalid Whisker configuration", err, reqLogger)
		return reconcile.Result{}, err
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, whiskerCR, utils.WithExtension(r.ext, ci.RenderInputs))
	cfg := &whisker.Configuration{
		PullSecrets:           pullSecrets,
		OpenShift:             r.provider.IsOpenShift(),
		Installation:          installationSpec,
		TrustedCertBundle:     trustedBundle,
		WhiskerKeyPair:        whiskerKeyPair,
		WhiskerBackendKeyPair: backendKeyPair,
		Whisker:               renderCR,
		ClusterDomain:         r.clusterDomain,
		BackendOnly:           data.BackendOnly,
		Disabled:              data.Disabled,
		KeyValidatorConfig:    data.KeyValidatorConfig,
	}

	clusterInfo := &v3.ClusterInformation{}
	err = r.cli.Get(ctx, utils.DefaultInstanceKey, clusterInfo)
	if err != nil {
		reqLogger.Info("Unable to retrieve ClusterInformation", "error", err)
	} else {
		cfg.CalicoVersion = clusterInfo.Spec.CalicoVersion
		cfg.ClusterType = clusterInfo.Spec.ClusterType
		cfg.ClusterID = clusterInfo.Spec.ClusterGUID
	}

	gwHelper := uigateway.NewHelper(r.cli, uigateway.Config{
		ResourcePrefix:               whisker.GatewayResourcePrefix,
		TLSSecretName:                whisker.GatewayTLSSecretName,
		BackendNamespace:             whisker.WhiskerNamespace,
		BackendServiceName:           whisker.WhiskerName,
		BackendPort:                  int32(whisker.WhiskerServicePort),
		BackendCABundleConfigMapName: certificatemanagement.TrustedCertConfigMapName,
		// Whisker streams flow logs as server-sent events; Envoy Gateway's
		// default 15s route timeout would drop the stream.
		RouteRequestTimeout: ptr.To("0s"),
		Provider:            r.provider,
		Azure:               installationSpec.Azure,
	})
	var gatewayComponents []render.Component
	var gatewayTLSKeyPair certificatemanagement.KeyPairInterface
	gatewayEnabled := renderCR.Spec.IngressGateway != nil
	if gw := renderCR.Spec.IngressGateway; gatewayEnabled {
		var err error
		gatewayTLSKeyPair, err = certificateManager.GetOrCreateKeyPair(r.cli, whisker.GatewayTLSSecretName, common.OperatorNamespace(), []string{gw.Hostname})
		if err != nil {
			r.status.SetDegraded(operatorv1.CertificateError, "Error getting or creating gateway TLS certificate", err, reqLogger)
			return reconcile.Result{}, err
		}

		gatewayComponents, err = gwHelper.Components(ctx, gw, gatewayTLSKeyPair)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to render gateway resources", err, reqLogger)
			return reconcile.Result{}, err
		}
		// Whisker's NetworkPolicy admits the gateway's Envoy proxy from this namespace.
		cfg.IngressGatewayNamespace = gw.NamespaceOrDefault()
	} else {
		var err error
		gatewayComponents, err = gwHelper.Teardown(ctx)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to list gateways for cleanup", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	var components []render.Component
	if !data.Disabled {
		keyPairOptions := []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(backendKeyPair, true, true),
		}
		if whiskerKeyPair != nil {
			keyPairOptions = append(keyPairOptions, rcertificatemanagement.NewKeyPairOption(whiskerKeyPair, true, true))
		}
		for _, kp := range extraKeyPairs {
			keyPairOptions = append(keyPairOptions, rcertificatemanagement.NewKeyPairOption(kp, true, true))
		}
		if gatewayTLSKeyPair != nil {
			keyPairOptions = append(keyPairOptions, rcertificatemanagement.NewKeyPairOption(gatewayTLSKeyPair, true, false))
		}

		components = append(components, rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       goldmane.GoldmaneNamespace,
			TruthNamespace:  common.OperatorNamespace(),
			ServiceAccounts: []string{whisker.WhiskerServiceAccountName},
			KeyPairOptions:  keyPairOptions,
			TrustedBundle:   trustedBundle,
		}))
	}
	components = append(components, whisker.Whisker(cfg))
	if len(stale) > 0 {
		components = append(components, render.NewDeletionPassthrough(stale...))
	}
	components = append(components, gatewayComponents...)
	if err = imageset.ApplyImageSet(ctx, r.cli, r.variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if gatewayEnabled {
		if msg := gwHelper.UnhealthyReason(ctx, renderCR.Spec.IngressGateway.NamespaceOrDefault()); msg != "" {
			r.status.SetDegraded(operatorv1.ResourceNotReady, msg, nil, reqLogger)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	return reconcile.Result{}, nil
}

func updateWhiskerWithDefaults(instance *operatorv1.Whisker) {
	if instance.Spec.Notifications == nil {
		instance.Spec.Notifications = ptr.To(operatorv1.Enabled)
	}
}

// The bool return value indicates if the finalizer is Set
func (r *Reconciler) maintainFinalizer(ctx context.Context, whiskerCr client.Object) (bool, error) {
	// These objects require graceful termination before the CNI plugin is torn down.
	whiskerDeployment := &v1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: common.CalicoNamespace, Name: whisker.WhiskerDeploymentName}}
	return utils.MaintainInstallationFinalizer(ctx, r.cli, whiskerCr, render.WhiskerFinalizer, whiskerDeployment)
}

// staleKeyPair names what an issued key pair leaves behind once whisker stops
// using it: its copy in whisker's namespace, and the truth-namespace secret when
// the operator issued it. A secret the user provided is theirs and stays.
func staleKeyPair(cli client.Client, cm certificatemanager.CertificateManager, name string) ([]client.Object, error) {
	objs := []client.Object{&corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: whisker.WhiskerNamespace},
	}}
	kp, err := cm.GetKeyPair(cli, name, common.OperatorNamespace(), nil)
	if err != nil {
		return nil, err
	}
	if kp != nil && !kp.BYO() && !kp.UseCertificateManagement() {
		objs = append(objs, kp.Secret(common.OperatorNamespace()))
	}
	return objs, nil
}
