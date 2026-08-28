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

	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
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
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
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

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
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
		images:        opts.Extensions.Images(),
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
	images        *imageoverride.Overrides
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

	if goldmaneCR, err := utils.GetIfExists[operatorv1.Goldmane](ctx, utils.DefaultInstanceKey, r.cli); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for Goldmane CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if goldmaneCR == nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "Goldmane CR not present; Goldmane is pre requisite for Whisker", err, reqLogger)
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

	whiskerCertificateNames := dns.GetServiceDNSNames(whisker.WhiskerName, whisker.WhiskerNamespace, r.clusterDomain)
	whiskerCertificateNames = append(whiskerCertificateNames, "localhost")
	whiskerKeyPair, err := certificateManager.GetOrCreateKeyPair(r.cli, whisker.WhiskerKeyPairSecret, whisker.WhiskerNamespace, whiskerCertificateNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating whisker TLS certificate", err, reqLogger)
		return reconcile.Result{}, err
	}

	whiskerBackendCertificateNames := dns.GetServiceDNSNames("whisker-backend", whisker.WhiskerNamespace, r.clusterDomain)
	whiskerBackendCertificateNames = append(whiskerBackendCertificateNames, "localhost", "127.0.0.1")
	backendKeyPair, err := certificateManager.GetOrCreateKeyPair(r.cli, whisker.WhiskerBackendKeyPairSecret, whisker.WhiskerNamespace, whiskerBackendCertificateNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating whisker-backend TLS certificate", err, reqLogger)
		return reconcile.Result{}, err
	}

	trustedBundle, err := certificateManager.CreateNamedTrustedBundleFromSecrets(
		whisker.WhiskerDeploymentName,
		r.cli,
		common.OperatorNamespace(),
		false,
		goldmane.GoldmaneKeyPairSecret,
	)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the trusted bundle", err, reqLogger)
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

	ri := render.Inputs{
		Installation:  installationSpec,
		ClusterDomain: r.clusterDomain,
		TrustedBundle: trustedBundle,
	}
	ch := utils.NewComponentHandler(log, r.cli, r.scheme, whiskerCR, utils.WithExtension(r.ext, ri))
	cfg := &whisker.Configuration{
		PullSecrets:           pullSecrets,
		OpenShift:             r.provider.IsOpenShift(),
		Installation:          installationSpec,
		TrustedCertBundle:     trustedBundle,
		WhiskerKeyPair:        whiskerKeyPair,
		WhiskerBackendKeyPair: backendKeyPair,
		Whisker:               whiskerCR,
		ClusterDomain:         r.clusterDomain,
		ImageOverrides:        r.images,
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

	certComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       goldmane.GoldmaneNamespace,
		TruthNamespace:  common.OperatorNamespace(),
		ServiceAccounts: []string{whisker.WhiskerServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(whiskerKeyPair, true, true),
			rcertificatemanagement.NewKeyPairOption(backendKeyPair, true, true),
		},
		TrustedBundle: trustedBundle,
	})

	components := []render.Component{certComponent, whisker.Whisker(cfg)}
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
