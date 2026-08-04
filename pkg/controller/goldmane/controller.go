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

package goldmane

import (
	"context"
	"fmt"

	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/render/whisker"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	controllerName = "goldmane-controller"
	ResourceName   = "goldmane"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new Reconciler Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	statusManager := status.New(mgr.GetClient(), "goldmane", opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, opts)

	// Create a new controller
	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	if err = c.WatchObject(&operatorv1.Goldmane{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch primary resource: %w", controllerName, err)
	}

	for _, secretName := range []string{
		goldmane.GoldmaneKeyPairSecret,
		certificatemanagement.CASecretName,
		whisker.WhiskerBackendKeyPairSecret,
		render.VoltronLinseedPublicCert,
		render.LegacyVoltronLinseedPublicCert,
	} {
		if err = utils.AddSecretsWatch(c, secretName, common.OperatorNamespace()); err != nil {
			return fmt.Errorf("failed to add watch for secret %s/%s: %w", common.OperatorNamespace(), secretName, err)
		}
	}

	if err = utils.AddConfigMapWatch(c, certificatemanagement.TrustedBundleName("goldmane", false), common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("failed to add watch for config map %s/%s: %w", common.OperatorNamespace(), certificatemanagement.TrustedCertConfigMapName, err)
	}

	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch management cluster connection resource: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	if err := utils.AddDeploymentWatch(c, whisker.WhiskerDeploymentName, whisker.WhiskerNamespace); err != nil {
		return fmt.Errorf("%s failed to watch Whisker deployment: %w", controllerName, err)
	}

	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("goldmane-controller failed to watch Tigerastatus: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("goldmane-controller failed to create periodic reconcile watch: %w", err)
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
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &Reconciler{}

// Reconciler reconciles a Goldmane object
type Reconciler struct {
	cli           client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
	variant       operatorv1.ProductVariant
}

// Reconcile reads that state of the cluster for a Goldmane object and makes changes based on the
// state read and what is in the Goldmane.Spec. The Controller will requeue the Request to be
// processed again if the returned error is non-nil or Result.Requeue is true, otherwise upon completion it will
// remove the work from the queue.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling Goldmane")

	goldmaneCR, err := utils.GetIfExists[operatorv1.Goldmane](ctx, utils.DefaultInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Goldmane CR", err, reqLogger)
		return reconcile.Result{}, err
	} else if goldmaneCR == nil {
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
	defer r.status.SetMetaData(&goldmaneCR.ObjectMeta)

	installationSpec, err := utils.GetInstallationSpec(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		return reconcile.Result{}, nil
	}

	mgmtClusterConnectionCR, err := utils.GetIfExists[operatorv1.ManagementClusterConnection](ctx, utils.DefaultEnterpriseInstanceKey, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying ManagementClusterConnection CR", err, reqLogger)
		return reconcile.Result{}, err
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

	goldmaneCertificateNames := dns.GetServiceDNSNames(goldmane.GoldmaneServiceName, goldmane.GoldmaneNamespace, r.clusterDomain)
	keyPair, err := certificateManager.GetOrCreateKeyPair(r.cli, goldmane.GoldmaneKeyPairSecret, common.OperatorNamespace(), goldmaneCertificateNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return reconcile.Result{}, err
	}

	nodeCA, err := certificateManager.GetCertificate(r.cli, render.NodeTLSSecretName, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, log)
		return reconcile.Result{}, err
	}

	trustedBundle, err := certificateManager.CreateNamedTrustedBundleFromSecrets(goldmane.GoldmaneDeploymentName, r.cli,
		common.OperatorNamespace(), false,
		whisker.WhiskerBackendKeyPairSecret)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the trusted bundle", err, reqLogger)
		return reconcile.Result{}, err
	}
	trustedBundle.AddCertificates(keyPair, nodeCA)

	// When connected to a management cluster, Goldmane's flow emitter must trust the management cluster's
	// Linseed signer. Its secret is named calico-voltron-linseed-certs-public (current) or
	// tigera-voltron-linseed-certs-public (legacy) depending on the management cluster's operator version, so
	// trust whichever is present and degrade if neither is - without it flow uploads fail TLS verification.
	if mgmtClusterConnectionCR != nil {
		var linseedCerts []certificatemanagement.CertificateInterface
		for _, secretName := range []string{render.VoltronLinseedPublicCert, render.LegacyVoltronLinseedPublicCert} {
			cert, err := certificateManager.GetCertificate(r.cli, secretName, common.OperatorNamespace())
			if err != nil {
				r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve %s", secretName), err, reqLogger)
				return reconcile.Result{}, err
			}
			if cert != nil {
				linseedCerts = append(linseedCerts, cert)
			}
		}
		if len(linseedCerts) == 0 {
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for the Linseed public certificate (%s or %s) required to verify flow uploads to the management cluster", render.VoltronLinseedPublicCert, render.LegacyVoltronLinseedPublicCert), nil, reqLogger)
			return reconcile.Result{}, nil
		}
		trustedBundle.AddCertificates(linseedCerts...)
	}

	certComponent := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       goldmane.GoldmaneNamespace,
		TruthNamespace:  common.OperatorNamespace(),
		ServiceAccounts: []string{whisker.WhiskerServiceAccountName},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			rcertificatemanagement.NewKeyPairOption(keyPair, true, true),
		},
		TrustedBundle: trustedBundle,
	})

	if _, err := r.maintainFinalizer(ctx, goldmaneCR); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error setting finalizer on Installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	ch := utils.NewComponentHandler(log, r.cli, r.scheme, goldmaneCR)
	cfg := &goldmane.Configuration{
		PullSecrets:                 pullSecrets,
		OpenShift:                   r.provider.IsOpenShift(),
		Installation:                installationSpec,
		TrustedCertBundle:           trustedBundle,
		GoldmaneServerKeyPair:       keyPair,
		ManagementClusterConnection: mgmtClusterConnectionCR,
		ClusterDomain:               r.clusterDomain,
		Goldmane:                    goldmaneCR,
	}

	components := []render.Component{certComponent, goldmane.Goldmane(cfg)}
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

func (r *Reconciler) maintainFinalizer(ctx context.Context, goldmaneCr client.Object) (bool, error) {
	// These objects require graceful termination before the CNI plugin is torn down.
	goldmaneDeployment := &v1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: common.CalicoNamespace, Name: goldmane.GoldmaneDeploymentName}}
	return utils.MaintainInstallationFinalizer(ctx, r.cli, goldmaneCr, render.GoldmaneFinalizer, goldmaneDeployment)
}
