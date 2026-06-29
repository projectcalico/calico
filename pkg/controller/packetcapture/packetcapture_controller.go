// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
//
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

package packetcapture

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
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	PacketCaptureControllerName = "packet-capture-controller"
	ResourceName                = "packet-capture"
)

var log = logf.Log.WithName("controller_packet_capture")

// Add creates a new PacketCapture Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller
		return nil
	}

	tierWatchReady := &utils.ReadyFlag{}

	r := newReconciler(mgr, opts, tierWatchReady)

	c, err := ctrlruntime.NewController(PacketCaptureControllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create packetcapture-controller: %w", err)
	}

	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)

	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: render.PacketCapturePolicyName, Namespace: render.PacketCaptureNamespace},
	})

	if err = c.WatchObject(&operatorv1.PacketCaptureAPI{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("packetcapture-controller failed to watch resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, render.PacketCaptureServerCert, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("packetcapture-controller failed to watch the Secret resource: %v", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("packetcapture-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("packetcapture-controller failed to watch packetcapture TigeraStatus: %w", err)
	}

	log.V(5).Info("Controller created and Watches setup")

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcilePacketCapture{
		client:         mgr.GetClient(),
		scheme:         mgr.GetScheme(),
		status:         status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion),
		tierWatchReady: tierWatchReady,
		opts:           opts,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// blank assignment to verify that ReconcilePacketCapture implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcilePacketCapture{}

// ReconcilePacketCapture reconciles a PackerCaptureAPI object
type ReconcilePacketCapture struct {
	client         client.Client
	scheme         *runtime.Scheme
	status         status.StatusManager
	tierWatchReady *utils.ReadyFlag
	opts           options.ControllerOptions
}

// Reconcile reads that state of the cluster for a PacketCapture object and makes changes based on the state read
// and what is in the PacketCapture.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcilePacketCapture) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling PacketCapture")

	packetcaptureapi, err := utils.GetPacketCaptureAPI(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(3).Info("PacketCaptureAPI CR not found", "err", err)
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying PacketCapture", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", packetcaptureapi)

	defer r.status.SetMetaData(&packetcaptureapi.ObjectMeta)

	// Changes for updating PacketCapture status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts); err != nil {
			return reconcile.Result{}, err
		}
		packetcaptureapi.Status.Conditions = status.UpdateStatusCondition(packetcaptureapi.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, packetcaptureapi); err != nil {
			log.WithValues("reason", err).Info("Failed to create packetcapture status conditions.")
			return reconcile.Result{}, err
		}
	}

	variant, installationSpec, err := utils.GetInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !variant.IsEnterprise() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation variant to be an enterprise variant", nil, reqLogger)
		return reconcile.Result{}, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Packet capture is disabled in multi tenant management cluster
	if r.opts.MultiTenant && managementCluster != nil {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Packet capture is not supported on multi-tenant management clusters", err, reqLogger)
		return reconcile.Result{}, err
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
		}
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Error querying calico-system tier", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, packetcaptureapi)

	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.opts.ClusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}
	packetCaptureCertSecret, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		render.PacketCaptureServerCert,
		common.OperatorNamespace(),
		dns.GetServiceDNSNames(render.PacketCaptureServiceName, render.PacketCaptureNamespace, r.opts.ClusterDomain))
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieve or creating packet capture TLS certificate", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Authentication", err, reqLogger)
		return reconcile.Result{}, err
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.opts.ClusterDomain, false)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to process the authentication CR.", err, reqLogger)
		return reconcile.Result{}, err
	}

	var certificates []certificatemanagement.CertificateInterface
	if keyValidatorConfig != nil {
		dexSecret, err := certificateManager.GetCertificate(r.client, render.DexTLSSecretName, common.OperatorNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Failed to retrieve %s", render.DexTLSSecretName), err, reqLogger)
			return reconcile.Result{}, err
		}
		if dexSecret != nil {
			certificates = append(certificates, dexSecret)
		}
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	trustedBundle := certificateManager.CreateTrustedBundle(certificates...)
	packetCaptureApiCfg := &render.PacketCaptureApiConfiguration{
		PullSecrets:                 pullSecrets,
		OpenShift:                   r.opts.DetectedProvider.IsOpenShift(),
		Installation:                installationSpec,
		KeyValidatorConfig:          keyValidatorConfig,
		ServerCertSecret:            packetCaptureCertSecret,
		ClusterDomain:               r.opts.ClusterDomain,
		ManagementClusterConnection: managementClusterConnection,
		TrustedBundle:               trustedBundle,
		PacketCaptureAPI:            packetcaptureapi,
	}
	pc := render.PacketCaptureAPI(packetCaptureApiCfg)
	components := []render.Component{
		pc,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       render.PacketCaptureNamespace,
			ServiceAccounts: []string{render.PacketCaptureServiceAccountName},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(packetCaptureCertSecret, true, true),
			},
			TrustedBundle: trustedBundle,
		}),
	}

	if pcPolicy := render.PacketCaptureAPIPolicy(packetCaptureApiCfg); pcPolicy != nil {
		components = append(components, pcPolicy)
	}

	if err = imageset.ApplyImageSet(ctx, r.client, variant, components...); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	for _, component := range components {
		if err := handler.CreateOrUpdateOrDelete(context.Background(), component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Check BYO certificate expiry warnings.
	certificatemanagement.CheckKeyPairWarnings(map[string]certificatemanagement.KeyPairInterface{
		render.PacketCaptureServerCert: packetCaptureCertSecret,
	}, r.status)

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Everything is available - update the CR status.
	packetcaptureapi.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, packetcaptureapi); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
