// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/active"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/k8sapi"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/controller/utils/imageset"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
)

var logw = logf.Log.WithName("controller_windows")

// Add creates a new Tiers Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func AddWindowsController(mgr manager.Manager, opts options.ControllerOptions) error {
	ri, err := newWindowsReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create Windows Reconciler: %w", err)
	}

	c, err := ctrlruntime.NewController("tigera-windows-controller", mgr, ctrl.Options{Reconciler: ri})
	if err != nil {
		return fmt.Errorf("failed to create tigera-windows-controller: %w", err)
	}

	// Watch for changes to primary resource Installation
	err = c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, InstallationName); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch calico Tigerastatus: %w", err)
	}

	if ri.opts.DetectedProvider.IsOpenShift() {
		// Watch for openshift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.WatchObject(&configv1.Network{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("tigera-windows-controller failed to watch openshift network config: %w", err)
			}
		}
	}

	// Watch for secrets in the operator namespace. We watch for all secrets, since we care
	// about specifically named ones - e.g., manager-tls, as well as image pull secrets that
	// may have been provided by the user with arbitrary names.
	err = utils.AddSecretsWatch(c, "", common.OperatorNamespace())
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch secrets: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, active.ActiveConfigMapName, common.CalicoNamespace, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch ConfigMap %s: %w", active.ActiveConfigMapName, err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch ImageSet: %w", err)
	}

	// Watch kube DNS service.
	dnsService := utils.GetDNSServiceName(opts.DetectedProvider)
	if err = utils.AddServiceWatch(c, dnsService.Name, dnsService.Namespace); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch Service: %w", err)
	}

	for _, t := range secondaryResources() {
		pred := predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				// Create occurs because we've created it, so we can safely ignore it.
				return false
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				if utils.IgnoreObject(e.ObjectOld) && !utils.IgnoreObject(e.ObjectNew) {
					// Don't skip the removal of the "ignore" annotation. We want to
					// reconcile when that happens.
					return true
				}
				// Otherwise, ignore updates to objects when metadata.Generation does not change.
				return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
			},
		}
		err = c.WatchObject(t,
			handler.EnqueueRequestForOwner(
				mgr.GetScheme(), mgr.GetRESTMapper(), &operatorv1.Installation{}, handler.OnlyControllerOwner(),
			),
			pred)
		if err != nil {
			return fmt.Errorf("tigera-windows-controller failed to watch %s: %w", t, err)
		}
	}

	// Watch for changes to FelixConfiguration.
	err = c.WatchObject(&v3.FelixConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to watch FelixConfiguration resource: %w", err)
	}

	// Watch for changes to IPAMConfiguration.
	go utils.WaitToAddResourceWatch(c, opts.K8sClientset, logw, ri.ipamConfigWatchReady, []client.Object{&v3.IPAMConfiguration{TypeMeta: metav1.TypeMeta{Kind: v3.KindIPAMConfiguration}}})

	if err = opts.Extensions.Windows().Watches(c); err != nil {
		return fmt.Errorf("tigera-windows-controller failed to set up extension watches: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-windows-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

type ReconcileWindows struct {
	config               *rest.Config
	client               client.Client
	scheme               *runtime.Scheme
	watches              map[runtime.Object]struct{}
	status               status.StatusManager
	ipamConfigWatchReady *utils.ReadyFlag
	opts                 options.ControllerOptions
	ext                  extensions.WindowsExtension
}

// newWindowsReconciler returns a new reconcile.Reconciler
func newWindowsReconciler(mgr manager.Manager, opts options.ControllerOptions) (*ReconcileWindows, error) {
	statusManager := status.New(mgr.GetClient(), "calico-windows", opts.KubernetesVersion)

	r := &ReconcileWindows{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		status:               statusManager,
		ipamConfigWatchReady: &utils.ReadyFlag{},
		opts:                 opts,
		ext:                  opts.Extensions.Windows(),
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

// Reconcile reads that state of the cluster for a Installation object and makes changes based on the state read
// and what is in the Installation.Spec. The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileWindows) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := logw.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling Installation.operator.tigera.io")

	// Get the installation object if it exists so that we can save the original
	// status before we merge/fill that object with other values.
	instance := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if apierrors.IsNotFound(err) {
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	// The core controller publishes the effective config, with defaults and the overlay
	// applied, on the status. Nothing here can be decided before that lands.
	if instance.Status.Computed == nil {
		reqLogger.V(1).Info("Waiting for the Installation computed config")
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}
	defaulted := instance.DeepCopy()
	defaulted.Spec = *instance.Status.Computed.DeepCopy()

	// Don't render calico-node-windows if it's disabled in the installation
	if !common.WindowsEnabled(defaulted.Spec) {
		reqLogger.V(1).Info("Calico Windows daemonset is disabled in the operator installation")
		return reconcile.Result{}, nil
	}

	// Mark CR found so we can report converter problems via tigerastatus
	r.status.OnCRFound()
	// FIXME: add logic to merge Installation status metadata

	// FIXME: add logic to update Installation status conditions that doesn't conflict with
	// core_controller

	reqLogger.V(2).Info("Loaded config", "config", defaulted)

	// The k8s service endpoint configmap must populate k8sapi.Endpoint data before validating the configuration.
	if _, err := utils.GetK8sServiceEndPoint(r.client); err != nil {
		// PopulateK8sServiceEndPoint() does not return an error if the configmap is not found, check for this with GetK8sServiceEndPoint()
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading services endpoint configmap", err, reqLogger)
		return reconcile.Result{}, err
	}
	if err := utils.PopulateK8sServiceEndPoint(r.client); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading services endpoint configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate the configuration.
	if err := validateCustomResource(defaulted); err != nil {
		r.status.SetDegraded(operatorv1.InvalidConfigurationError, "Invalid Installation provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	if defaulted.Spec.WindowsNodes == nil {
		err := fmt.Errorf("Installation.Status.Computed.WindowsNodes is nil")
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Installation.Status.Computed.WindowsNodes is nil", err, reqLogger)
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, &defaulted.Spec, r.opts.ClusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	typhaNodeTLS, err := GetTyphaNodeTLSConfig(r.client, certificateManager)
	if err != nil {
		logw.Error(err, "Error with Typha/Felix secrets")
		r.status.SetDegraded(operatorv1.CertificateError, "Error with Typha/Felix secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch default FelixConfiguration
	felixConfiguration := &v3.FelixConfiguration{}
	err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, felixConfiguration)
	if err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read FelixConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Fetch and validate default IPAMConfiguration for StrictAffinity when using Calico IPAM
	if defaulted.Spec.CNI.Type == operatorv1.PluginCalico && defaulted.Spec.CNI.IPAM.Type == operatorv1.IPAMPluginCalico {
		if !r.ipamConfigWatchReady.IsReady() {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for IPAMConfiguration watch to be established", nil, logw)
			return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
		}
		ipamConfiguration := &v3.IPAMConfiguration{}
		err = r.client.Get(ctx, types.NamespacedName{Name: "default"}, ipamConfiguration)
		if err != nil && !apierrors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Unable to read IPAMConfiguration", err, reqLogger)
			return reconcile.Result{}, err
		}
		if !ipamConfiguration.Spec.StrictAffinity {
			err := fmt.Errorf("StrictAffinity is false, it must be set to 'true' in the default IPAMConfiguration when using Calico IPAM on Windows")
			r.status.SetDegraded(operatorv1.ResourceReadError, "Invalid StrictAffinity, it must be set to 'true' when using Calico IPAM on Windows", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	var component render.Component

	kubeDNSServiceName := utils.GetDNSServiceName(r.opts.DetectedProvider)
	kubeDNSService := &corev1.Service{}
	err = r.client.Get(ctx, kubeDNSServiceName, kubeDNSService)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, fmt.Sprintf("%s service not found", kubeDNSServiceName.Name), err, reqLogger)
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error querying %s service", kubeDNSServiceName.Name), err, reqLogger)
		}
		return reconcile.Result{}, err
	}
	kubeDNSIPs := kubeDNSService.Spec.ClusterIPs

	// felixConfiguration.Spec.VXLANVNI is defaulted by fillDefaults() in the core controller, so if it isn't set, requeue to wait until it is
	if felixConfiguration.Spec.VXLANVNI == nil {
		err = fmt.Errorf("VXLANVNI not specified in FelixConfigurationSpec")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading VXLANVNI from FelixConfiguration", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Run the variant's windows controller extension to build the render inputs
	// (creating no enterprise artifacts in core).
	ci := controller.Inputs{
		RenderInputs: render.Inputs{
			Installation:       &defaulted.Spec,
			FelixConfiguration: felixConfiguration,
			ClusterDomain:      r.opts.ClusterDomain,
			TrustedBundle:      typhaNodeTLS.TrustedBundle,
		},
		Client:             r.client,
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
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error preparing windows extension", err, reqLogger)
		return reconcile.Result{}, err
	}

	windowsCfg := render.WindowsConfiguration{
		K8sServiceEp:   k8sapi.Endpoint,
		K8sDNSServers:  kubeDNSIPs,
		Installation:   &defaulted.Spec,
		ClusterDomain:  r.opts.ClusterDomain,
		TLS:            typhaNodeTLS,
		VXLANVNI:       *felixConfiguration.Spec.VXLANVNI,
		ImageOverrides: r.ext.Images(),
	}
	component = render.Windows(&windowsCfg)

	imageSet, err := imageset.GetImageSet(ctx, r.client, defaulted.Spec.Variant)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ValidateImageSet(imageSet); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error validating ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = imageset.ResolveImages(imageSet, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Error resolving ImageSet for components", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Create a component handler to create or update the rendered components.
	handler := utils.NewComponentHandler(
		logw,
		r.client,
		r.scheme,
		instance,
		utils.WithExtension(r.ext, ci.RenderInputs),
	)
	if err := handler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	reqLogger.V(1).Info("Finished reconciling windows installation")
	return reconcile.Result{}, nil
}
