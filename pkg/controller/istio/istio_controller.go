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

package istio

import (
	"context"
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"
	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/istio/waypoint"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/gatewayapi"
	"github.com/tigera/operator/pkg/render/istio"
)

const IstioName = "istio"

var (
	// blank assignment to verify that ReconcileIstio implements reconcile.Reconciler
	_ reconcile.Reconciler = &ReconcileIstio{}

	log = logf.Log.WithName("controller_istio")
)

// Add creates a new Istio Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
//
// Start Watches within the Add function for any resources that this controller creates or monitors. This will trigger
// calls to Reconcile() when an instance of one of the watched resources is modified.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	r := newReconciler(mgr, opts)

	c, err := ctrlruntime.NewController("istio-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create istio-controller: %w", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, IstioName); err != nil {
		return fmt.Errorf("istio-controller failed to watch calico Tigerastatus: %w", err)
	}

	// Watch for changes to primary resource Istio
	err = c.WatchObject(&operatorv1.Istio{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("istio-controller failed to watch primary resource: %v", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("istio-controller failed to watch Installation resource: %v", err)
	}

	err = c.WatchObject(&v3.FelixConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("istio-controller failed to watch FelixConfiguration resource: %w", err)
	}

	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("istio-controller failed to create periodic reconcile watch: %w", err)
	}

	// The waypoint controller reconciles the per-Gateway state the Istio
	// feature needs beyond istiod's own rendering. It replicates the
	// Installation pull secret into namespaces that contain istio-waypoint
	// Gateways, so waypoint pods can pull the Istio proxy image from a private
	// registry (the imagePullSecrets reference injected via istiod's global
	// config is namespace-scoped and the secret must exist in the user
	// namespace). It also deletes the per-class resource sets that istiod
	// strands when a Gateway's spec.gatewayClassName changes: istiod only
	// applies the set for the current class and never deletes the previous
	// class's set, and owner-reference GC only fires when the Gateway itself
	// is deleted.
	if err := waypoint.Add(mgr, opts); err != nil {
		return fmt.Errorf("failed to add waypoint controller: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.ControllerOptions) *ReconcileIstio {
	r := &ReconcileIstio{
		Client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		status:   status.New(mgr.GetClient(), "istio", opts.KubernetesVersion),
		provider: opts.DetectedProvider,
	}

	r.status.Run(opts.ShutdownContext)
	return r
}

// ReconcileIstio reconciles a Istio object
type ReconcileIstio struct {
	client.Client
	scheme   *runtime.Scheme
	status   status.StatusManager
	provider operatorv1.Provider
}

func (r *ReconcileIstio) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling Istio")

	// Get the Istio CR.
	instance := &operatorv1.Istio{}
	err := r.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.V(1).Info("Istio object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError,
			fmt.Sprintf("Error querying for Istio CR: failed to get Istio %q", utils.DefaultInstanceKey),
			err,
			reqLogger,
		)
		return reconcile.Result{}, err
	}

	if res, err, finished := r.maintainFinalizer(ctx, instance, reqLogger); err != nil || finished {
		return res, err
	}

	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating Istio status conditions.
	if request.Name == IstioName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.Get(ctx, types.NamespacedName{Name: IstioName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to update Istio status conditions.")
			return reconcile.Result{}, err
		}
	}

	// Set defaults
	preDefaultPatchFrom := client.MergeFrom(instance.DeepCopy())
	updateDefaults(instance)
	if err := r.Patch(ctx, instance, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get the Installation, for k8s provider info.
	variant, installationSpec, err := utils.GetInstallationSpec(ctx, r)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	if variant == "" {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation Variant to be set", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Get the Kubernetes Gateway API CRDs.
	essentialCRDs, optionalCRDs, err := gatewayapi.K8SGatewayAPICRDs(installationSpec.KubernetesProvider, r.scheme)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error rendering gateway API CRDs", err, log)
		return reconcile.Result{}, err
	}

	// Check CRDs are present and only create it if not
	handler := utils.NewComponentHandler(log, r, r.scheme, nil)
	handler.SetCreateOnly()
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewCreationPassthrough(essentialCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating gateway API CRDs", err, log)
		return reconcile.Result{}, err
	}
	err = handler.CreateOrUpdateOrDelete(ctx, render.NewCreationPassthrough(optionalCRDs...), nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		reqLogger.Info("Could not render all optional gateway API CRDs", "err", err)
	}

	// Render resources for Istio support
	istioCfg := &istio.Configuration{
		Installation:   installationSpec,
		PullSecrets:    pullSecrets,
		Istio:          instance,
		IstioNamespace: istio.IstioNamespace,
		Scheme:         r.scheme,
	}
	istioComponentCRDs, istioComponent, err := istio.Istio(istioCfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error initializing Istio components", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Apply the image set
	if err = imageset.ApplyImageSet(ctx, r.Client, installationSpec.Variant, istioComponent); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error with ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Deploy Istio CRDs
	err = handler.CreateOrUpdateOrDelete(ctx, istioComponentCRDs, nil)
	if err != nil && !errors.IsAlreadyExists(err) {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Calico Istio CRDs", err, log)
		return reconcile.Result{}, err
	}

	// Deploy Istio components, passing the Istio CR for the owner this time.
	err = utils.NewComponentHandler(log, r, r.scheme, instance).CreateOrUpdateOrDelete(ctx, istioComponent, r.status)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error rendering Calico Istio resources", err, log)
		return reconcile.Result{}, err
	}

	_, err = utils.PatchFelixConfiguration(ctx, r.Client, func(fc *v3.FelixConfiguration) (bool, error) {
		return r.setIstioFelixConfiguration(ctx, instance, fc, false)
	})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error patching felix configuration with Istio settings", err, log)
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	return reconcile.Result{}, nil
}

func updateDefaults(istio *operatorv1.Istio) {
	if istio.Spec.DSCPMark == nil {
		dscpMark := numorstring.DSCPFromInt(23)
		istio.Spec.DSCPMark = &dscpMark
	}
}

func (r *ReconcileIstio) setIstioFelixConfiguration(ctx context.Context, instance *operatorv1.Istio, fc *v3.FelixConfiguration, remove bool) (bool, error) {
	ambientChanged, err := r.configureIstioAmbientMode(fc, remove)
	if err != nil {
		return false, err
	}
	dscpChanged, err := r.configureIstioDSCPMark(instance, fc, remove)
	if err != nil {
		return false, err
	}
	policySyncChanged, err := r.configurePolicySyncPathPrefix(ctx, instance, fc, remove)
	if err != nil {
		return false, err
	}
	return ambientChanged || dscpChanged || policySyncChanged, nil
}

func (r *ReconcileIstio) configureIstioAmbientMode(fc *v3.FelixConfiguration, remove bool) (bool, error) {
	var annotationMode *string
	if fc.Annotations[istio.IstioOperatorAnnotationMode] != "" {
		value := fc.Annotations[istio.IstioOperatorAnnotationMode]
		annotationMode = &value
	}

	// If the annotation does not match the spec value (ignoring both nil), it indicates a misconfiguration.
	match := annotationMode == nil && fc.Spec.IstioAmbientMode == nil ||
		annotationMode != nil && fc.Spec.IstioAmbientMode != nil && *annotationMode == string(*fc.Spec.IstioAmbientMode)

	if !match {
		return false, fmt.Errorf("felixconfig IstioAmbientMode modified by user")
	}

	if remove {
		if annotationMode == nil && fc.Spec.IstioAmbientMode == nil {
			return false, nil
		}
		delete(fc.Annotations, istio.IstioOperatorAnnotationMode)
		fc.Spec.IstioAmbientMode = nil
		return true, nil
	}

	istioModeDesired := v3.IstioAmbientModeEnabled
	if fc.Spec.IstioAmbientMode != nil && *fc.Spec.IstioAmbientMode == istioModeDesired &&
		annotationMode != nil && *annotationMode == string(istioModeDesired) {
		return false, nil
	}
	fc.Spec.IstioAmbientMode = &istioModeDesired
	if fc.Annotations == nil {
		fc.Annotations = make(map[string]string)
	}
	fc.Annotations[istio.IstioOperatorAnnotationMode] = string(istioModeDesired)
	return true, nil
}

func (r *ReconcileIstio) configureIstioDSCPMark(instance *operatorv1.Istio, fc *v3.FelixConfiguration, remove bool) (bool, error) {
	var annotationDSCP *numorstring.DSCP
	if fc.Annotations[istio.IstioOperatorAnnotationDSCP] != "" {
		value, err := strconv.ParseUint(fc.Annotations[istio.IstioOperatorAnnotationDSCP], 10, 6)
		if err != nil {
			return false, err
		}
		dscp := numorstring.DSCPFromInt(uint8(value))
		annotationDSCP = &dscp
	}

	// Return an error if it appears that FelixConfiguration has been modified out of band.
	match := annotationDSCP == nil && fc.Spec.IstioDSCPMark == nil ||
		annotationDSCP != nil && fc.Spec.IstioDSCPMark != nil && annotationDSCP.ToUint8() == fc.Spec.IstioDSCPMark.ToUint8()

	if !match {
		return false, fmt.Errorf("felixconfig IstioDSCPMark modified by user")
	}

	if remove || instance.Spec.DSCPMark == nil {
		if annotationDSCP == nil && fc.Spec.IstioDSCPMark == nil {
			return false, nil
		}
		delete(fc.Annotations, istio.IstioOperatorAnnotationDSCP)
		fc.Spec.IstioDSCPMark = nil
		return true, nil
	}

	istioDSCPMarkDesired := *instance.Spec.DSCPMark
	if fc.Spec.IstioDSCPMark != nil && annotationDSCP != nil &&
		fc.Spec.IstioDSCPMark.ToUint8() == istioDSCPMarkDesired.ToUint8() &&
		annotationDSCP.ToUint8() == istioDSCPMarkDesired.ToUint8() {
		return false, nil
	}
	fc.Spec.IstioDSCPMark = &istioDSCPMarkDesired
	if fc.Annotations == nil {
		fc.Annotations = make(map[string]string)
	}
	fc.Annotations[istio.IstioOperatorAnnotationDSCP] = strconv.FormatUint(uint64(istioDSCPMarkDesired.ToUint8()), 10)
	return true, nil
}

// configurePolicySyncPathPrefix reconciles FelixConfiguration.policySyncPathPrefix
// for the Istio side. The L7 ambient waypoint pod's l7-collector sidecar
// dials Felix's nodeagent socket, which Felix only opens when this field
// is set. The applicationlayer controller writes this same field for the
// Dikastes/sidecar/WAF flow; both controllers consult each other's state
// (via utils.{ApplicationLayerRequiresPolicySync,IstioRequiresPolicySync})
// so that deleting one CR does not strand the other.
func (r *ReconcileIstio) configurePolicySyncPathPrefix(ctx context.Context, instance *operatorv1.Istio, fc *v3.FelixConfiguration, remove bool) (bool, error) {
	var istioNeeds bool
	if !remove {
		// Mirror the renderer gate at pkg/render/istio/istio.go: it reads
		// installationSpec.Variant (i.e. Installation.Spec.Variant), so the
		// policy-sync field tracks the renderer's decision to ship the L7
		// waypoint sidecar even before Status.Variant catches up.
		_, installationSpec, err := utils.GetInstallationSpec(ctx, r.Client)
		if err != nil && !errors.IsNotFound(err) {
			return false, err
		}
		var variant operatorv1.ProductVariant
		if installationSpec != nil {
			variant = installationSpec.Variant
		}
		istioNeeds = utils.IstioRequiresPolicySync(instance, variant)
	}

	al, err := utils.GetApplicationLayer(ctx, r.Client)
	if err != nil {
		return false, err
	}
	alNeeds := utils.ApplicationLayerRequiresPolicySync(al)

	desired := utils.DesiredPolicySyncPathPrefix(fc.Spec.PolicySyncPathPrefix, alNeeds, istioNeeds)
	if fc.Spec.PolicySyncPathPrefix == desired {
		return false, nil
	}
	fc.Spec.PolicySyncPathPrefix = desired
	return true, nil
}

func (r *ReconcileIstio) maintainFinalizer(ctx context.Context, instance *operatorv1.Istio, reqLogger logr.Logger) (res reconcile.Result, err error, finalized bool) {
	// Executing clean up on finalizing
	if !instance.DeletionTimestamp.IsZero() {
		if _, err = utils.PatchFelixConfiguration(ctx, r.Client, func(fc *v3.FelixConfiguration) (bool, error) {
			return r.setIstioFelixConfiguration(ctx, instance, fc, true)
		}); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error cleaning up felix configuration", err, reqLogger)
			return
		}
		patchFrom := client.MergeFrom(instance.DeepCopy())
		instance.Finalizers = stringsutil.RemoveStringInSlice(istio.IstioFinalizer, instance.Finalizers)
		if err = r.Patch(ctx, instance, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error removing finalizer on Istio", err, reqLogger)
			return
		}

		r.status.ClearDegraded()
		return res, nil, true
	}

	if !stringsutil.StringInSlice(istio.IstioFinalizer, instance.Finalizers) {
		patchFrom := client.MergeFrom(instance.DeepCopy())
		instance.Finalizers = append(instance.Finalizers, istio.IstioFinalizer)
		if err = r.Patch(ctx, instance, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error setting finalizer on Istio", err, reqLogger)
			return
		}
	}

	return
}
