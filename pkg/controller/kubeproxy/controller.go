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

package kubeproxy

import (
	"context"
	"fmt"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
)

const (
	controllerName = "kubeproxy-controller"
	ResourceName   = "kubeproxy-monitor"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new Reconciler Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	statusManager := status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, opts)

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = c.WatchObject(&v3.FelixConfiguration{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch for Felix Configuration resource: %w", controllerName, err)
	}

	if err = utils.AddKubeProxyWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch for Kube Proxy resource: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("kubeproxy-controller failed to watch TigeraStatus: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("kubeproxy-controller failed to create periodic reconcile watch: %w", err)
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
}

// Reconcile reads that state of the cluster for a kube-proxy object and makes changes based on the
// state read and what is in the Installation and FelixConfiguration CRs.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling KubeProxy")

	installationSpec, err := utils.GetComputedInstallationSpec(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if installationSpec == nil {
		return reconcile.Result{}, nil
	}

	if !installationSpec.KubeProxyManagementEnabled() {
		// If KubeProxyManagement is not Enabled, we should clean up kubeproxy from tigerastatus and not reconcile kube-proxy.
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	// Mark resource found so we can report problems via tigerastatus
	r.status.OnCRFound()

	// Try to retrieve the kube-proxy DaemonSet.
	kubeProxyDS := &appsv1.DaemonSet{}
	err = r.cli.Get(ctx, utils.KubeProxyInstanceKey, kubeProxyDS)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceNotFound, "failed to retrieve kube-proxy DaemonSet", err, reqLogger)
		return reconcile.Result{}, fmt.Errorf("failed to get kube-proxy: %w", err)
	}

	// Validate that the kube-proxy DaemonSet is not managed by an external tool.
	err = validateDaemonSetUnmanaged(kubeProxyDS)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "failed to validate kube-proxy DaemonSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	felixCR, err := utils.GetFelixConfiguration(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if felixCR == nil {
		return reconcile.Result{}, nil
	}

	// If BPF enabled in FelixConfiguration (meaning the calico-node rollout is completed) and KubeProxyManagement is Enabled,
	// we should try to disable kube-proxy.
	if felixCR.Spec.BPFEnabled != nil && *felixCR.Spec.BPFEnabled {
		// 1. Check if kube-proxy is already disabled.
		if kubeProxyDS.Spec.Template.Spec.NodeSelector != nil &&
			kubeProxyDS.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey] == strconv.FormatBool(true) {
			return reconcile.Result{}, nil
		}

		// 2. Patch the kube-proxy DaemonSet with a disabling nodeSelector.
		// This step ensures that kube-proxy is disabled not only during BPF installation (fresh install or migration),
		// but also if an external operation - such as a manual upgrade or migration - overrides this setting.
		patchFrom := client.MergeFrom(kubeProxyDS.DeepCopy())
		if kubeProxyDS.Spec.Template.Spec.NodeSelector == nil {
			kubeProxyDS.Spec.Template.Spec.NodeSelector = make(map[string]string)
		}
		kubeProxyDS.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey] = strconv.FormatBool(true)
		if err := r.cli.Patch(ctx, kubeProxyDS, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "unable to add kube-proxy nodeSelector", err, reqLogger)
			return reconcile.Result{}, err

		}
		reqLogger.Info("kube-proxy DaemonSet patched to disable kube-proxy, since kubeProxyManagement is Enabled and BPFEnabled is true.")
		if !installationSpec.KubernetesProvider.IsNone() {
			reqLogger.Info(fmt.Sprintf("[WARNING] Auto disabling kube-proxy may result in unexpected behavior in %s. ", installationSpec.KubernetesProvider) +
				"If the Operator fails to patch the kube-proxy DaemonSet, disable 'kubeProxyManagement' in the Installation CR " +
				"and follow the eBPF installation guide at https://docs.tigera.io.")
		}
	} else {
		// If the dataplane is not BPF, we'll try to re-enable kube-proxy:
		// 1. Check if kube-proxy DaemonSet is disabled by verifying whether render.DisableKubeProxyKey exists in the NodeSelector.
		if _, ok := kubeProxyDS.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey]; !ok {
			return reconcile.Result{}, nil
		}

		// 2. Re-enable kube-proxy by removing the disabling nodeSelector.
		patchFrom := client.MergeFrom(kubeProxyDS.DeepCopy())
		delete(kubeProxyDS.Spec.Template.Spec.NodeSelector, render.DisableKubeProxyKey)
		if err := r.cli.Patch(ctx, kubeProxyDS, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "unable to remove kube-proxy nodeSelector", err, reqLogger)
			return reconcile.Result{}, err
		}
		reqLogger.Info("kube-proxy DaemonSet patched to deploy kube-proxy, since kubeProxyManagement is Enabled and BPFEnabled is false.")
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

// validateDaemonSetUnmanaged checks whether the DaemonSet is managed by an external tool,
// based on common labels or annotations typically added by automation.
func validateDaemonSetUnmanaged(ds *appsv1.DaemonSet) error {
	if len(ds.Labels) == 0 && len(ds.Annotations) == 0 {
		return nil
	}

	// Kubernetes well-known labels
	if _, ok := ds.Labels["app.kubernetes.io/managed-by"]; ok {
		return fmt.Errorf("DaemonSet is likely managed by: %s", ds.Labels["app.kubernetes.io/managed-by"])
	}
	if _, ok := ds.Labels["addonmanager.kubernetes.io/mode"]; ok {
		return fmt.Errorf("DaemonSet is likely managed by another source due to the label 'addonmanager.kubernetes.io/mode: %s'", ds.Labels["addonmanager.kubernetes.io/mode"])
	}

	// Check for GitOps tools
	if _, ok := ds.Annotations["argocd.argoproj.io/tracking-id"]; ok {
		return fmt.Errorf("DaemonSet is likely managed by another source due to the label 'argocd.argoproj.io/tracking-id: %s'", ds.Annotations["argocd.argoproj.io/tracking-id"])
	}

	return nil
}
