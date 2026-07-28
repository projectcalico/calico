// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package waypoint

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	// IstioWaypointClassName is the GatewayClass name used by Istio waypoints.
	IstioWaypointClassName = "istio-waypoint"

	// WaypointPullSecretLabel labels secrets copied by this controller. We use a label rather
	// than owner references because the controller needs to efficiently find and clean up its
	// managed secrets during reconciliation — for example, when pull secrets are removed from
	// Installation or when the Istio CR is deleted. A label selector provides a simple,
	// cross-namespace query that covers all cleanup scenarios, whereas owner references would
	// only automate Gateway-deletion cleanup via Kubernetes garbage collection.
	WaypointPullSecretLabel = "operator.tigera.io/istio-waypoint-pull-secret"
)

var log = logf.Log.WithName("controller_istio_waypoint")

// Add creates the waypoint controller and adds it to the Manager. The
// controller reconciles the per-Gateway state the Istio feature needs beyond
// istiod's own rendering: it copies Installation pull secrets into namespaces
// that contain istio-waypoint Gateways, and deletes the resource sets istiod
// strands when a Gateway's spec.gatewayClassName changes.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	gatewayWatchReady := &utils.ReadyFlag{}

	r := &ReconcileWaypoint{
		Client:            mgr.GetClient(),
		scheme:            mgr.GetScheme(),
		gatewayWatchReady: gatewayWatchReady,
	}

	c, err := ctrlruntime.NewController("istio-waypoint-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create istio-waypoint-controller: %w", err)
	}

	// Defer the Gateway watch — the Gateway API CRD may not be installed yet.
	// The Istio reconciler creates it during reconciliation, so we use a background
	// goroutine that retries until the CRD appears.
	gatewayObj := &gapi.Gateway{
		TypeMeta: metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
	}
	go utils.WaitToAddResourceWatch(c, opts.K8sClientset, log, gatewayWatchReady, []client.Object{gatewayObj}, predicate.Funcs{
		// Any create can matter: a waypoint-class Gateway needs pull secrets,
		// and when the informer syncs at operator startup every Gateway is
		// replayed as a create — the sweep uses those to catch class flips
		// that happened while the operator was down.
		CreateFunc: func(e event.CreateEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			old, okOld := e.ObjectOld.(*gapi.Gateway)
			curr, okNew := e.ObjectNew.(*gapi.Gateway)
			if !okOld || !okNew {
				return false
			}
			// A class change strands the resource set istiod rendered for the
			// previous class, and moves pull secrets in or out of scope.
			if old.Spec.GatewayClassName != curr.Spec.GatewayClassName {
				return true
			}
			// Other updates only matter for waypoint Gateways, which drive
			// pull-secret placement.
			return string(curr.Spec.GatewayClassName) == IstioWaypointClassName
		},
		// Deletes only affect pull secrets: the resource sets istiod rendered
		// are removed by Kubernetes garbage collection via owner references.
		DeleteFunc: func(e event.DeleteEvent) bool {
			gw, ok := e.Object.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
		GenericFunc: func(e event.GenericEvent) bool {
			gw, ok := e.Object.(*gapi.Gateway)
			return ok && string(gw.Spec.GatewayClassName) == IstioWaypointClassName
		},
	})

	// Watch the Istio CR for pull secret config changes and feature enablement.
	err = c.WatchObject(&operatorv1.Istio{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to watch Istio resource: %w", err)
	}

	// Watch Installation for pull secret changes.
	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to watch Installation resource: %w", err)
	}

	// Periodic reconcile as a backstop.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("istio-waypoint-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// ReconcileWaypoint reconciles the per-Gateway state the Istio feature needs
// beyond istiod's own rendering: it copies pull secrets to namespaces that
// contain istio-waypoint Gateways so waypoint pods can pull images from
// private registries, and deletes istiod-managed gateway resources that were
// rendered for a GatewayClass their owning Gateway no longer uses.
type ReconcileWaypoint struct {
	client.Client
	scheme *runtime.Scheme

	gatewayWatchReady *utils.ReadyFlag
}

func (r *ReconcileWaypoint) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling waypoint gateway resources")

	// Get the Istio CR - if not found or being deleted, the feature is
	// inactive: copied pull secrets are stale, and istiod's gateway resources
	// belong to a mesh the operator does not manage and must not be touched.
	instance := &operatorv1.Istio{}
	err := r.Get(ctx, utils.DefaultInstanceKey, instance)
	if err != nil && !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	istioActive := err == nil && instance.DeletionTimestamp.IsZero()
	gatewaysVisible := istioActive && r.gatewayWatchReady.IsReady()

	toCreate, toDelete, err := r.pullSecretChanges(ctx, gatewaysVisible, reqLogger)
	if err != nil {
		return reconcile.Result{}, err
	}

	if gatewaysVisible {
		stale, err := r.staleGatewaySets(ctx, reqLogger)
		if err != nil {
			return reconcile.Result{}, err
		}
		toDelete = append(toDelete, stale...)
	}

	// Use a single passthrough component to handle both creation and deletion.
	hdlr := utils.NewComponentHandler(log, r, r.scheme, nil)
	component := render.NewPassthrough(toCreate, toDelete)
	if err := hdlr.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to reconcile waypoint gateway resources: %w", err)
	}

	return reconcile.Result{}, nil
}

// pullSecretChanges determines which copied pull secrets need to exist
// (toCreate) based on the namespaces that contain istio-waypoint Gateways, and
// which existing copies are stale (toDelete). When active is false no copies
// are desired, so every existing copy is returned as stale.
func (r *ReconcileWaypoint) pullSecretChanges(ctx context.Context, active bool, reqLogger logr.Logger) (toCreate, toDelete []client.Object, err error) {
	// Build the desired set of secrets if Istio is active and the Gateway watch is established.
	if active {
		_, installationSpec, err := utils.GetInstallationSpec(ctx, r)
		if err != nil {
			if errors.IsNotFound(err) {
				reqLogger.V(1).Info("Installation not found")
				return nil, nil, nil
			}
			return nil, nil, err
		}

		pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r)
		if err != nil {
			return nil, nil, err
		}

		// List all Gateway resources and filter for istio-waypoint class.
		gatewayList := &gapi.GatewayList{}
		if err := r.List(ctx, gatewayList); err != nil {
			return nil, nil, fmt.Errorf("failed to list Gateways: %w", err)
		}

		targetNamespaces := map[string]bool{}
		for i := range gatewayList.Items {
			gw := &gatewayList.Items[i]
			if string(gw.Spec.GatewayClassName) == IstioWaypointClassName &&
				gw.Namespace != common.OperatorNamespace() {
				targetNamespaces[gw.Namespace] = true
			}
		}

		// Build desired secrets for each target namespace.
		for ns := range targetNamespaces {
			copied := secret.CopyToNamespace(ns, pullSecrets...)
			for _, s := range copied {
				if s.Labels == nil {
					s.Labels = map[string]string{}
				}
				s.Labels[WaypointPullSecretLabel] = "true"
				toCreate = append(toCreate, s)
			}
		}
	}

	// Build the desired set keyed on (namespace, name) so that renamed or removed
	// secrets are correctly detected as stale.
	desiredSecrets := map[types.NamespacedName]bool{}
	for _, obj := range toCreate {
		desiredSecrets[types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}] = true
	}

	// List all existing secrets managed by this controller and mark stale ones for deletion.
	existingSecrets := &corev1.SecretList{}
	if err := r.List(ctx, existingSecrets, client.MatchingLabels{WaypointPullSecretLabel: "true"}); err != nil {
		return nil, nil, fmt.Errorf("failed to list waypoint pull secrets: %w", err)
	}
	for i := range existingSecrets.Items {
		s := &existingSecrets.Items[i]
		key := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}
		if !desiredSecrets[key] {
			toDelete = append(toDelete, s)
		}
	}

	return toCreate, toDelete, nil
}
