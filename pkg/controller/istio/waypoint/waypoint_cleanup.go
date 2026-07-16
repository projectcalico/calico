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
	"strings"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// GatewayClassNameLabel is stamped by istiod's gateway deployment controller
	// on every resource it renders for a Gateway, recording the GatewayClass the
	// resource was rendered for.
	GatewayClassNameLabel = "gateway.networking.k8s.io/gateway-class-name"

	gatewayAPIGroup = "gateway.networking.k8s.io"

	// istioGatewayControllerPrefix identifies GatewayClasses handled by istiod's
	// gateway deployment controller (e.g. istio.io/gateway-controller,
	// istio.io/mesh-controller).
	istioGatewayControllerPrefix = "istio.io/"
)

// builtinIstioGatewayClasses are the GatewayClass names istiod handles even
// when no GatewayClass object exists for them. istiod's ClassController
// creates (and re-creates) the GatewayClass objects for these, so this list
// only decides staleness in the window where such an object is absent.
var builtinIstioGatewayClasses = map[string]bool{
	"istio":           true,
	"istio-waypoint":  true,
	"istio-remote":    true,
	"istio-east-west": true,
}

// staleGatewaySets returns the istiod-managed gateway resources that were
// rendered for a GatewayClass their owning Gateway no longer uses.
//
// Istiod's gateway deployment controller renders a per-class resource set
// (Deployment, Service, ServiceAccount, ...) for each Gateway, named
// differently per class: the istio-waypoint class uses the Gateway's name
// as-is, other classes append the class name. It only ever applies the set for
// the Gateway's *current* class and never deletes the set rendered for a
// previous class, and Kubernetes garbage collection only fires when the
// Gateway itself is deleted. So changing a Gateway's spec.gatewayClassName
// strands the previous class's set — for waypoints, a running Deployment whose
// l7-collector sidecar stays connected to Felix.
func (r *ReconcileWaypoint) staleGatewaySets(ctx context.Context, reqLogger logr.Logger) ([]client.Object, error) {
	gatewayList := &gapi.GatewayList{}
	if err := r.List(ctx, gatewayList); err != nil {
		return nil, fmt.Errorf("failed to list Gateways: %w", err)
	}
	gateways := map[types.NamespacedName]*gapi.Gateway{}
	for i := range gatewayList.Items {
		gw := &gatewayList.Items[i]
		gateways[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = gw
	}

	// The kinds istiod renders for every managed Gateway. It can also render a
	// HorizontalPodAutoscaler and PodDisruptionBudget when the Gateway opts in;
	// the HPA is not swept here because the operator has no delete permission
	// on HPAs, and a stale HPA is inert (its scale target no longer exists) and
	// is still garbage-collected with the Gateway.
	lists := []client.ObjectList{
		&appsv1.DeploymentList{},
		&corev1.ServiceList{},
		&corev1.ServiceAccountList{},
		&policyv1.PodDisruptionBudgetList{},
	}

	var stale []client.Object
	classManaged := map[string]bool{}
	for _, list := range lists {
		if err := r.List(ctx, list, client.HasLabels{GatewayClassNameLabel}); err != nil {
			return nil, fmt.Errorf("failed to list gateway-managed resources: %w", err)
		}
		items, err := meta.ExtractList(list)
		if err != nil {
			return nil, fmt.Errorf("failed to extract gateway-managed resources: %w", err)
		}
		for _, item := range items {
			obj, ok := item.(client.Object)
			if !ok {
				continue
			}
			isStale, err := r.staleGatewayResource(ctx, obj, gateways, classManaged)
			if err != nil {
				return nil, err
			}
			if isStale {
				stale = append(stale, obj)
			}
		}
	}

	// These deletions are in user namespaces, so leave an Info-level trail.
	for _, obj := range stale {
		gvk, _ := apiutil.GVKForObject(obj, r.scheme)
		reqLogger.Info("Deleting gateway resource rendered for a class its Gateway no longer uses",
			"kind", gvk.Kind, "namespace", obj.GetNamespace(), "name", obj.GetName(),
			"renderedForClass", obj.GetLabels()[GatewayClassNameLabel])
	}

	return stale, nil
}

// staleGatewayResource reports whether obj was rendered by istiod for a
// GatewayClass that its owning Gateway no longer uses. Resources whose owning
// Gateway no longer exists (or was recreated with a new UID) are not
// considered stale: Kubernetes garbage collection removes those via the owner
// reference. Resources rendered for a class that is not istiod-managed are
// never touched — another gateway implementation could stamp the same labels.
//
// A racy read can transiently mark the active set stale (e.g. the class was
// flipped back but the cache still holds the old Gateway). Deleting it anyway
// is safe: istiod watches the resources it manages and re-applies the set for
// the Gateway's current class.
func (r *ReconcileWaypoint) staleGatewayResource(ctx context.Context, obj client.Object, gateways map[types.NamespacedName]*gapi.Gateway, classManaged map[string]bool) (bool, error) {
	class := obj.GetLabels()[GatewayClassNameLabel]
	if class == "" {
		return false, nil
	}
	owner := gatewayOwnerRef(obj)
	if owner == nil {
		return false, nil
	}
	gw, ok := gateways[types.NamespacedName{Namespace: obj.GetNamespace(), Name: owner.Name}]
	if !ok || gw.UID != owner.UID {
		return false, nil
	}
	if string(gw.Spec.GatewayClassName) == class {
		return false, nil
	}
	return r.isIstioManagedClass(ctx, class, classManaged)
}

// isIstioManagedClass reports whether className is handled by istiod's gateway
// deployment controller, mirroring istiod's own lookup: an existing
// GatewayClass object decides by controllerName; otherwise the builtin class
// names apply. Results are memoized in classManaged for the reconcile.
func (r *ReconcileWaypoint) isIstioManagedClass(ctx context.Context, className string, classManaged map[string]bool) (bool, error) {
	if managed, ok := classManaged[className]; ok {
		return managed, nil
	}
	var managed bool
	gc := &gapi.GatewayClass{}
	err := r.Get(ctx, types.NamespacedName{Name: className}, gc)
	switch {
	case err == nil:
		managed = strings.HasPrefix(string(gc.Spec.ControllerName), istioGatewayControllerPrefix)
	case errors.IsNotFound(err):
		managed = builtinIstioGatewayClasses[className]
	default:
		return false, err
	}
	classManaged[className] = managed
	return managed, nil
}

// gatewayOwnerRef returns obj's owner reference to a Gateway API Gateway, or
// nil if there is none.
func gatewayOwnerRef(obj client.Object) *metav1.OwnerReference {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == "Gateway" && strings.HasPrefix(ref.APIVersion, gatewayAPIGroup+"/") {
			return &ref
		}
	}
	return nil
}
