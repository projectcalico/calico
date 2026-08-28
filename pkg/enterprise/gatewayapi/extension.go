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

package gatewayapi

import (
	"context"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/gatewayapi"
)

// legacyNamespace is where the pre-namespaced Gateway install put its resources.
const legacyNamespace = "tigera-gateway"

// Extension is the Calico Enterprise behavior for the gateway API controller.
type Extension struct {
	variant operatorv1.ProductVariant
}

var _ extensions.GatewayAPIExtension = &Extension{}

// New returns the gateway API extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant) *Extension {
	return &Extension{variant: variant}
}

// RegisterImages adds the images the gateway API components resolve.
func RegisterImages(o *imageoverride.Overrides, variant operatorv1.ProductVariant) {
	o.Register(variant, gatewayapi.ComponentNameEnvoyGateway, components.ComponentGatewayAPIEnvoyGateway)
	o.Register(variant, gatewayapi.ComponentNameEnvoyProxy, components.ComponentGatewayAPIEnvoyProxy)
	o.Register(variant, gatewayapi.ComponentNameEnvoyRatelimit, components.ComponentGatewayAPIEnvoyRatelimit)
}

// gatewayAPIRenderData is the controller-produced data the gateway API extension hands
// to its modifier through Inputs.Extension.
type gatewayAPIRenderData struct {
	// l7LogCollectorImage runs alongside envoy to collect access and WAF audit logs.
	// The base render never resolves it, and a modifier runs with no ImageSet.
	l7LogCollectorImage string
}

// gatewayAPIData pulls the extension's render data back out of the render inputs,
// returning the zero value when none is set.
func gatewayAPIData(ri render.Inputs) gatewayAPIRenderData {
	return render.ExtractExtensionData[gatewayAPIRenderData](ri)
}

// ExtendInputs resolves the l7-log-collector image for the modifier.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, error) {
	in := ci.RenderInputs.Installation

	imageSet, err := imageset.GetImageSet(ctx, ci.Client, in.Variant)
	if err != nil {
		return ci, extensions.Degradedf(operatorv1.ResourceReadError, "error getting ImageSet: %w", err)
	}
	image, err := components.GetReference(components.ComponentGatewayL7Collector, in.Registry, in.ImagePath, in.ImagePrefix, imageSet)
	if err != nil {
		return ci, extensions.Degradedf(operatorv1.ResourceUpdateError, "error with images from ImageSet: %w", err)
	}

	ci.RenderInputs.Extension = gatewayAPIRenderData{l7LogCollectorImage: image}
	return ci, nil
}

// Modify dispatches over the components the gateway API controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch t := c.(type) {
	case gatewayapi.ImplementationComponent:
		return extensions.Decorate(c, ri, e.variant, func(create, del []client.Object) ([]client.Object, []client.Object) {
			return modifyImplementation(ri, t.GetConfig(), create, del)
		})
	default:
		return c
	}
}

// modifyImplementation adds the WAF HTTP filter's RBAC, layers the filter and the
// l7-log-collector onto each rendered EnvoyProxy, and cleans up the legacy install's
// service account and the cluster role bindings that bound it.
func modifyImplementation(ri render.Inputs, cfg *gatewayapi.GatewayAPIImplementationConfig, create, del []client.Object) ([]client.Object, []client.Object) {
	create = append(create, gatewayapi.WAFClusterScopedRole(), gatewayapi.WAFGatewayResourcesRole())

	// The shared binding's subjects are recomputed each reconcile, and it goes away
	// once no Gateway namespaces remain.
	if len(cfg.GatewayNamespaces) > 0 {
		create = append(create, gatewayapi.GatewayNamespacesCRB(cfg.GatewayNamespaces))
	} else {
		del = append(del, gatewayapi.GatewayNamespacesCRB(nil))
	}

	image := gatewayAPIData(ri).l7LogCollectorImage
	patched := 0
	for _, o := range create {
		if proxy, ok := o.(*envoyapi.EnvoyProxy); ok {
			applyWAFAndLogCollector(proxy, image)
			patched++
		}
	}

	// The render emits one EnvoyProxy per GatewayClass. A mismatch means a proxy that
	// serves traffic would run without the WAF filter.
	if expected := len(cfg.GatewayAPI.Spec.GatewayClasses); patched != expected {
		panic(fmt.Sprintf("BUG: applied the WAF filter to %d EnvoyProxies for %d GatewayClasses", patched, expected))
	}

	// The legacy install's service account, unless a Gateway lives there and the
	// controller is managing it.
	if !slices.Contains(cfg.GatewayNamespaces, legacyNamespace) {
		del = append(del, &corev1.ServiceAccount{
			TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: gatewayapi.WAFFilterName, Namespace: legacyNamespace},
		})
	}

	// The orphaned bindings that bound it: a current install uses the shared binding
	// and per-namespace role bindings instead.
	del = append(del,
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: gatewayapi.WAFClusterScopedRole().Name},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: gatewayapi.WAFGatewayResourcesRole().Name},
		},
	)

	return create, del
}

// GatewayNamespaceObjects returns the WAF HTTP filter's per-namespace identity and the
// pull secrets its container needs.
func (e *Extension) GatewayNamespaceObjects(namespace string, pullSecrets []*corev1.Secret) []client.Object {
	objs := []client.Object{
		gatewayapi.GatewayNamespaceServiceAccount(namespace),
		gatewayapi.GatewayNamespaceRoleBinding(namespace),
		render.CreateOperatorSecretsRoleBinding(namespace),
	}
	return append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(namespace, pullSecrets...)...)...)
}
