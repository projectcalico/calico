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

package istio

import (
	"context"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/enterprise/policysync"
	"github.com/tigera/operator/pkg/enterprise/utils"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	ristio "github.com/tigera/operator/pkg/render/istio"
)

// Extension is the Calico Enterprise behavior for the istio controller.
type Extension struct {
	variant operatorv1.ProductVariant
}

var _ extensions.IstioExtension = &Extension{}

// New returns the istio extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant) *Extension {
	return &Extension{variant: variant}
}

// RegisterImages adds the images the istio components resolve.
func RegisterImages(o *imageoverride.Overrides, variant operatorv1.ProductVariant) {
	o.Register(variant, ristio.ComponentNamePilot, components.ComponentIstioPilot)
	o.Register(variant, ristio.ComponentNameInstallCNI, components.ComponentIstioInstallCNI)
	o.Register(variant, ristio.ComponentNameZTunnel, components.ComponentIstioZTunnel)
	o.Register(variant, ristio.ComponentNameProxyv2, components.ComponentIstioProxyv2)
}

// PolicySyncRequired reports whether the ApplicationLayer flow needs the policy-sync
// socket, so deleting the Istio CR does not strand it.
func (e *Extension) PolicySyncRequired(ctx context.Context, c client.Client) (bool, error) {
	al, err := utils.GetApplicationLayer(ctx, c)
	if err != nil {
		return false, err
	}
	return policysync.ApplicationLayerRequires(al), nil
}

// istioRenderData is the controller-produced data the istio extension hands to its
// modifier through Inputs.Extension.
type istioRenderData struct {
	// l7CollectorImage runs beside each waypoint proxy to collect L7 logs. The base
	// render never resolves it, and a modifier runs with no ImageSet.
	l7CollectorImage string
}

// istioData pulls the extension's render data back out of the render inputs,
// returning the zero value when none is set.
func istioData(ri render.Inputs) istioRenderData {
	return render.ExtractExtensionData[istioRenderData](ri)
}

// ExtendInputs resolves the waypoint l7-collector image for the modifier.
func (e *Extension) ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, error) {
	in := ci.RenderInputs.Installation

	imageSet, err := imageset.GetImageSet(ctx, ci.Client, in.Variant)
	if err != nil {
		return ci, extensions.Degradedf(operatorv1.ResourceReadError, "error getting ImageSet: %w", err)
	}

	// The l7-collector runs as a subcommand of the combined calico binary, so waypoint
	// pods resolve it from the node cache that calico-node already populated and need no
	// pull secret in their namespace.
	image, err := components.GetReference(components.ComponentTigeraCalico, in.Registry, in.ImagePath, in.ImagePrefix, imageSet)
	if err != nil {
		return ci, extensions.Degradedf(operatorv1.ResourceUpdateError, "error with images from ImageSet: %w", err)
	}

	ci.RenderInputs.Extension = istioRenderData{l7CollectorImage: image}
	return ci, nil
}

// Modify dispatches over the components the istio controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch t := c.(type) {
	case ristio.ConfiguredComponent:
		return extensions.Decorate(c, ri, e.variant, func(create, del []client.Object) ([]client.Object, []client.Object) {
			return modifyIstio(ri, t.GetConfig(), create, del)
		})
	default:
		return c
	}
}

// modifyIstio renders the waypoint L7 logging objects, or queues them for deletion
// when logging is off so an install that turned it off cleans up after itself.
func modifyIstio(ri render.Inputs, cfg *ristio.Configuration, create, del []client.Object) ([]client.Object, []client.Object) {
	objs := L7WaypointObjects(cfg.IstioNamespace, istioData(ri).l7CollectorImage)
	if cfg.Istio.WaypointLoggingEnabled() {
		return append(create, objs...), del
	}
	slices.Reverse(objs)
	return create, append(del, objs...)
}
