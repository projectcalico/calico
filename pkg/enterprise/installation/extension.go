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

package installation

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/typhaautoscaler"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
)

// Extension is the Calico Enterprise behavior for the installation controller and
// the components it renders.
type Extension struct {
	variant operatorv1.ProductVariant
	opts    eoptions.Options

	// typhaAutoscaler scales the non-cluster-host Typha deployment. Nil until the
	// first reconcile that sees a NonClusterHost resource.
	typhaAutoscaler *typhaautoscaler.Autoscaler
}

var _ extensions.InstallationExtension = &Extension{}

// New returns the installation extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant, opts eoptions.Options) *Extension {
	return &Extension{variant: variant, opts: opts}
}

// RegisterImages adds the images the installation controller's components resolve.
func RegisterImages(o *imageoverride.Overrides, variant operatorv1.ProductVariant, opts eoptions.Options) {
	o.Register(variant, render.ComponentNameNode, components.ComponentTigeraNode)

	// The node component renders the cni-plugins init container; its image resolves
	// through its own override key.
	o.Register(variant, render.ComponentNameCNIPlugins, components.ComponentTigeraCNIPlugins)

	if opts.Cloud {
		// Calico Cloud runs kube-controllers from the combined image, which carries the
		// Cloud behavior the mono image lacks.
		o.Register(variant, render.ComponentNameKubeControllers, components.CalicoCloudImage())
	}
}

// Modify dispatches over the components the installation controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch comp := c.(type) {
	case render.NodeComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyNode(ri, objs, del)
		})
	case render.TyphaComponent:
		cfg := comp.TyphaConfig()
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyTypha(ri, cfg, objs, del)
		})
	case kubecontrollers.CalicoComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyKubeControllers(ri, objs, del)
		})
	case kubecontrollers.CalicoPolicyComponent:
		return extensions.Decorate(c, ri, e.variant, func(objs, del []client.Object) ([]client.Object, []client.Object) {
			return modifyKubeControllersPolicy(ri, objs, del)
		})
	default:
		return c
	}
}
