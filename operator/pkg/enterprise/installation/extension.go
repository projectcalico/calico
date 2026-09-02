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

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/typhaautoscaler"
	eoptions "github.com/projectcalico/calico/operator/pkg/enterprise/options"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/kubecontrollers"
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

// KubeControllersImage returns the Cloud build of the combined image, which carries
// behavior the mono image lacks. Every other install runs the plain Enterprise image.
func (e *Extension) KubeControllersImage() *components.Component {
	if !e.opts.Cloud {
		return nil
	}
	img := components.CalicoCloudImage()
	return &img
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
