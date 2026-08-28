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

package whisker

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
	rwhisker "github.com/projectcalico/calico/operator/pkg/render/whisker"
)

// Extension is the Calico Enterprise behavior for the whisker controller.
type Extension struct {
	variant operatorv1.ProductVariant
}

var _ extensions.WhiskerExtension = &Extension{}

// New returns the whisker extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant) *Extension {
	return &Extension{variant: variant}
}

// Modify dispatches over the components the whisker controller renders.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	switch c.(type) {
	case *rwhisker.Component:
		return extensions.Decorate(c, ri, e.variant, deleteWhisker)
	default:
		return c
	}
}

// deleteWhisker moves everything whisker rendered to the delete list. Enterprise has
// no whisker, so an install upgraded from Calico cleans up after itself.
func deleteWhisker(create, del []client.Object) ([]client.Object, []client.Object) {
	return nil, append(del, create...)
}
