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

package extensions

import (
	"context"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// WhiskerExtension is the variant's hook into the components the whisker controller
// renders.
type WhiskerExtension interface {
	// ValidateAndDefault unsets the fields the variant does not render, reporting each
	// one it drops. Pass the copy the controller renders from, not the CR it writes back.
	ValidateAndDefault(cr *operatorv1.Whisker, st status.StatusManager) error

	// Watches registers the variant's watches.
	Watches(c ctrlruntime.Controller) error

	// ExtendInputs does the reconcile work render cannot, returning keypairs for the
	// controller to manage. A variant that deploys whisker-backend alone reports it
	// through a whisker.RenderData in the render inputs.
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error)

	// Modify layers the variant onto a component the controller rendered.
	Modify(c render.Component, ri render.Inputs) render.Component
}

// noopWhisker runs the core operator's behavior unchanged.
type noopWhisker struct{}

// ValidateAndDefault keeps the CR as written, since Calico renders every Whisker field.
func (noopWhisker) ValidateAndDefault(_ *operatorv1.Whisker, _ status.StatusManager) error {
	return nil
}

func (noopWhisker) Watches(ctrlruntime.Controller) error {
	return nil
}

func (noopWhisker) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	return ci, nil, nil
}

func (noopWhisker) Modify(c render.Component, _ render.Inputs) render.Component {
	return c
}
