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

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
)

// IstioExtension is the variant's hook into the istio controller.
type IstioExtension interface {
	// PolicySyncRequired reports whether a variant feature needs Felix's policy-sync
	// socket, which the istio controller shares the FelixConfiguration field with.
	PolicySyncRequired(ctx context.Context, c client.Client) (bool, error)

	// Images overrides the images the istio render resolves.
	Images() *imageoverride.Overrides

	// ExtendInputs resolves what the modifier needs but cannot read for itself.
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, error)

	// Modify layers the variant onto a component the controller rendered.
	Modify(c render.Component, ri render.Inputs) render.Component
}

// noopIstio needs nothing of the shared FelixConfiguration field.
type noopIstio struct{}

func (noopIstio) PolicySyncRequired(context.Context, client.Client) (bool, error) {
	return false, nil
}

func (noopIstio) Images() *imageoverride.Overrides {
	return nil
}

func (noopIstio) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, error) {
	return ci, nil
}

func (noopIstio) Modify(c render.Component, _ render.Inputs) render.Component {
	return c
}
