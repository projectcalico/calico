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

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/render"
)

// IstioExtension is the variant's hook into the istio controller.
type IstioExtension interface {
	// PolicySyncRequired reports whether a variant feature needs Felix's policy-sync
	// socket, which the istio controller shares the FelixConfiguration field with.
	PolicySyncRequired(ctx context.Context, c client.Client) (bool, error)

	// Watches registers the watches the extension needs, so a change to an input
	// only the extension reads reconciles the Istio CR.
	Watches(c ctrlruntime.Controller) error

	// ExtendInputs resolves what the modifier needs but cannot read for itself.
	// ci.Status is set, for warnings. An error from Partialf leaves the returned
	// inputs usable: the controller renders with them, then degrades.
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, error)

	// Finalize cleans up what the extension created outside the objects the Istio CR
	// owns. The controller calls it while the CR is deleting, before its own cleanup,
	// and keeps the finalizer, retrying, until Finalize reports done. ci carries the
	// client and the status, with Terminating set.
	Finalize(ctx context.Context, ci controller.Inputs, instance *operatorv1.Istio) (done bool, err error)

	// Modify layers the variant onto a component the controller rendered.
	Modify(c render.Component, ri render.Inputs) render.Component
}

// noopIstio needs nothing of the shared FelixConfiguration field.
type noopIstio struct{}

func (noopIstio) PolicySyncRequired(context.Context, client.Client) (bool, error) {
	return false, nil
}

func (noopIstio) Watches(ctrlruntime.Controller) error {
	return nil
}

func (noopIstio) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, error) {
	return ci, nil
}

func (noopIstio) Modify(c render.Component, _ render.Inputs) render.Component {
	return c
}

func (noopIstio) Finalize(context.Context, controller.Inputs, *operatorv1.Istio) (bool, error) {
	return true, nil
}
