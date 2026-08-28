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

	"k8s.io/client-go/kubernetes"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// ClusterConnectionExtension is the variant's hook into the clusterconnection
// controller and the guardian components it renders.
type ClusterConnectionExtension interface {
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error)

	// ValidateAndDefault rejects fields the variant does not support and fills in
	// the ones it defaults.
	ValidateAndDefault(cr *operatorv1.ManagementClusterConnection) error
	// Watches registers the variant's watches. The clientset is for those that must
	// wait on a CRD.
	Watches(c ctrlruntime.Controller, cs kubernetes.Interface) error

	// Modify layers the variant onto a component the controller rendered.
	Modify(c render.Component, ri render.Inputs) render.Component
}

// noopClusterConnection runs the core operator's behavior unchanged.
type noopClusterConnection struct{}

func (noopClusterConnection) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	return ci, nil, nil
}

func (noopClusterConnection) Watches(ctrlruntime.Controller, kubernetes.Interface) error {
	return nil
}

// ValidateAndDefault rejects the Enterprise-only fields of the shared CRD.
func (noopClusterConnection) ValidateAndDefault(cr *operatorv1.ManagementClusterConnection) error {
	if cr.Spec.Impersonation != nil {
		return InvalidConfigf("ManagementClusterConnection.Spec.Impersonation must be unset when Installation.Spec.Variant = Calico")
	}
	if cr.Spec.TLS != nil && cr.Spec.TLS.CA == operatorv1.CATypePublic {
		return InvalidConfigf("Guardian CA cannot be public in Calico")
	}
	return nil
}

func (noopClusterConnection) Modify(c render.Component, _ render.Inputs) render.Component {
	return c
}
