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

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/imageoverride"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// InstallationExtension is the variant's hook into the installation controller and
// the components it renders.
type InstallationExtension interface {
	// ExtendInputs does the reconcile work render cannot, returning keypairs for the
	// controller to manage. Rejects unsupported config with InvalidConfigf.
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error)

	// Watches registers the watches the extension needs.
	Watches(c ctrlruntime.Controller) error

	// DefaultFelixConfiguration defaults FelixConfiguration fields, reporting whether
	// it changed fc. It runs before Felix defaulting persists.
	DefaultFelixConfiguration(install *operatorv1.InstallationSpec, fc *v3.FelixConfiguration) (bool, error)

	// ProductVersion is the version the operator writes to the Installation status.
	ProductVersion() string

	// Images overrides the images the rendered components resolve to.
	Images() *imageoverride.Overrides

	// Modify layers the variant onto a component the controller rendered.
	Modify(c render.Component, ri render.Inputs) render.Component
}

// noopInstallation runs the core operator's behavior unchanged.
type noopInstallation struct{}

func (noopInstallation) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	return ci, nil, nil
}

func (noopInstallation) Watches(ctrlruntime.Controller) error {
	return nil
}

func (noopInstallation) DefaultFelixConfiguration(*operatorv1.InstallationSpec, *v3.FelixConfiguration) (bool, error) {
	return false, nil
}

func (noopInstallation) ProductVersion() string {
	return components.CalicoRelease
}

func (noopInstallation) Images() *imageoverride.Overrides {
	return nil
}

func (noopInstallation) Modify(c render.Component, _ render.Inputs) render.Component {
	return c
}
