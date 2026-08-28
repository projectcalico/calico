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

	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// APIServerExtension is the variant's hook into the apiserver controller.
type APIServerExtension interface {
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error)
	Watches(c ctrlruntime.Controller) error

	// Modify layers the variant onto a component the controller rendered.
	Modify(c render.Component, ri render.Inputs) render.Component
}

// noopAPIServer runs the core operator's behavior unchanged.
type noopAPIServer struct{}

func (noopAPIServer) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	return ci, nil, nil
}

func (noopAPIServer) Watches(ctrlruntime.Controller) error {
	return nil
}

func (noopAPIServer) Modify(c render.Component, _ render.Inputs) render.Component {
	return c
}
