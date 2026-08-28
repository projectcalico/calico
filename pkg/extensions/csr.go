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

	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// CSRExtension is the variant's hook into the CSR controller.
type CSRExtension interface {
	// ExtendInputs stashes the variant's render.CSRData in the render inputs.
	ExtendInputs(ctx context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error)

	// Watches registers the variant's watches.
	Watches(c ctrlruntime.Controller) error
}

// noopCSR runs the core operator's behavior unchanged.
type noopCSR struct{}

func (noopCSR) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	return ci, nil, nil
}

func (noopCSR) Watches(ctrlruntime.Controller) error {
	return nil
}
