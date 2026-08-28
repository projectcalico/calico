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
	"github.com/projectcalico/calico/operator/pkg/render"
)

// WhiskerExtension is the variant's hook into the components the whisker controller
// renders.
type WhiskerExtension interface {
	// Modify layers the variant onto a component the controller rendered.
	Modify(c render.Component, ri render.Inputs) render.Component
}

// noopWhisker runs the core operator's behavior unchanged.
type noopWhisker struct{}

func (noopWhisker) Modify(c render.Component, _ render.Inputs) render.Component {
	return c
}
