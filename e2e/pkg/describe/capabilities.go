// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package describe

import (
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/capability"
)

// requiresKey is the label key specs declare preconditions under.
const requiresKey = "Requires"

// Requires marks a spec as needing a capability. A lane selects the spec only
// if its cluster fragments provide every capability the spec requires.
func Requires(c capability.Capability) any {
	return framework.WithLabel(requiresKey + ":" + string(c))
}

// RunsAnywhere declares that a spec needs no capability, so it runs on every
// lane whose suites select it. It adds no label; it exists so that having no
// requirements is a visible choice rather than an omission.
func RunsAnywhere() any {
	return []any{}
}
