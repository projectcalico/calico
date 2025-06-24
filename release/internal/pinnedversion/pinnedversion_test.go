// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package pinnedversion

import (
	"testing"

	"github.com/projectcalico/calico/release/internal/registry"
)

func TestNormalizeComponent(t *testing.T) {
	for _, tt := range []struct {
		componentName string
		component     registry.Component
		expected      registry.Component
	}{
		// components in registry.ImageMap
		{
			componentName: "typha",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "typha",
			},
		},
		{
			componentName: "calicoctl",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "ctl",
			},
		},
		{
			componentName: "flannel",
			component: registry.Component{
				Version:  "v0.14.0",
				Registry: "quay.io",
			},
			expected: registry.Component{
				Version:  "v0.14.0",
				Image:    "coreos/flannel",
				Registry: "quay.io",
			},
		},
		{
			componentName: "flexvol",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "pod2daemon-flexvol",
			},
		},
		{
			componentName: "key-cert-provisioner",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "key-cert-provisioner",
			},
		},
		{
			componentName: "csi-node-driver-registrar",
			component: registry.Component{
				Version: "v1.0.0",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "node-driver-registrar",
			},
		},
		// components not in registry.ImageMap
		{
			componentName: "calico/cni",
			component: registry.Component{
				Version: "v1.0.0",
				Image:   "cni",
			},
			expected: registry.Component{
				Version: "v1.0.0",
				Image:   "cni",
			},
		},
	} {
		t.Run(tt.componentName, func(t *testing.T) {
			got := normalizeComponent(tt.componentName, tt.component)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}
