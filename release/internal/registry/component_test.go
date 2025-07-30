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

package registry

import (
	"testing"
)

func TestComponentString(t *testing.T) {
	for _, tc := range []struct {
		name      string
		component Component
		expected  string
	}{
		{
			name: "without registry",
			component: Component{
				Version: "1.2.3",
				Image:   "calico/node",
			},
			expected: "calico/node:1.2.3",
		},
		{
			name: "with registry",
			component: Component{
				Version:  "1.2.3",
				Image:    "calico/node",
				Registry: "docker.io",
			},
			expected: "docker.io/calico/node:1.2.3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.component.String(); got != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestOperatorComponentInitImage(t *testing.T) {
	c := OperatorComponent{
		Component: Component{
			Version:  "1.2.3",
			Image:    "nameprefix/operator",
			Registry: "quay.io",
		},
	}
	want := Component{
		Version:  "1.2.3",
		Image:    "nameprefix/operator-init",
		Registry: "quay.io",
	}
	got := c.InitImage()
	if got != want {
		t.Errorf("expected init image %s, got %s", want.String(), got.String())
	}
}
