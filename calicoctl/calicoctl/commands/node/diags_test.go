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

package node

import (
	"testing"
)

// TestGetIPSetCommand tests the getIPSetCommand function returns appropriate commands for each runtime
func TestGetIPSetCommand(t *testing.T) {
	tests := []struct {
		name     string
		runtime  containerRuntime
		expected string
	}{
		{
			name:     "Docker runtime returns docker command",
			runtime:  runtimeDocker,
			expected: "docker run --rm --privileged --net=host calico/node ipset list",
		},
		{
			name:     "CRI-O runtime returns crictl command",
			runtime:  runtimeCRIO,
			expected: "crictl exec $(crictl ps --name calico-node -q | head -1) ipset list",
		},
		{
			name:     "Containerd runtime returns ctr command",
			runtime:  runtimeContainerd,
			expected: "ctr -n k8s.io task exec --exec-id diag-ipset $(ctr -n k8s.io c ls -q | grep calico-node | head -1) ipset list",
		},
		{
			name:     "Unknown runtime returns empty string",
			runtime:  runtimeUnknown,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getIPSetCommand(tt.runtime)
			if result != tt.expected {
				t.Errorf("getIPSetCommand(%v) = %q, want %q", tt.runtime, result, tt.expected)
			}
		})
	}
}

// TestContainerRuntimeConstants tests that runtime constants are defined correctly
func TestContainerRuntimeConstants(t *testing.T) {
	if runtimeUnknown != 0 {
		t.Errorf("runtimeUnknown should be 0, got %d", runtimeUnknown)
	}
	if runtimeDocker == runtimeUnknown {
		t.Error("runtimeDocker should not equal runtimeUnknown")
	}
	if runtimeContainerd == runtimeUnknown {
		t.Error("runtimeContainerd should not equal runtimeUnknown")
	}
	if runtimeCRIO == runtimeUnknown {
		t.Error("runtimeCRIO should not equal runtimeUnknown")
	}
}
