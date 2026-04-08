// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import "testing"

func TestTTLSecurityTemplates(t *testing.T) {
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
	}{
		{"explicit_node", "ttl_security/explicit_node/input.yaml", "ttl_security/explicit_node"},
		{"peer_selector", "ttl_security/peer_selector/input.yaml", "ttl_security/peer_selector"},
		{"global", "ttl_security/global/input.yaml", "ttl_security/global"},
	}

	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					runConfdTest(t, be, tc.inputYAML, tc.goldenDir)
				})
			}
		})
	}
}
