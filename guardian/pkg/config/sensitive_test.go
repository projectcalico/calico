// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package config

import (
	"strings"
	"testing"
)

func TestConfigStringOmitsEndpointCredentials(t *testing.T) {
	endpoint := "https://test-user:test-password@example.com/path?token=test-token#test-fragment"
	cfg := Config{VoltronURL: endpoint, K8sEndpoint: endpoint, GoldmaneEndpoint: endpoint}
	got := cfg.String()
	for _, secret := range []string{"test-user", "test-password", "test-token", "test-fragment"} {
		if strings.Contains(got, secret) {
			t.Fatal("configuration string contains credential")
		}
	}
	if cfg.VoltronURL != endpoint || cfg.K8sEndpoint != endpoint || cfg.GoldmaneEndpoint != endpoint {
		t.Fatal("redaction mutated configuration")
	}
}
