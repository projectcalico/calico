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

package config

import (
	"os"
	"testing"
)

func TestHealthPortDefaultDoesNotCollideWithListenPort(t *testing.T) {
	t.Setenv("GUARDIAN_VOLTRON_URL", "management.example:443")
	unsetEnv(t, "GUARDIAN_HEALTH_PORT")
	unsetEnv(t, "GUARDIAN_LISTEN_PORT")

	cfg, err := newConfig()
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if cfg.HealthPort != 9080 {
		t.Fatalf("HealthPort = %d, want 9080 (operator probes this port)", cfg.HealthPort)
	}
	if cfg.ListenPort != "8080" {
		t.Fatalf("ListenPort = %q, want 8080 (Voltron proxy listen port)", cfg.ListenPort)
	}
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
}
