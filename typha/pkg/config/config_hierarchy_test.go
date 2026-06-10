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

package config_test

import (
	"testing"

	"github.com/projectcalico/calico/typha/pkg/config"
)

// load applies the given env-style key/values to a fresh Config and returns it.
func load(t *testing.T, kvs map[string]string) *config.Config {
	t.Helper()
	cfg := config.New()
	if _, err := cfg.UpdateFrom(kvs, config.EnvironmentVariable); err != nil {
		t.Fatalf("UpdateFrom returned error: %v", err)
	}
	return cfg
}

func TestHierarchyConfig_Defaults(t *testing.T) {
	cfg := config.New()
	if cfg.HierarchyEnabled {
		t.Error("HierarchyEnabled should default to false")
	}
	if cfg.UpstreamAddr != "" {
		t.Errorf("UpstreamAddr should default to empty, got %q", cfg.UpstreamAddr)
	}
	if cfg.UpstreamReadTimeout.Seconds() != 30 {
		t.Errorf("UpstreamReadTimeout should default to 30s, got %v", cfg.UpstreamReadTimeout)
	}
	if cfg.UpstreamWriteTimeout.Seconds() != 10 {
		t.Errorf("UpstreamWriteTimeout should default to 10s, got %v", cfg.UpstreamWriteTimeout)
	}
	if cfg.UpstreamK8sPortName != "calico-typha" {
		t.Errorf("UpstreamK8sPortName should default to calico-typha, got %q", cfg.UpstreamK8sPortName)
	}
	// Validation of a default config must pass (feature off).
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config failed validation: %v", err)
	}
}

func TestHierarchyConfig_Parse(t *testing.T) {
	cfg := load(t, map[string]string{
		"HierarchyEnabled":     "true",
		"UpstreamAddr":         "typha-leader:5473",
		"UpstreamReadTimeout":  "45",
		"UpstreamWriteTimeout": "15",
	})
	if !cfg.HierarchyEnabled {
		t.Error("HierarchyEnabled should be true")
	}
	if cfg.UpstreamAddr != "typha-leader:5473" {
		t.Errorf("UpstreamAddr = %q", cfg.UpstreamAddr)
	}
	if cfg.UpstreamReadTimeout.Seconds() != 45 {
		t.Errorf("UpstreamReadTimeout = %v", cfg.UpstreamReadTimeout)
	}
}

func TestHierarchyValidation(t *testing.T) {
	tests := []struct {
		name    string
		kvs     map[string]string
		wantErr bool
	}{
		{
			name:    "hierarchy off, no upstream: ok",
			kvs:     map[string]string{"HierarchyEnabled": "false"},
			wantErr: false,
		},
		{
			name:    "hierarchy on, static upstream: ok",
			kvs:     map[string]string{"HierarchyEnabled": "true", "UpstreamAddr": "host:5473"},
			wantErr: false,
		},
		{
			name:    "hierarchy on, k8s service upstream: ok",
			kvs:     map[string]string{"HierarchyEnabled": "true", "UpstreamK8sServiceName": "calico-typha-leader"},
			wantErr: false,
		},
		{
			name:    "hierarchy on, no upstream: error",
			kvs:     map[string]string{"HierarchyEnabled": "true"},
			wantErr: true,
		},
		{
			name: "hierarchy on, both static and service upstream: error",
			kvs: map[string]string{
				"HierarchyEnabled":       "true",
				"UpstreamAddr":           "host:5473",
				"UpstreamK8sServiceName": "calico-typha-leader",
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := load(t, tc.kvs)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestUpstreamTLSValidation checks the "all or nothing (except CN/URISAN)" rule
// for the client-side TLS params.  We use non-file-existence-checked values by
// only setting CN/URISAN-adjacent fields where possible; since the file params
// require existing files, we assert on the cross-field rule by setting the
// server identity but omitting key material.
func TestUpstreamTLSValidation_PartialIsError(t *testing.T) {
	cfg := config.New()
	// Set only the server identity (no key/cert/ca files). requiringUpstreamTLS
	// becomes true, so validation must complain that the rest are missing.
	if _, err := cfg.UpdateFrom(map[string]string{
		"UpstreamServerCN": "typha-leader",
	}, config.EnvironmentVariable); err != nil {
		t.Fatalf("UpdateFrom: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for partial upstream TLS config, got nil")
	}
}
