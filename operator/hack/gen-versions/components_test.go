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

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestRenderRequiresTemplateComponents(t *testing.T) {
	tests := []struct {
		name     string
		tpl      string
		versions string
		omit     string
	}{
		{
			name:     "calico",
			tpl:      osVersionsTpl,
			versions: "../../config/calico_versions.yml",
			omit:     "node",
		},
		{
			name:     "enterprise",
			tpl:      eeVersionsTpl,
			versions: "../../config/enterprise_versions.yml",
			omit:     "manager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			vz, err := GetComponents(tt.versions)
			if err != nil {
				t.Fatalf("failed to read %s: %v", tt.versions, err)
			}
			if err := render(io.Discard, tt.tpl, vz); err != nil {
				t.Fatalf("render of %s failed: %v", tt.versions, err)
			}

			trimmed, err := GetComponents(versionsWithout(t, tt.versions, tt.omit))
			if err != nil {
				t.Fatalf("failed to read trimmed versions file: %v", err)
			}
			err = render(io.Discard, tt.tpl, trimmed)
			if err == nil {
				t.Fatalf("render succeeded with component %q missing", tt.omit)
			}
			if !strings.Contains(err.Error(), tt.omit) {
				t.Errorf("error %q does not name the missing component %q", err, tt.omit)
			}
		})
	}
}

// versionsWithout writes a copy of a versions file with one component removed and
// returns its path.
func versionsWithout(t *testing.T, versionsPath, omit string) string {
	t.Helper()

	release, err := readComponents(versionsPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", versionsPath, err)
	}
	if _, ok := release.Components[omit]; !ok {
		t.Fatalf("%s has no component %q to remove", versionsPath, omit)
	}
	delete(release.Components, omit)

	out, err := yaml.Marshal(release)
	if err != nil {
		t.Fatalf("failed to marshal versions: %v", err)
	}

	path := filepath.Join(t.TempDir(), filepath.Base(versionsPath))
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}
