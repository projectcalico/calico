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

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGoldenConfigsParseWithBIRD validates that every compiled_templates
// scenario's bird.cfg (which includes the other 5 fragment files) parses
// successfully with a real BIRD binary using `bird -p -c`.
//
// The confd FV golden-file tests only do text comparison; they cannot catch
// configuration that is syntactically invalid for BIRD. This test closes that
// gap by parsing each generated config with BIRD itself.
//
// BIRD 3.x is required (channel-based config syntax). The binary is located
// via the BIRD_BIN environment variable, falling back to "bird" on PATH. When
// no BIRD binary is available the test is skipped, so it is a no-op in
// environments without BIRD (e.g. the default unit-test container) and an
// enforced check in CI jobs that provide a BIRD 3.x binary.
func TestGoldenConfigsParseWithBIRD(t *testing.T) {
	birdBin := os.Getenv("BIRD_BIN")
	if birdBin == "" {
		birdBin = "bird"
	}
	resolved, err := exec.LookPath(birdBin)
	if err != nil {
		t.Skipf("BIRD binary %q not found (set BIRD_BIN to enable); skipping BIRD config validation", birdBin)
	}
	t.Logf("Validating golden configs with BIRD binary: %s", resolved)

	goldenRoot := filepath.Join("compiled_templates")
	var birdCfgs []string
	err = filepath.Walk(goldenRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "bird.cfg" {
			birdCfgs = append(birdCfgs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk golden dir: %v", err)
	}
	if len(birdCfgs) == 0 {
		t.Fatal("no bird.cfg golden files found")
	}

	for _, cfg := range birdCfgs {
		cfg := cfg
		// Use the scenario directory name as the subtest name.
		name := filepath.Dir(cfg)
		t.Run(name, func(t *testing.T) {
			// `bird -p -c <file>` parses the config and exits 0 if valid.
			// Relative includes in bird.cfg resolve against its directory.
			out, err := exec.Command(resolved, "-p", "-c", cfg).CombinedOutput()
			if err != nil {
				t.Errorf("BIRD rejected %s:\n%s", cfg, string(out))
			}
		})
	}
}
