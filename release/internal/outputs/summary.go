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

package outputs

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"
)

// StepSummary represents structured output for a release step.
// It is written to <baseDir>/summary/<version>/<step>.yaml after each release step.
type StepSummary struct {
	Status    string         `yaml:"status"`
	Started   time.Time      `yaml:"started"`
	Completed time.Time      `yaml:"completed"`
	Outputs   map[string]any `yaml:"outputs,omitempty"`
}

// SummaryOutputDir returns the base output directory for step summaries
// within the given repo root.
func SummaryOutputDir(repoRootDir string) string {
	return filepath.Join(repoRootDir, "release", "_output")
}

// WriteSummary writes a summary YAML file to <baseDir>/summary/<version>/<step>.yaml.
// Errors are returned but callers should log and continue — summary failure should not
// block the release.
func WriteSummary(baseDir, version, step string, s StepSummary) error {
	dir := filepath.Join(baseDir, "summary", version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshaling summary: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, step+".yaml"), data, 0o644)
}
