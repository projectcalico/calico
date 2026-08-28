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

package middleware

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/tigera/operator/hack/release/internal/command"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

// ReleaseDir is the path to the release directory base relative to the repo root.
const ReleaseDir = "hack/release"

// StepSummary represents structured output for a release step.
// Written to <repoRoot>/hack/release/_output/summary/<key>/<step>.yaml,
// where <key> is a release version (e.g. v1.36.0) for release-* steps
// or a stream identifier (e.g. v1.36) for branch-* steps.
type StepSummary struct {
	Status    string         `yaml:"status"`
	Started   time.Time      `yaml:"started"`
	Completed time.Time      `yaml:"completed"`
	Outputs   map[string]any `yaml:"outputs,omitempty"`
}

// SummaryOutputDir returns the base output directory for step summaries.
func SummaryOutputDir(repoRootDir string) string {
	return filepath.Join(repoRootDir, ReleaseDir, "_output")
}

// WriteSummary writes a summary YAML file to <baseDir>/summary/<key>/<step>.yaml.
// key is a release version or stream identifier; step is the step name.
func WriteSummary(baseDir, key, step string, s StepSummary) error {
	dir := filepath.Join(baseDir, "summary", key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshaling summary: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, step+".yaml"), data, 0o644)
}

// SummaryAction is a command action that returns a key (version or stream),
// structured outputs, and an error.
type SummaryAction func(context.Context, *cli.Command) (string, map[string]any, error)

// WithSummary wraps a SummaryAction with timing, status, and summary file emission.
func WithSummary(step string, action SummaryAction) cli.ActionFunc {
	return withSummary(step, action, command.GitDir)
}

// withSummary is the testable core of WithSummary, parameterized over the
// repo-root resolver so tests can inject a temp dir.
func withSummary(step string, action SummaryAction, repoRootFn func() (string, error)) cli.ActionFunc {
	return func(ctx context.Context, c *cli.Command) error {
		started := time.Now()
		key, outputsMap, actionErr := action(ctx, c)

		status := "success"
		if actionErr != nil {
			status = "failure"
		}
		if key == "" {
			key = "unknown"
		}
		summary := StepSummary{
			Status:    status,
			Started:   started,
			Completed: time.Now(),
			Outputs:   outputsMap,
		}
		repoRoot, err := repoRootFn()
		if err != nil {
			logrus.WithError(err).Warn("Failed to determine repo root for summary")
			return actionErr
		}
		outputDir := SummaryOutputDir(repoRoot)
		if err := WriteSummary(outputDir, key, step, summary); err != nil {
			logrus.WithError(err).Warn("Failed to write summary file")
		}
		return actionErr
	}
}
