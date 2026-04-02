// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
)

var (
	// debug controls whether or not to emit debug level logging.
	debug bool

	// releaseOutputPath is the directory where all outputs are stored
	// relative to the repo root
	releaseOutputPath = []string{utils.ReleaseFolderName, "_output"}
)

func logPrettifier(f *runtime.Frame) (string, string) {
	filename := path.Base(f.File)
	funcSegments := strings.Split(f.Function, "/")
	return fmt.Sprintf("%s()", funcSegments[len(funcSegments)-1]), fmt.Sprintf("%s:%d", filename, f.Line)
}

// configureLogging sets up logging to both stdout and a file.
func configureLogging(filename string) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		CallerPrettyfier:       logPrettifier,
	})

	rotateFileHook, err := rotatefilehook.NewRotateFileHook(rotatefilehook.RotateFileConfig{
		Filename:   filename,
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
		Level:      logrus.DebugLevel,
		Formatter: &logrus.TextFormatter{
			DisableColors:          true,
			DisableLevelTruncation: true,
			CallerPrettyfier:       logPrettifier,
		},
	})
	if err != nil {
		panic(err)
	}

	logrus.AddHook(rotateFileHook)
}

// withLogging wraps a cli.ActionFunc with automatic log file configuration
// derived from the command's full name (e.g. "release prep" -> "release-prep.log").
func withLogging(action cli.ActionFunc) cli.ActionFunc {
	return func(ctx context.Context, c *cli.Command) error {
		cmdName := strings.TrimSpace(strings.TrimPrefix(c.FullName(), c.Root().Name))
		logFileName := strings.ReplaceAll(cmdName, " ", "-") + ".log"
		configureLogging(logFileName)
		return action(ctx, c)
	}
}

// SummaryAction is a command action that returns a version string,
// structured outputs, and an error. The version identifies the summary
// file path. Outputs are included in the summary YAML.
type SummaryAction func(context.Context, *cli.Command) (string, map[string]any, error)

// withSummary wraps a SummaryAction with timing, status, and summary file
// emission. The step name identifies the summary file (e.g. "release-prep").
// Summary write failures are logged but never mask the action error.
func withSummary(cfg *Config, step string, action SummaryAction) cli.ActionFunc {
	return func(ctx context.Context, c *cli.Command) error {
		started := time.Now()
		ver, outputsMap, actionErr := action(ctx, c)

		status := "success"
		if actionErr != nil {
			status = "failure"
		}
		if ver == "" {
			ver = "unknown"
		}
		summary := outputs.StepSummary{
			Status:    status,
			Started:   started,
			Completed: time.Now(),
			Outputs:   outputsMap,
		}
		outputDir := outputs.SummaryOutputDir(cfg.RepoRootDir)
		if err := outputs.WriteSummary(outputDir, ver, step, summary); err != nil {
			logrus.WithError(err).Warn("Failed to write summary file")
		}
		return actionErr
	}
}

// slackConfig returns a config for slack based on the CLI context.
func slackConfig(c *cli.Command) *slack.Config {
	return &slack.Config{
		Token:   c.String(slackTokenFlag.Name),
		Channel: c.String(slackChannelFlag.Name),
	}
}
