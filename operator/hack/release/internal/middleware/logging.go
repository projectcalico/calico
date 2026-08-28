// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	"path"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
	"github.com/urfave/cli/v3"
)

// LogPrettifier formats logrus caller information as "pkg.Func():file:line".
func LogPrettifier(f *runtime.Frame) (string, string) {
	filename := path.Base(f.File)
	funcSegments := strings.Split(f.Function, "/")
	return fmt.Sprintf("%s()", funcSegments[len(funcSegments)-1]), fmt.Sprintf("%s:%d", filename, f.Line)
}

// ConfigureLogging sets up logging to both stdout and a file.
func ConfigureLogging(c *cli.Command) {
	if debug := c.Bool("debug"); debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		CallerPrettyfier:       LogPrettifier,
		ForceColors:            true,
		PadLevelText:           true,
		DisableQuote:           true,
		DisableSorting:         true,
	})

	filename := strings.ReplaceAll(c.FullName(), " ", "-") + ".log"

	rotateFileHook, err := rotatefilehook.NewRotateFileHook(rotatefilehook.RotateFileConfig{
		Filename:   filename,
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
		Level:      logrus.DebugLevel,
		Formatter: &logrus.TextFormatter{
			DisableColors:          true,
			DisableLevelTruncation: true,
			CallerPrettyfier:       LogPrettifier,
			DisableSorting:         true,
		},
	})
	if err != nil {
		cli.HandleExitCoder(cli.Exit(fmt.Errorf("unable to create logrus hook for log file rotation: %w", err), 1))
	}

	logrus.AddHook(rotateFileHook)
}

// WithLogging wraps a cli.BeforeFunc with automatic log file configuration
// derived from the command's full name (e.g. "release branch" -> "release-branch.log").
func WithLogging(before cli.BeforeFunc) cli.BeforeFunc {
	return func(ctx context.Context, c *cli.Command) (context.Context, error) {
		ConfigureLogging(c)
		return before(ctx, c)
	}
}
