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
	"fmt"
	"path"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
)

var (
	// debug controls whether or not to emit debug level logging.
	debug bool

	// releaseNotesDir is the directory where release notes are stored
	releaseNotesDir = "release-notes"

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

// slackConfig returns a config for slack based on the CLI context.
func slackConfig(c *cli.Command) *slack.Config {
	return &slack.Config{
		Token:   c.String(slackTokenFlag.Name),
		Channel: c.String(slackChannelFlag.Name),
	}
}
