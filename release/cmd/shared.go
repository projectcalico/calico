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
	"io"
	"os"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"gopkg.in/natefinch/lumberjack.v2"

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

// configureLogging sets up logging to both stdout and a file.
func configureLogging(filename string) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	writers := []io.Writer{os.Stdout, &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
	}}

	logrus.SetOutput(io.MultiWriter(writers...))
}

// slackConfig returns a config for slack based on the CLI context.
func slackConfig(c *cli.Context) *slack.Config {
	return &slack.Config{
		Token:   c.String(slackTokenFlag.Name),
		Channel: c.String(slackChannelFlag.Name),
	}
}
