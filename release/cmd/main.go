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
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/release/internal/command"
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

type Config struct {
	// RepoRootDir is the root directory for this repository
	RepoRootDir string `envconfig:"REPO_ROOT"`

	// OutputDir is the directory where all outputs are stored
	OutputDir string

	// TmpDir is the directory for temporary files
	TmpDir string
}

// loadConfig loads the configuration for the release tool.
func loadConfig() (*Config, error) {
	config := &Config{
		RepoRootDir: os.Getenv("REPO_ROOT"),
	}
	if config.RepoRootDir == "" {
		dir, err := command.GitDir("")
		if err != nil {
			return nil, fmt.Errorf("failed to get repo root dir: %w", err)
		}
		config.RepoRootDir = dir
	}
	if config.OutputDir == "" {
		config.OutputDir = filepath.Join(config.RepoRootDir, utils.ReleaseFolderName, "_output")
	}
	config.TmpDir = filepath.Join(config.RepoRootDir, utils.ReleaseFolderName, "tmp")
	return config, nil
}

func configureLogging(filename string) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// Set up logging to both stdout as well as a file.
	writers := []io.Writer{os.Stdout, &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
	}}
	logrus.SetOutput(io.MultiWriter(writers...))
}

func Commands(cfg *Config) []*cli.Command {
	return []*cli.Command{
		hashreleaseCommand(cfg),
		releaseCommand(cfg),
		branchCommand(cfg),
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	app := &cli.App{
		Name:     "release",
		Usage:    fmt.Sprintf("a tool for building %s releases", utils.DisplayProductName()),
		Flags:    globalFlags,
		Commands: Commands(cfg),
	}

	// Run the app.
	if err := app.Run(os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running task")
	}
}

func slackConfig(c *cli.Context) *slack.Config {
	return &slack.Config{
		Token:   c.String(slackTokenFlag.Name),
		Channel: c.String(slackChannelFlag.Name),
	}
}
