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
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

// Config contains overall configuration for the release tool inputs and outputs
type Config struct {
	// RepoRootDir is the root directory for this repository
	RepoRootDir string

	// OutputDir is the directory where all outputs are stored
	OutputDir string

	// TmpDir is the directory for temporary files
	TmpDir string
}

// loadConfig loads the configuration for the release tool.
func loadConfig() (*Config, error) {
	repoRoot, err := command.GitDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get repo root dir: %w", err)
	}

	config := &Config{
		RepoRootDir: repoRoot,
		OutputDir:   filepath.Join(repoRoot, utils.ReleaseFolderName, "_output"),
		TmpDir:      filepath.Join(repoRoot, utils.ReleaseFolderName, "tmp"),
	}
	return config, nil
}

// Commands returns the list of top-level program commands
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

	logutils.ConfigureFormatter("release")

	app := &cli.Command{
		Name:                  "release",
		Usage:                 fmt.Sprintf("release tool for %s", utils.ProductName),
		Flags:                 globalFlags,
		Commands:              Commands(cfg),
		EnableShellCompletion: true,
	}

	// Run the app.
	if err := app.Run(context.Background(), os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running app")
	}
}
