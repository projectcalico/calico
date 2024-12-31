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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

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
	metadataFile := filepath.Join(cfg.RepoRootDir, "metadata.mk")
	if err := loadMetadata(metadataFile); err != nil {
		logrus.WithError(err).Fatalf("Failed to load values from %s", metadataFile)
	}

	app := &cli.App{
		Name:     "release",
		Usage:    "a tool for building releases",
		Flags:    globalFlags,
		Commands: Commands(cfg),
	}

	// Run the app.
	if err := app.Run(os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running task")
	}
}

func loadMetadata(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open metadata file: %v", err)
	}
	defer file.Close()

	// Regex to split on either "=" or "?=" as the delimiter.
	delimiterRegex := regexp.MustCompile(`\s*(=|\?=)\s*`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments and empty lines.
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		parts := delimiterRegex.Split(line, 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid line in metadata file: %s", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Existing environment variables take precedence.
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read metadata file: %v", err)
	}
	return nil
}