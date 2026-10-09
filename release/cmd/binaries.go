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

package main

import (
	"context"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/binaries"
)

var binariesSubCommands = func(cfg *Config) []*cli.Command {
	return []*cli.Command{
		binariesBuildCommand(cfg),
	}
}

func binariesCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:     "binaries",
		Usage:    "Build the binaries a release ships",
		Commands: binariesSubCommands(cfg),
	}
}

var (
	binariesBuildFlags  = []cli.Flag{hashreleaseFlag}
	binariesBuildAction = func(cfg *Config) func(ctx context.Context, c *cli.Command) error {
		return func(_ context.Context, c *cli.Command) error {
			configureLogging("binaries-build.log")
			ver, err := releaseVersion(cfg, c)
			if err != nil {
				return err
			}
			dest, err := outputDir(cfg, c, ver.FormattedString())
			if err != nil {
				return err
			}
			return binaries.Build(
				cfg.RepoRootDir, ver.FormattedString(),
				binaries.Release(dest),
				binaries.WithRunner(commandRunner),
				binaries.WithLogsDir(cfg.LogsDir),
			)
		}
	}
)

func binariesBuildCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "build",
		Usage:  "Build binaries",
		Flags:  binariesBuildFlags,
		Action: binariesBuildAction(cfg),
	}
}
