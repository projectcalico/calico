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

package main

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/tigera/operator/hack/release/internal/command"
)

func main() {
	version, err := command.GitVersion()
	if err != nil {
		logrus.WithError(err).Fatal("Could not determine git version")
	}

	cmd := app(version)

	// Run the app.
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running command")
	}
}

// Create the CLI app with the given version.
func app(version string) *cli.Command {
	return &cli.Command{
		Name:    "release",
		Usage:   "CLI tool for releasing operator",
		Version: version,
		Commands: []*cli.Command{
			buildCommand,
			publishCommand,
			branchCommand,
			prepCommand,
			publicCommand,
			releaseNotesCommand,
			releaseFromCommand,
		},
		Flags: []cli.Flag{
			gitRemoteFlag,
			gitRepoFlag,
			debugFlag,
		},
		EnableShellCompletion: true,
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			if c.Bool(debugFlag.Name) {
				logrus.SetLevel(logrus.DebugLevel)
			}
			return ctx, nil
		},
	}
}
