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

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/utils"
)

var (
	// debug controls whether or not to emit debug level logging.
	debug bool

	// releaseNotesDir is the directory where release notes are stored
	releaseNotesDir = "release-notes"
)

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

type Commands interface {
	Subcommands() []*cli.Command
}

type CalicoCommands struct {
	cfg *config.Config
}

func (c *CalicoCommands) Subcommands() []*cli.Command {
	return []*cli.Command{
		// The hashrelease command suite is used to build and publish hashreleases,
		// as well as to interact with the hashrelease server.
		{
			Name:        "hashrelease",
			Aliases:     []string{"hr"},
			Usage:       "Build and publish hashreleases.",
			Subcommands: hashreleaseSubCommands(c.cfg),
		},

		// The release command suite is used to build and publish official Calico releases.
		{
			Name:        "release",
			Aliases:     []string{"rel"},
			Usage:       "Build and publish official Calico releases.",
			Subcommands: releaseSubCommands(c.cfg),
		},

		// The branch command suite is used to manage branches.
		{
			Name:        "branch",
			Aliases:     []string{"br"},
			Usage:       "Manage branches.",
			Subcommands: branchSubCommands(c.cfg),
		},
	}
}

func NewCommands(cfg *config.Config) Commands {
	return &CalicoCommands{cfg: cfg}
}

func main() {
	cfg := config.LoadConfig()

	app := &cli.App{
		Name:     "release",
		Usage:    fmt.Sprintf("a tool for building %s releases", utils.DisplayProductName()),
		Flags:    globalFlags,
		Commands: []*cli.Command{},
	}

	// Add sub-commands below.
	subcommands := NewCommands(cfg).Subcommands()
	app.Commands = append(app.Commands, subcommands...)

	// Run the app.
	if err := app.Run(os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running task")
	}
}
