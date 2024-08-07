package main

import (
	"os"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/tasks"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
)

func main() {
	cfg := config.LoadConfig()
	runner := registry.MustDockerRunner()

	app := &cli.App{
		Name:     "release",
		Usage:    "release is a tool for building Calico releases",
		Commands: []*cli.Command{},
	}

	// Add sub-commands below.

	// The hashrelease command suite is used to build and publish hashreleases, as well as
	// to interact with the hashrelease server.
	app.Commands = append(app.Commands, &cli.Command{
		Name:        "hashrelease",
		Aliases:     []string{"hr"},
		Usage:       "Build and publish hashreleases.",
		Subcommands: hashrelaseSubCommands(cfg, runner),
	})

	// Run the app.
	if err := app.Run(os.Args); err != nil {
		logrus.WithError(err).Fatal("Error running task")
	}
}

func hashrelaseSubCommands(cfg *config.Config, runner *registry.DockerRunner) []*cli.Command {
	return []*cli.Command{
		// The build command is used to produce a new local hashrelease in the output directory.
		{
			Name:  "build",
			Usage: "Build a hashrelease locally in output/",
			Action: func(c *cli.Context) error {
				tasks.PreReleaseValidate(cfg)
				tasks.PinnedVersion(cfg)
				tasks.OperatorHashreleaseBuild(runner, cfg)
				tasks.HashreleaseBuild(cfg)
				tasks.ReleaseNotes(cfg)
				logrus.Infof("%s build complete.", cfg.ReleaseType())
				return nil
			},
		},

		// The publish command is used to publish a locally built hashrelease to the hashrelease server.
		{
			Name:  "publish",
			Usage: "Publish hashrelease from output/ to hashrelease server",
			Action: func(c *cli.Context) error {
				tasks.HashreleaseValidate(cfg)
				tasks.HashreleasePush(cfg)
				return nil
			},
		},

		// The garbage-collect command is used to clean up older hashreleases from the hashrelease server.
		{
			Name:    "garbage-collect",
			Usage:   "Clean up older hashreleases",
			Aliases: []string{"gc"},
			Action: func(c *cli.Context) error {
				tasks.HashreleaseCleanRemote(cfg)
				return nil
			},
		},
	}
}
