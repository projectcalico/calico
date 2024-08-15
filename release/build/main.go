package main

import (
	"os"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/tasks"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
)

const (
	skipValidationFlag = "skip-validation"
)

var debug bool

func configureLogging() {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
}

// globalFlags are flags that are available to all sub-commands.
var globalFlags = []cli.Flag{
	&cli.BoolFlag{
		Name:        "debug",
		Usage:       "Enable verbose log output",
		Value:       false,
		Destination: &debug,
	},
}

func main() {
	cfg := config.LoadConfig()
	runner := registry.MustDockerRunner()

	app := &cli.App{
		Name:     "release",
		Usage:    "release is a tool for building Calico releases",
		Flags:    globalFlags,
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
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-build validation", Value: false},
			},
			Action: func(c *cli.Context) error {
				configureLogging()
				if !c.Bool(skipValidationFlag) {
					tasks.PreReleaseValidate(cfg)
				}
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
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: skipValidationFlag, Usage: "Skip pre-publish validation", Value: false},
			},
			Action: func(c *cli.Context) error {
				configureLogging()
				if !c.Bool(skipValidationFlag) {
					tasks.HashreleaseValidate(cfg)
				}
				tasks.OperatorHashreleasePush(runner, cfg)
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
				configureLogging()
				tasks.HashreleaseCleanRemote(cfg)
				return nil
			},
		},
	}
}
