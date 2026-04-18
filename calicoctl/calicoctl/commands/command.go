// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package commands

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// MassageError cleans up error messages for user display. In particular it
// strips the confusing "error unmarshaling JSON" prefix that surfaces from
// YAML unmarshaling and rewrites `unknown field "X"` into a friendlier form.
func MassageError(err error) string {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "error unmarshaling JSON: while decoding JSON: json: ")

	unknownFieldRegexp := regexp.MustCompile(`unknown field "([^"]+)"`)
	if m := unknownFieldRegexp.FindStringSubmatch(msg); m != nil {
		msg = "field in document is not recognized or is in the wrong location: " + m[1]
	}
	return msg
}

// wrapRunEWithMassageError walks cmd and its subcommands, wrapping each
// non-nil RunE so that any error it returns has MassageError applied before
// bubbling up to cobra's SilenceErrors+SilenceUsage path. Callers of Execute()
// print the returned error directly, so without this wrapping the calicoctl
// YAML/JSON error UX would regress when run under the combined calico binary's
// ctl subcommand.
func wrapRunEWithMassageError(cmd *cobra.Command) {
	for _, sub := range cmd.Commands() {
		wrapRunEWithMassageError(sub)
	}
	if original := cmd.RunE; original != nil {
		cmd.RunE = func(c *cobra.Command, args []string) error {
			err := original(c, args)
			if err == nil {
				return nil
			}
			return errors.New(MassageError(err))
		}
	}
}

// NewCommand returns a cobra command tree for calicoctl.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ctl",
		Short: "Calico CLI tool for managing Calico resources",
		Long: `The calicoctl command line tool is used to manage Calico network and security
policy, to view and manage endpoint configuration, and to manage a Calico
node instance.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags.
	cmd.PersistentFlags().StringP("log-level", "l", "panic", "Set the log level (panic, fatal, error, warn, info, debug)")
	cmd.PersistentFlags().String("context", "", "The name of the kubeconfig context to use")
	cmd.PersistentFlags().Bool("allow-version-mismatch", false, "Allow client and cluster versions mismatch")

	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		logLevel, _ := cmd.Flags().GetString("log-level")
		parsedLevel, err := logrus.ParseLevel(logLevel)
		if err != nil {
			return fmt.Errorf("unknown log level: %s, expected one of: panic, fatal, error, warn, info, debug", logLevel)
		}
		logrus.SetLevel(parsedLevel)

		if context, _ := cmd.Flags().GetString("context"); context != "" {
			_ = os.Setenv("K8S_CURRENT_CONTEXT", context)
		}
		return nil
	}

	// CRUD commands.
	cmd.AddCommand(
		newCreateCommand(),
		newApplyCommand(),
		newReplaceCommand(),
		newDeleteCommand(),
		newGetCommand(),
		newPatchCommand(),
		newLabelCommand(),
		newValidateCommand(),
	)

	// Router commands.
	cmd.AddCommand(
		newIPAMCommand(),
		newNodeCommand(),
		newDatastoreCommand(),
		newClusterCommand(),
	)

	// Version.
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Display the version of this binary",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Bridge to the existing docopt-based Version function.
			synthArgs := []string{"version"}
			if config, _ := cmd.Flags().GetString("config"); config != "" {
				synthArgs = append(synthArgs, "--config="+config)
			}
			if poll, _ := cmd.Flags().GetString("poll"); poll != "" {
				synthArgs = append(synthArgs, "--poll="+poll)
			}
			if clientOnly, _ := cmd.Flags().GetBool("client"); clientOnly {
				synthArgs = append(synthArgs, "--client")
			}
			if allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch"); allowMismatch {
				synthArgs = append(synthArgs, "--allow-version-mismatch")
			}
			return Version(synthArgs)
		},
	}
	versionCmd.Flags().StringP("config", "c", "", "Path to the file containing connection configuration.")
	versionCmd.Flags().String("poll", "", "Poll for changes to the cluster information at a frequency specified using POLL duration.")
	versionCmd.Flags().Bool("client", false, "Display the client version only.")
	cmd.AddCommand(versionCmd)

	wrapRunEWithMassageError(cmd)
	return cmd
}

// argsFromCRUDFlags builds the map[string]any expected by ExecuteConfigCommand
// from cobra flag values. This bridges cobra flags to the existing common code
// without requiring changes to ExecuteConfigCommand.
func argsFromCRUDFlags(cmd *cobra.Command, positionalArgs []string) map[string]any {
	args := map[string]any{}

	// All CRUD commands share these flags.
	args["--filename"], _ = cmd.Flags().GetString("filename")
	args["--recursive"], _ = cmd.Flags().GetBool("recursive")
	args["--skip-empty"], _ = cmd.Flags().GetBool("skip-empty")
	args["--config"], _ = cmd.Flags().GetString("config")
	args["--namespace"], _ = cmd.Flags().GetString("namespace")
	args["--context"], _ = cmd.Flags().GetString("context")
	args["--allow-version-mismatch"], _ = cmd.Flags().GetBool("allow-version-mismatch")

	// Normalize empty strings to nil for fields the common code checks with != nil.
	if args["--filename"] == "" {
		args["--filename"] = nil
	}
	if args["--config"] == "" {
		args["--config"] = nil
	}
	if args["--namespace"] == "" {
		args["--namespace"] = nil
	}
	if args["--context"] == "" {
		args["--context"] = nil
	}

	// Positional args: <KIND> and <NAME> for get/delete, not used for file-based commands.
	if len(positionalArgs) > 0 {
		args["<KIND>"] = positionalArgs[0]
		if len(positionalArgs) > 1 {
			args["<NAME>"] = positionalArgs[1:]
		} else {
			args["<NAME>"] = []string{}
		}
	}

	return args
}
