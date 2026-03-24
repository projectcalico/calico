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

package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands"
)

func newCtlCommand() *cobra.Command {
	return &cobra.Command{
		Use:                "ctl",
		Short:              "Calico CLI tool for managing Calico resources",
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			runCalicoctl(args)
		},
	}
}

func runCalicoctl(args []string) {
	doc := `Usage:
  calicoctl [options] <command> [<args>...]

    create       Create a resource by file, directory or stdin.
    replace      Replace a resource by file, directory or stdin.
    apply        Apply a resource by file, directory or stdin.  This creates a resource
                 if it does not exist, and replaces a resource if it does exists.
    patch        Patch a preexisting resource in place.
    delete       Delete a resource identified by file, directory, stdin or resource type and
                 name.
    get          Get a resource identified by file, directory, stdin or resource type and
                 name.
    label        Add or update labels of resources.
    validate     Validate a resource by file, directory or stdin without applying it.
    ipam         IP address management.
    node         Calico node management.
    version      Display the version of this binary.
    datastore    Calico datastore management.
    cluster      Access cluster information.

Options:
  -h --help                    Show this screen.
  -l --log-level=<level>       Set the log level (one of panic, fatal, error,
                               warn, info, debug) [default: panic]
     --context=<context>       The name of the kubeconfig context to use.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The calicoctl command line tool is used to manage Calico network and security
  policy, to view and manage endpoint configuration, and to manage a Calico
  node instance.

  See 'calicoctl <command> --help' to read about a specific subcommand.
`

	versionSummary := "Run 'calicoctl version' to see version information."

	parser := &docopt.Parser{
		HelpHandler:   docopt.PrintHelpOnly,
		OptionsFirst:  true,
		SkipHelpFlags: false,
	}
	arguments, err := parser.ParseArgs(doc, args, versionSummary)
	if err != nil {
		if _, ok := err.(*docopt.UserError); ok {
			fmt.Printf("Invalid option: '%s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		}
		os.Exit(1)
	}

	if logLevel := arguments["--log-level"]; logLevel != nil {
		parsedLogLevel, err := logrus.ParseLevel(logLevel.(string))
		if err != nil {
			fmt.Printf("Unknown log level: %s, expected one of: \n"+
				"panic, fatal, error, warn, info, debug.\n", logLevel)
			os.Exit(1)
		} else {
			logrus.SetLevel(parsedLogLevel)
			logrus.Infof("Log level set to %v", parsedLogLevel)
		}
	}

	if context := arguments["--context"]; context != nil {
		_ = os.Setenv("K8S_CURRENT_CONTEXT", context.(string))
	}

	if arguments["<command>"] != nil {
		command := arguments["<command>"].(string)
		cmdArgs := append([]string{command}, arguments["<args>"].([]string)...)

		if allowMismatch, _ := arguments["--allow-version-mismatch"].(bool); allowMismatch {
			cmdArgs = append(cmdArgs, "--allow-version-mismatch")
		}

		var cmdErr error

		switch command {
		case "create":
			cmdErr = commands.Create(cmdArgs)
		case "replace":
			cmdErr = commands.Replace(cmdArgs)
		case "apply":
			cmdErr = commands.Apply(cmdArgs)
		case "patch":
			cmdErr = commands.Patch(cmdArgs)
		case "delete":
			cmdErr = commands.Delete(cmdArgs)
		case "get":
			cmdErr = commands.Get(cmdArgs)
		case "label":
			cmdErr = commands.Label(cmdArgs)
		case "validate":
			cmdErr = commands.Validate(cmdArgs)
		case "version":
			cmdErr = commands.Version(cmdArgs)
		case "node":
			cmdErr = commands.Node(cmdArgs)
		case "ipam":
			cmdErr = commands.IPAM(cmdArgs)
		case "cluster":
			cmdErr = commands.Cluster(cmdArgs)
		case "datastore":
			cmdErr = commands.Datastore(cmdArgs)
		default:
			cmdErr = fmt.Errorf("unknown command: %q\n%s", command, doc)
		}

		if cmdErr != nil {
			fmt.Fprintf(os.Stderr, "%s\n", massageCtlError(cmdErr))
			os.Exit(1)
		}
	}
}

func massageCtlError(err error) string {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "error unmarshaling JSON: while decoding JSON: json: ")

	unknownFieldRegexp := regexp.MustCompile(`unknown field "([^"]+)"`)
	if m := unknownFieldRegexp.FindStringSubmatch(msg); m != nil {
		msg = "field in document is not recognized or is in the wrong location: " + m[1]
	}

	return msg
}
