// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/node"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

// Node function is a switch to node related sub-commands
func Node(args []string) error {
	var err error
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> node <command> [<args>...]

    run          Run the Calico node container image.
    status       View the current status of a Calico node.
    diags        Gather a diagnostics bundle for a Calico node.
    checksystem  Verify the compute host is able to run a Calico node instance.

Options:
  -h --help      Show this screen.

Description:
  Node specific commands for <BINARY_NAME>.  These commands must be run directly on
  the compute host running the Calico node instance.

  See '<BINARY_NAME> node <command> --help' to read about a specific subcommand.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	var parser = &docopt.Parser{
		HelpHandler:   docopt.PrintHelpAndExit,
		OptionsFirst:  true,
		SkipHelpFlags: false,
	}
	arguments, err := parser.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if arguments["<command>"] == nil {
		return nil
	}

	command := arguments["<command>"].(string)
	args = append([]string{"node", command}, arguments["<args>"].([]string)...)

	switch command {
	case "status":
		return node.Status(args)
	case "diags":
		return node.Diags(args)
	case "checksystem":
		return node.Checksystem(args)
	case "run":
		return node.Run(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
