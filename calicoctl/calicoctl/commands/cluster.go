// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/cluster"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
)

// Cluster includes any cluster-level subcommands.
func Cluster(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl cluster <command> [<args>...]

    diags            Collect snapshot of diagnostic info and logs related to Calico at the cluster-level.

Options:
  -h --help      Show this screen.

Description:
  Commands for accessing Cluster related information.

  See 'calicoctl cluster <command> --help' to read about a specific subcommand.`

	var parser = &docopt.Parser{
		HelpHandler:   docopt.PrintHelpAndExit,
		OptionsFirst:  true,
		SkipHelpFlags: false,
	}
	arguments, err := parser.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}
	if arguments["<command>"] == nil {
		return nil
	}

	command := arguments["<command>"].(string)
	args = append([]string{"cluster", command}, arguments["<args>"].([]string)...)

	switch command {
	case "diags":
		return cluster.Diags(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
