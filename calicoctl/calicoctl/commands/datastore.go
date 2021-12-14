// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/datastore"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

// Datastore function is a switch to datastore related sub-commands
func Datastore(args []string) error {
	var err error
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> datastore <command> [<args>...]

    migrate  Migrate the contents of an etcdv3 datastore to a Kubernetes datastore.

Options:
  -h --help      Show this screen.

Description:
  Datastore specific commands for <BINARY_NAME>.

  See '<BINARY_NAME> datastore <command> --help' to read about a specific subcommand.
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
	args = append([]string{"datastore", command}, arguments["<args>"].([]string)...)

	switch command {
	case "migrate":
		return datastore.Migrate(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
