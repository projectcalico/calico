// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package datastore

import (
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/datastore/migrate"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

// Migrate function is a switch to migrate related sub-commands
func Migrate(args []string) error {
	var err error
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> datastore migrate <command> [<args>...]

    export  Export the contents of the etcdv3 datastore to yaml.
    import  Store and convert yaml of resources into the Kubernetes datastore.
    lock    Lock the datastore to prevent changes from occurring during datastore migration.
    unlock  Unlock the datastore to allow changes once the migration is completed.

Options:
  -h --help      Show this screen.

Description:
  Migration specific commands.

  See '<BINARY_NAME> datastore migrate <command> --help' to read about a specific subcommand.
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
	args = append([]string{"datastore", "migrate", command}, arguments["<args>"].([]string)...)

	switch command {
	case "export":
		return migrate.Export(args)
	case "import":
		return migrate.Import(args)
	case "lock":
		return migrate.Lock(args)
	case "unlock":
		return migrate.Unlock(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
