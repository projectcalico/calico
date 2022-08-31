// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/ipam"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func IPAM(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam <command> [<args>...]

    check            Check the integrity of the IPAM datastructures.
    release          Release a Calico assigned IP address.
    show             Show details of a Calico configuration,
                     assigned IP address, or of overall IP usage.
    split            Split the IP pool specified by the CIDR into
                     the specified number of smaller IPPools.
    configure        Configure IPAM

Options:
  -h --help      Show this screen.

Description:
  IP address management commands for Calico.

  See '<BINARY_NAME> ipam <command> --help' to read about a specific subcommand.
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
	args = append([]string{"ipam", command}, arguments["<args>"].([]string)...)

	switch command {
	case "check":
		return ipam.Check(args, VERSION)
	case "release":
		return ipam.Release(args, VERSION)
	case "show":
		return ipam.Show(args)
	case "configure":
		return ipam.Configure(args)
	case "split":
		return ipam.Split(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
