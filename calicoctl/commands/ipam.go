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
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calicoctl/calicoctl/commands/ipam"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func IPAM(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl ipam <command> [<args>...]

    release      Release a Calico assigned IP address.
    show         Show details of a Calico assigned IP address.

Options:
  -h --help      Show this screen.

Description:
  IP Address Management specific commands for calicoctl.

  See 'calicoctl ipam <command> --help' to read about a specific subcommand.
`
	arguments, err := docopt.Parse(doc, args, true, "", true, false)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if arguments["<command>"] == nil {
		return nil
	}

	command := arguments["<command>"].(string)
	args = append([]string{"ipam", command}, arguments["<args>"].([]string)...)

	switch command {
	case "release":
		return ipam.Release(args)
	case "show":
		return ipam.Show(args)
	default:
		fmt.Println(doc)
	}

	return nil
}
