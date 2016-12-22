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

package ipam

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"

	docopt "github.com/docopt/docopt-go"
	"github.com/projectcalico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calicoctl/calicoctl/commands/clientmgr"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func Show(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl ipam show --ip=<IP> [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
     --ip=<IP>          IP address to show.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: /etc/calico/calicoctl.cfg]

Description:
  The ipam show command prints information about a given IP address, such as
  special attributes defined for the IP or whether the IP has been reserved by
  a user of the Calico IP Address Manager.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
	}

	// Create a new backend client from env vars.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ipamClient := client.IPAM()
	passedIP := parsedArgs["--ip"].(string)
	ip := argutils.ValidateIP(passedIP)
	attr, err := ipamClient.GetAssignmentAttributes(ip)

	// IP address is not assigned, this prints message like
	// `IP 192.168.71.1 is not assigned in block`. This is not exactly an error,
	// so not returning it to the caller.
	if err != nil {
		fmt.Println(err)
		return
	}

	// IP address is assigned with attributes.
	if len(attr) != 0 {
		fmt.Println(attr)
	} else {
		// IP address is assigned but attributes are not set.
		fmt.Printf("No attributes defined for IP %s\n", ip)
	}
}
