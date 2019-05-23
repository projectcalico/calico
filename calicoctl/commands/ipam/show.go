// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/libcalico-go/lib/ipam"

	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calicoctl/calicoctl/commands/clientmgr"
)

// IPAM takes keyword with an IP address then calls the subcommands.
func Show(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl ipam show [--ip=<IP> | --show-blocks] [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
     --ip=<IP>          Report whether this specific IP address is in use.
     --show-blocks      Show detailed information for IP blocks as well as pools.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: ` + constants.DefaultConfigPath + `]

Description:
  The ipam show command prints information about a given IP address, or about
  overall IP usage.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	ctx := context.Background()

	// Create a new backend client from env vars.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		fmt.Println(err)
	}

	showBlocks := parsedArgs["--show-blocks"].(bool)

	ipamClient := client.IPAM()
	if passedIP := parsedArgs["--ip"]; passedIP != nil {
		ip := argutils.ValidateIP(passedIP.(string))
		attr, err := ipamClient.GetAssignmentAttributes(ctx, ip)

		// IP address is not assigned, this prints message like `IP 192.168.71.1
		// is not assigned in block`. This is not exactly an error, so not
		// returning it to the caller.
		if err != nil {
			fmt.Println(err)
			return nil
		}

		// IP address is assigned.
		fmt.Printf("IP %s is in use\n", ip)
		if len(attr) != 0 {
			fmt.Printf("Attributes: %v\n", attr)
		} else {
			fmt.Println("No attributes defined")
		}
		return nil
	}

	usage, err := ipamClient.GetUtilization(ctx, ipam.GetUtilizationArgs{})
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Grouping", "CIDR", "IPs in use", "IPs available"})
	genRow := func(kind, cidr string, available, capacity int) []string {
		return []string{
			kind,
			cidr,
			// Note: the '+capacity/2' bits here give us rounding to the nearest
			// integer, instead of rounding down, and so ensure that the two percentages
			// add up to 100.
			fmt.Sprintf("%v/%v (%v%%)", capacity-available, capacity, (100*(capacity-available)+capacity/2)/capacity),
			fmt.Sprintf("%v/%v (%v%%)", available, capacity, (100*available+capacity/2)/capacity),
		}
	}
	for _, poolUse := range usage {
		var blockRows [][]string
		var poolAvailable, poolCapacity int
		for _, blockUse := range poolUse.Blocks {
			blockRows = append(blockRows, genRow("Block", blockUse.CIDR.String(), blockUse.Available, blockUse.Capacity))
			poolAvailable += blockUse.Available
			poolCapacity += blockUse.Capacity
		}
		if poolCapacity > 0 {
			table.Append(genRow("IP Pool", poolUse.CIDR.String(), poolAvailable, poolCapacity))
			if showBlocks {
				table.AppendBulk(blockRows)
			}
		}
	}
	table.Render()

	return nil
}
