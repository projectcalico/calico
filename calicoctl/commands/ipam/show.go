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
	"math"
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
	table.SetHeader([]string{"GROUPING", "CIDR", "IPS TOTAL", "IPS IN USE", "IPS FREE"})
	genRow := func(kind, cidr string, available, capacity float64) []string {
		return []string{
			kind,
			cidr,
			fmt.Sprintf("%.5g", capacity),
			// Note: the '+capacity/2' bits here give us rounding to the nearest
			// integer, instead of rounding down, and so ensure that the two percentages
			// add up to 100.
			fmt.Sprintf("%.5g (%.f%%)", capacity-available, 100*(capacity-available)/capacity),
			fmt.Sprintf("%.5g (%.f%%)", available, 100*available/capacity),
		}
	}
	for _, poolUse := range usage {
		var blockRows [][]string
		var poolInUse float64
		for _, blockUse := range poolUse.Blocks {
			blockRows = append(blockRows, genRow("Block", blockUse.CIDR.String(), float64(blockUse.Available), float64(blockUse.Capacity)))
			poolInUse += float64(blockUse.Capacity - blockUse.Available)
		}
		ones, bits := poolUse.CIDR.Mask.Size()
		poolCapacity := math.Pow(2, float64(bits-ones))
		if ones > 0 {
			// Only show the IP Pool row for a real IP Pool and not for the orphaned
			// block case.
			table.Append(genRow("IP Pool", poolUse.CIDR.String(), poolCapacity-poolInUse, poolCapacity))
		}
		if showBlocks {
			table.AppendBulk(blockRows)
		}
	}
	table.Render()

	return nil
}
