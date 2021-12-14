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

package ipam

import (
	"context"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"

	"github.com/olekukonko/tablewriter"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"

	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

type borrowedIP struct {
	addr           string
	borrowingNode  string
	block          string
	blockOwner     string
	allocationType string
	allocatedTo    string
}

func getBorrowedIPs(ctx context.Context, ippoolClient clientv3.IPPoolInterface, bc bapi.Client) ([]*borrowedIP, int, error) {
	var details []*borrowedIP

	// Read details for all blocks.
	blocks, err := bc.List(ctx, model.BlockListOptions{}, "")
	if err != nil {
		return nil, 0, err
	}

	// For really old IP allocations, AttrSecondary[model.IPAMBlockAttributeNode] used to be not set.
	// Count such IP addresses, and, if any, warn customer as we are unable to classify those as
	// borrowed or not.
	unclassifiedIPs := 0

	for _, kvp := range blocks.KVPairs {
		b := kvp.Value.(*model.AllocationBlock)

		for i := range b.Allocations {
			if b.Allocations[i] != nil {
				// Allocations[i] if not nil:
				// - b.OrdinalToIP(i) is the allocated IP address
				// - *b.Allocations[i] is the index of the corresponding b.Attributes

				attributes := b.Attributes[*b.Allocations[i]]

				// Include both following cases:
				// - Affinity defined and IP assigned by a different node
				// - IP allocated from a block with no Affinity

				blockOwner := ""
				if b.Affinity != nil {
					// Affinity is in the form host:mgianluc-bz-09s4-kadm-node-2
					// Remove "host:"
					parts := strings.Split(*b.Affinity, ":")
					if len(parts) == 2 {
						blockOwner = parts[1]
					} else {
						blockOwner = parts[0]
					}
				}

				if borrowingNode, ok := attributes.AttrSecondary[model.IPAMBlockAttributeNode]; ok {
					if blockOwner != borrowingNode {
						bIP := borrowedIP{block: b.CIDR.IPNet.String(), blockOwner: blockOwner, borrowingNode: borrowingNode}
						bIP.addr = b.OrdinalToIP(i).String()
						if _, ok := attributes.AttrSecondary[model.IPAMBlockAttributePod]; ok {
							bIP.allocatedTo = fmt.Sprintf("%s/%s", attributes.AttrSecondary[model.IPAMBlockAttributeNamespace],
								attributes.AttrSecondary[model.IPAMBlockAttributePod])
							bIP.allocationType = model.IPAMBlockAttributePod
						} else if _, ok := attributes.AttrSecondary[model.IPAMBlockAttributeType]; ok {
							bIP.allocationType = attributes.AttrSecondary[model.IPAMBlockAttributeType]
						}
						details = append(details, &bIP)
					}
				} else {
					unclassifiedIPs++
				}
			}
		}
	}
	return details, unclassifiedIPs, nil
}

func showBorrowedDetails(ctx context.Context, ippoolClient clientv3.IPPoolInterface, bc bapi.Client) error {
	details, unclassifiedIPs, err := getBorrowedIPs(ctx, ippoolClient, bc)
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"IP", "BORROWING-NODE", "BLOCK", "BLOCK OWNER", "TYPE", "ALLOCATED-TO"})
	genRow := func(address, borrowingNode, block, blockOwner, t, allocatedTo string) []string {
		return []string{
			address,
			borrowingNode,
			block,
			blockOwner,
			t,
			allocatedTo,
		}
	}

	var rows [][]string
	for _, detail := range details {
		rows = append(rows, genRow(detail.addr, detail.borrowingNode, detail.block, detail.blockOwner,
			detail.allocationType, detail.allocatedTo))
	}
	table.AppendBulk(rows)
	table.Render()

	if unclassifiedIPs != 0 {
		fmt.Printf("\nNote: found %d IP allocations without an explicit node association. Unable to determine if they are borrowed.\n",
			unclassifiedIPs)
	}

	return nil
}

func showIP(ctx context.Context, ipamClient ipam.Interface, passedIP interface{}) error {
	ip := argutils.ValidateIP(passedIP.(string))
	attr, _, err := ipamClient.GetAssignmentAttributes(ctx, ip)
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// IP address is not assigned.  The detailed error message here is either
			// "resource does not exist: BlockKey...", if the whole block doesn't exist,
			// or "resource does not exist: <IP>...", if the IP is not assigned within
			// the block, but we don't want to expose that detail here.
			fmt.Printf("%v is not assigned\n", ip)
			return nil
		}
		return err
	}

	// IP address is assigned.
	fmt.Printf("IP %s is in use\n", ip)
	if len(attr) != 0 {
		fmt.Println("Attributes:")
		for k, v := range attr {
			fmt.Printf("  %v: %v\n", k, v)
		}
	} else {
		fmt.Println("No attributes defined")
	}
	return nil
}

func showBlockUtilization(ctx context.Context, ipamClient ipam.Interface, showBlocks bool) error {
	usage, err := ipamClient.GetUtilization(ctx, ipam.GetUtilizationArgs{})
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"GROUPING", "CIDR", "IPS TOTAL", "IPS IN USE", "IPS FREE"})
	genRow := func(kind, cidr string, inUse, capacity float64) []string {
		return []string{
			kind,
			cidr,
			fmt.Sprintf("%.5g", capacity),
			// Note: the '+capacity/2' bits here give us rounding to the nearest
			// integer, instead of rounding down, and so ensure that the two percentages
			// add up to 100.
			fmt.Sprintf("%.5g (%.f%%)", inUse, 100*inUse/capacity),
			fmt.Sprintf("%.5g (%.f%%)", capacity-inUse, 100*(capacity-inUse)/capacity),
		}
	}
	for _, poolUse := range usage {
		var blockRows [][]string
		var poolInUse float64
		for _, blockUse := range poolUse.Blocks {
			blockRows = append(blockRows, genRow("Block", blockUse.CIDR.String(), float64(blockUse.Capacity-blockUse.Available), float64(blockUse.Capacity)))
			poolInUse += float64(blockUse.Capacity - blockUse.Available)
		}
		ones, bits := poolUse.CIDR.Mask.Size()
		poolCapacity := math.Pow(2, float64(bits-ones))
		if ones > 0 {
			// Only show the IP Pool row for a real IP Pool and not for the orphaned
			// block case.
			table.Append(genRow("IP Pool", poolUse.CIDR.String(), poolInUse, poolCapacity))
		}
		if showBlocks {
			table.AppendBulk(blockRows)
		}
	}
	table.Render()

	return nil
}

func showConfiguration(ctx context.Context, ipamClient ipam.Interface) error {
	ipamConfig, err := ipamClient.GetIPAMConfig(ctx)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"PROPERTY", "VALUE"})
	genRow := func(name string, value interface{}) []string {
		return []string{
			name,
			fmt.Sprintf("%#v", value),
		}
	}

	var rows [][]string
	e := reflect.ValueOf(ipamConfig).Elem()
	for i := 0; i < e.NumField(); i++ {
		varName := e.Type().Field(i).Name
		varValue := e.Field(i).Interface()

		rows = append(rows, genRow(varName, varValue))
	}
	table.AppendBulk(rows)
	table.Render()
	return nil
}

// IPAM takes keyword with an IP address then calls the subcommands.
func Show(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam show [--ip=<IP> | --show-blocks | --show-borrowed | --show-configuration] [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
     --ip=<IP>                 Report whether this specific IP address is in use.
     --show-blocks             Show detailed information for IP blocks as well as pools.
     --show-borrowed           Show detailed information for "borrowed" IP addresses.
     --show-configuration      Show current Calico IPAM configuration.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The ipam show command prints information about a given IP address, or about
  overall IP usage.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	err = common.CheckVersionMismatch(parsedArgs["--config"], parsedArgs["--allow-version-mismatch"])
	if err != nil {
		return err
	}

	ctx := context.Background()

	// Create a new backend client from env vars.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	ipamClient := client.IPAM()
	ippoolClient := client.IPPools()

	// Get the backend client.
	type accessor interface {
		Backend() bapi.Client
	}
	bc := client.(accessor).Backend()

	passedIP := parsedArgs["--ip"]
	showBlocks := parsedArgs["--show-blocks"].(bool)
	showBorrowed := parsedArgs["--show-borrowed"].(bool)
	configuration := parsedArgs["--show-configuration"].(bool)

	if passedIP != nil {
		return showIP(ctx, ipamClient, passedIP)
	} else if showBlocks {
		return showBlockUtilization(ctx, ipamClient, true)
	} else if showBorrowed {
		return showBorrowedDetails(ctx, ippoolClient, bc)
	} else if configuration {
		return showConfiguration(ctx, ipamClient)
	}

	return showBlockUtilization(ctx, ipamClient, false)
}
