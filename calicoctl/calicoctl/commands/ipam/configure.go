// Copyright (c) 2016,2020 Tigera, Inc. All rights reserved.

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
	"strconv"
	"strings"

	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	ipamlib "github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

func updateIPAMConfig(
	ctx context.Context,
	ipamClient ipamlib.Interface,
	strictAffinity *bool,
	maxBlocks *int,
	persistence *ipamlib.VMAddressPersistence,
) error {
	ipamConfig, err := ipamClient.GetIPAMConfig(ctx)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	// Update StrictAffinity if specified.
	if strictAffinity != nil {
		ipamConfig.StrictAffinity = *strictAffinity
	}

	// Set MaxBlocksPerHost if specified.
	if maxBlocks != nil {
		ipamConfig.MaxBlocksPerHost = *maxBlocks
	}

	// Update KubeVirtVMAddressPersistence if specified.
	if persistence != nil {
		ipamConfig.KubeVirtVMAddressPersistence = persistence
	}

	err = ipamClient.SetIPAMConfig(ctx, *ipamConfig)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	if strictAffinity != nil {
		fmt.Println("Successfully set StrictAffinity to:", *strictAffinity)
	}
	if maxBlocks != nil {
		fmt.Println("Successfully set MaxBlocksPerHost to:", *maxBlocks)
	}
	if persistence != nil {
		fmt.Println("Successfully set KubeVirtVMAddressPersistence to:", *persistence)
	}

	return nil
}

// parsePersistence validates and converts CLI value to typed enum.
func parsePersistence(val string) (*ipamlib.VMAddressPersistence, error) {
	switch val {
	case string(ipamlib.VMAddressPersistenceEnabled):
		p := ipamlib.VMAddressPersistenceEnabled
		return &p, nil
	case string(ipamlib.VMAddressPersistenceDisabled):
		p := ipamlib.VMAddressPersistenceDisabled
		return &p, nil
	default:
		return nil, fmt.Errorf("invalid value for --kubevirt-ip-persistence. Use Enabled or Disabled")
	}
}

// Configure IPAM.
func Configure(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam configure [--strictaffinity=<true/false>]
                               [--max-blocks-per-host=<number>]
                               [--kubevirt-ip-persistence=<Enabled|Disabled>]
                               [--config=<CONFIG>]
                               [--allow-version-mismatch]

Options:
  -h --help                        Show this screen.
     --strictaffinity=<true/false>  Set StrictAffinity to true/false. When StrictAffinity
                                    is true, borrowing IP addresses is not allowed.
     --max-blocks-per-host=<number> Set the maximum number of blocks that can be affine to a host.
     --kubevirt-ip-persistence=<Enabled|Disabled>
                                    Control whether KubeVirt VMs retain persistent IP addresses
                                    across lifecycle events.
  -c --config=<CONFIG>              Path to the file containing connection configuration in
                                    YAML or JSON format.
                                    [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch       Allow client and cluster versions mismatch.

Description:
 Modify configuration for Calico IP address management.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
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

	// Parse StrictAffinity (optional).
	var strictAffinity *bool
	if passedValue, ok := parsedArgs["--strictaffinity"].(string); ok && passedValue != "" {
		enabled, err := strconv.ParseBool(passedValue)
		if err != nil {
			return fmt.Errorf("invalid value. Use true or false to set strictaffinity")
		}
		strictAffinity = &enabled
	}

	// Parse MaxBlocksPerHost (optional).
	var maxBlocks *int
	if maxBlockStr, ok := parsedArgs["--max-blocks-per-host"].(string); ok && maxBlockStr != "" {
		maxBlocksVal, err := strconv.Atoi(maxBlockStr)
		if err != nil {
			return fmt.Errorf("invalid value for maxblockhost. Use a valid number")
		}
		maxBlocks = &maxBlocksVal
	}

	// Parse KubeVirtVMAddressPersistence (optional).
	var persistence *ipamlib.VMAddressPersistence
	if val, ok := parsedArgs["--kubevirt-ip-persistence"].(string); ok && val != "" {
		persistence, err = parsePersistence(val)
		if err != nil {
			return err
		}
	}

	if strictAffinity == nil && maxBlocks == nil && persistence == nil {
		return fmt.Errorf("at least one configuration option must be specified")
	}

	return updateIPAMConfig(ctx, ipamClient, strictAffinity, maxBlocks, persistence)
}
