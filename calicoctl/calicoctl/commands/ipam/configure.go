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
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

func updateIPAMStrictAffinity(ctx context.Context, ipamClient ipam.Interface, enabled bool) error {
	ipamConfig, err := ipamClient.GetIPAMConfig(ctx)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	// If StrictAffinity == true => an address from a block can only be assigned by
	// host with block affinity.
	ipamConfig.StrictAffinity = enabled

	err = ipamClient.SetIPAMConfig(ctx, *ipamConfig)
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	fmt.Println("Successfully set StrictAffinity to:", enabled)

	return nil
}

// Configure IPAM.
func Configure(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam configure --strictaffinity=<true/false> [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                        Show this screen.
     --strictaffinity=<true/false> Set StrictAffinity to true/false. When StrictAffinity
                                   is true, borrowing IP addresses is not allowed.
  -c --config=<CONFIG>             Path to the file containing connection configuration in
                                   YAML or JSON format.
                                   [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch      Allow client and cluster versions mismatch.

Description:
 Modify configuration for Calico IP address management.
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
	passedValue := parsedArgs["--strictaffinity"].(string)
	enabled, err := strconv.ParseBool(passedValue)
	if err != nil {
		return fmt.Errorf("Invalid value. Use true or false to set strictaffinity")
	}

	return updateIPAMStrictAffinity(ctx, ipamClient, enabled)
}
