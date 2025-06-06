// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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
	"strings"

	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Clean IPAM resources that are orphaned or no longer needed.
func Clean(args []string, version string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> ipam clean orphaned-blocks [--force] [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -f --force                   Delete blocks even if they have active IP allocations.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The clean command is used to clean up IPAM resources that are orphaned or no 
  longer needed.

  The orphaned-blocks subcommand cleans up IPAM blocks that have affinity to nodes 
  that are no longer present in the cluster.
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

	// Load config.
	cf := parsedArgs["--config"].(string)
	cfg, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		return err
	}

	// Create a new backend client.
	client, err := clientmgr.NewClientFromConfig(cfg)
	if err != nil {
		return err
	}

	// Get the IPAM client
	ipamClient := client.IPAM()

	// Execute the appropriate subcommand.
	if parsedArgs["orphaned-blocks"].(bool) {
		// Get all nodes from the cluster.
		nodeList, err := client.Nodes().List(ctx, options.ListOptions{})
		if err != nil {
			return err
		}

		// Extract node names.
		var nodes []string
		for _, node := range nodeList.Items {
			nodes = append(nodes, node.Name)
		}

		// Call the IPAM client to clean up orphaned blocks.
		force := parsedArgs["--force"].(bool)
		count, err := ipamClient.CleanupBlocksForRemovedNodes(ctx, nodes, force)
		if err != nil {
			return err
		}

		// Print a message indicating how many blocks were cleaned up.
		if count == 0 {
			fmt.Println("No orphaned IPAM blocks found.")
		} else {
			fmt.Printf("Successfully cleaned up %d orphaned IPAM block(s).\n", count)
		}

		return nil
	}

	// If we get here, the command is not recognized.
	fmt.Println(doc)
	return nil
}
