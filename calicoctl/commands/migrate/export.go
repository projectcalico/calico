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

package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
)

// All of the resources we can retrieve via the v3 API.
var allV3Resources []string = []string{
	"ippools",
	"bgpconfig",
	"bgppeers",
	"felixconfigs",
	"globalnetworkpolicies",
	"globalnetworksets",
	"heps",
	"networkpolicies",
	"networksets",
	"nodes",
}

var resourceDisplayMap map[string]string = map[string]string{
	"ipamBlocks":            "IPAMBlocks",
	"blockaffinities":       "BlockAffinities",
	"ipamhandles":           "IPAMHandles",
	"ipamconfigs":           "IPAMConfigurations",
	"ippools":               "IPPools",
	"bgpconfig":             "BGPConfigurations",
	"bgppeers":              "BGPPeers",
	"clusterinfos":          "ClusterInformations",
	"felixconfigs":          "FelixConfigurations",
	"globalnetworkpolicies": "GlobalNetworkPolicies",
	"globalnetworksets":     "GlobalNetworkSets",
	"heps":                  "HostEndpoints",
	"networkpolicies":       "NetworkPolicies",
	"networksets":           "Networksets",
	"nodes":                 "Nodes",
}

var namespacedResources map[string]struct{} = map[string]struct{}{
	"networkpolicies": struct{}{},
	"networksets":     struct{}{},
}

func Export(args []string) error {
	doc := `Usage:
  calicoctl datastore migrate export [--config=<CONFIG>]

Options:
  -h --help                 Show this screen.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: ` + constants.DefaultConfigPath + `]

Description:
  Export the contents of the etcdv3 datastore.  Resources will be exported
  in yaml and json format. Save the results of this command to a file for
  later use with the import command.
  
  The resources exported include the following:
    - IPAMBlocks
    - BlockAffinities
    - IPAMHandles
    - IPAMConfigurations
    - IPPools
    - BGPConfigurations
    - BGPPeers
    - ClusterInformations
    - FelixConfigurations
    - GlobalNetworkPolicies
    - GlobalNetworkSets
    - HostEndpoints
    - NetworkPolicies
    - Networksets
    - Nodes

  The following resources are not exported:
    - WorkloadEndpoints
    - Profiles
`

	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	cf := parsedArgs["--config"].(string)
	// Get the backend client.
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	// Check that the datastore is locked.
	ctx := context.Background()
	locked, err := checkLocked(ctx, client)
	if err != nil {
		return fmt.Errorf("Error while checking if datastore was locked: %s", err)
	} else if !locked {
		return fmt.Errorf("Datastore is not locked. Run the `calicoctl datastore migrate lock` command in order to begin migration.")
	}

	// Check that the datastore configured datastore is etcd
	cfg, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		log.Info("Error loading config")
		return err
	}

	if cfg.Spec.DatastoreType != apiconfig.EtcdV3 {
		return fmt.Errorf("Invalid datastore type: %s to export from for datastore migration. Datastore type must be etcdv3", cfg.Spec.DatastoreType)
	}

	rp := common.ResourcePrinterYAML{}
	// Loop through all the resource types to retrieve every resource available by the v3 API.
	for _, r := range allV3Resources {
		mockArgs := map[string]interface{}{
			"<KIND>":   r,
			"<NAME>":   []string{},
			"--config": cf,
			"--export": true,
			"--output": "yaml",
			"get":      true,
		}
		results := common.ExecuteConfigCommand(mockArgs, common.ActionGetOrList)
		if len(results.ResErrs) > 0 {
			var errStr string
			for i, err := range results.ResErrs {
				errStr += err.Error()
				if (i + 1) != len(results.ResErrs) {
					errStr += "\n"
				}
			}
			return fmt.Errorf(errStr)
		}

		for _, resource := range results.Resources {
			// Remove relevant metadata because the --export flag does not remove it for lists.
			err := meta.EachListItem(resource, func(obj runtime.Object) error {
				rom := obj.(v1.ObjectMetaAccessor).GetObjectMeta()
				rom.SetUID("")
				rom.SetResourceVersion("")
				rom.SetCreationTimestamp(v1.Time{})
				rom.SetDeletionTimestamp(nil)
				rom.SetDeletionGracePeriodSeconds(nil)
				rom.SetClusterName("")
				return nil
			})
			if err != nil {
				return fmt.Errorf("Unable to clean metadata for export for %s resource: %s", resourceDisplayMap[r], err)
			}

			// Nodes need to also be modified to move the Orchestrator reference to the name field.
			if r == "nodes" {
				err := meta.EachListItem(resource, func(obj runtime.Object) error {
					node, ok := obj.(*apiv3.Node)
					if !ok {
						return fmt.Errorf("Failed to convert resource to Node object for migration processing: %+v", obj)
					}

					var newNodeName string
					for _, orchRef := range node.Spec.OrchRefs {
						if orchRef.Orchestrator == "k8s" {
							newNodeName = orchRef.NodeName
						}
					}

					if newNodeName == "" {
						return fmt.Errorf("Node %s missing a 'k8s' orchestrator reference. Unable to export data unless every node has a 'k8s' orchestrator reference", node.GetObjectMeta().GetName())
					}

					node.GetObjectMeta().SetName(newNodeName)

					return nil
				})
				if err != nil {
					return fmt.Errorf("Unable to process metadata for export for Node resource: %s", err)
				}
			}
		}

		err = rp.Print(results.Client, results.Resources)
		if err != nil {
			return err
		}

		// Add the yaml separator between resource types
		fmt.Print("---\n")
	}

	// Denote separation between the v3 resources and the cluster info resource which requires separate handling on import.
	fmt.Print("===\n")
	mockArgs := map[string]interface{}{
		"<KIND>":   "clusterinfos",
		"<NAME>":   "default",
		"--config": cf,
		"--export": false,
		"--output": "yaml",
		"get":      true,
	}
	results := common.ExecuteConfigCommand(mockArgs, common.ActionGetOrList)
	for _, resource := range results.Resources {
		clusterinfo, ok := resource.(*apiv3.ClusterInformation)
		if !ok {
			return fmt.Errorf("Failed to convert resource to ClusterInformation object: %+v", resource)
		}

		// Print the Cluster Info resource
		if output, err := json.MarshalIndent(clusterinfo, "", "  "); err != nil {
			return err
		} else {
			fmt.Printf("%s\n", string(output))
		}
	}

	if len(results.ResErrs) > 0 {
		var errStr string
		for i, err := range results.ResErrs {
			errStr += err.Error()
			if (i + 1) != len(results.ResErrs) {
				errStr += "\n"
			}
		}
		return fmt.Errorf(errStr)
	}

	// Denote separation between resources stored in YAML and the JSON IPAM resources.
	// IPAM resources are stored in JSON since the objects are not supported by the v3 API
	// and are not meant to be used with other calicoctl commands except for import.
	fmt.Print("===\n")

	// Get the backend client.
	client, err = clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	// Use the v1 API in order to retrieve IPAM resources
	ipam := NewMigrateIPAM(client)
	err = ipam.PullFromDatastore()
	if err != nil {
		return err
	}

	// Print out the contents of IPAM
	output, err := json.MarshalIndent(ipam, "", "  ")
	if err != nil {
		return err
	} else {
		fmt.Printf("%s\n", string(output))
	}

	return nil
}
