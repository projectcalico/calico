// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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
	"os"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

func Patch(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> patch <KIND> <NAME> --patch=<PATCH> [--type=<TYPE>] [--config=<CONFIG>] [--namespace=<NS>] [--context=<context>] [--allow-version-mismatch]

Examples:
  # Partially update a node using a strategic merge patch.
  <BINARY_NAME> patch node node-0 --patch '{"spec":{"bgp": {"routeReflectorClusterID": "CLUSTER_ID"}}}'

  # Partially update a node using a json merge patch.
  <BINARY_NAME> patch node node-0 --patch '{"spec":{"bgp": {"routeReflectorClusterID": "CLUSTER_ID"}}}' --type json

Options:
  -h --help                    Show this screen.
  -p --patch=<PATCH>           Spec to use to patch the resource.
  -t --type=<TYPE>             Format of patch type:
                                  strategic   Strategic merge patch (default)
                                  json        JSON Patch, RFC 6902 (not yet implemented)
                                  merge       JSON Merge Patch, RFC 7386 (not yet implemented)
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                               Uses the default namespace if not specified.
     --context=<context>       The name of the kubeconfig context to use.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The patch command is used to patch a specific resource by type and identifiers in place.
  Currently, only JSON format is accepted.

  Valid resource types are:

    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * globalNetworkSet
    * hostEndpoint
    * ipPool
    * ipReservation
    * kubeControllersConfiguration
    * networkPolicy
    * networkSet
    * node
    * profile
    * workloadEndpoint

  The resource type is case insensitive and may be pluralized.

  Attempting to patch a resource that does not exists is treated as a
  terminating error unless the --skip-not-exists flag is set.  If this flag is
  set, resources that do not exist are skipped.

  When patching resources by type, only a single type may be specified at a
  time.  The name is required along with any and other identifiers required to
  uniquely identify a resource of the specified type.
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
	if context := parsedArgs["--context"]; context != nil {
		os.Setenv("K8S_CURRENT_CONTEXT", context.(string))
	}

	results := common.ExecuteConfigCommand(parsedArgs, common.ActionPatch)
	log.Infof("results: %+v", results)

	if results.NumResources == 0 {
		// No resources specified. If there is an associated error use that, otherwise print message with no error.
		if results.Err != nil {
			return results.Err
		}
		return fmt.Errorf("No resources specified")
	} else if results.Err == nil && results.NumHandled > 0 {
		fmt.Printf("Successfully patched %d '%s' resource\n", results.NumHandled, results.SingleKind)
	} else if results.Err != nil {
		return fmt.Errorf("Hit error: %v", results.Err)
	}

	if len(results.ResErrs) > 0 {
		var errStr string
		for _, err := range results.ResErrs {
			errStr += fmt.Sprintf("Failed to patch '%s' resource: %v\n", results.SingleKind, err)
		}
		return fmt.Errorf(errStr)
	}

	return nil
}
