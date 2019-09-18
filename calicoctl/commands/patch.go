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

package commands

import (
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	log "github.com/sirupsen/logrus"
)

func Patch(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl patch <KIND> <NAME> --patch=<PATCH> [--type=<TYPE>] [--config=<CONFIG>] [--namespace=<NS>]

Examples:
  # Partially update a node using a strategic merge patch.
  calicoctl patch node node-0 --patch '{"spec":{"bgp": {"routeReflectorClusterID": "CLUSTER_ID"}}}'

  # Partially update a node using a json merge patch.
  calicoctl patch node node-0 --patch '{"spec":{"bgp": {"routeReflectorClusterID": "CLUSTER_ID"}}}' --type json

Options:
  -h --help                  Show this screen.
  -p --patch=<PATCH>         Spec to use to patch the resource.
  -t --type=<TYPE>           Format of patch type:
                                strategic   Strategic merge patch (default)
                                json        JSON Patch, RFC 6902 (not yet implemented)
                                merge       JSON Merge Patch, RFC 7386 (not yet implemented)
  -c --config=<CONFIG>       Path to the file containing connection
                             configuration in YAML or JSON format.
                             [default: ` + constants.DefaultConfigPath + `]
  -n --namespace=<NS>        Namespace of the resource.
                             Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                             Uses the default namespace if not specified.

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

	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	results := executeConfigCommand(parsedArgs, actionPatch)
	log.Infof("results: %+v", results)

	if results.numResources == 0 {
		return fmt.Errorf("No resources specified")
	} else if results.err == nil && results.numHandled > 0 {
		fmt.Printf("Successfully patched %d '%s' resource\n", results.numHandled, results.singleKind)
	} else if results.err != nil {
		return fmt.Errorf("Hit error: %v", results.err)
	}

	if len(results.resErrs) > 0 {
		var errStr string
		for _, err := range results.resErrs {
			errStr += fmt.Sprintf("Failed to patch '%s' resource: %v\n", results.singleKind, err)
		}
		return fmt.Errorf(errStr)
	}

	return nil
}
