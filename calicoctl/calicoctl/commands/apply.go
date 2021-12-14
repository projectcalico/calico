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

func Apply(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> apply --filename=<FILENAME> [--recursive] [--skip-empty]
                  [--config=<CONFIG>] [--namespace=<NS>] [--context=<context>] [--allow-version-mismatch]

Examples:
  # Apply a policy using the data in policy.yaml.
  <BINARY_NAME> apply -f ./policy.yaml

  # Apply a policy based on the JSON passed into stdin.
  cat policy.json | <BINARY_NAME> apply -f -

Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to apply the resource.  If set to
                               "-" loads from stdin. If filename is a directory, this command is
                               invoked for each .json .yaml and .yml file within that directory,
                               terminating after the first failure.
  -R --recursive               Process the filename specified in -f or --filename recursively.
     --skip-empty              Do not error if any files or directory specified using -f or --filename contain no
                               data.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                               Uses the default namespace if not specified.
     --context=<context>       The name of the kubeconfig context to use.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The apply command is used to create or replace a set of resources by filename
  or stdin.  JSON and YAML formats are accepted.

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

  When applying a resource:
  -  if the resource does not already exist (as determined by it's primary
     identifiers) then it is created
  -  if the resource already exists then the specification for that resource is
     replaced in it's entirety by the new resource specification.

  The output of the command indicates how many resources were successfully
  applied, and the error reason if an error occurred.

  The resources are applied in the order they are specified.  In the event of a
  failure applying a specific resource it is possible to work out which
  resource failed based on the number of resources successfully applied

  When applying a resource to perform an update, the complete resource spec
  must be provided, it is not sufficient to supply only the fields that are
  being updated.
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

	results := common.ExecuteConfigCommand(parsedArgs, common.ActionApply)
	log.Infof("results: %+v", results)

	if results.FileInvalid {
		return fmt.Errorf("Failed to execute command: %v", results.Err)
	} else if results.NumResources == 0 {
		// No resources specified. If there is an associated error use that, otherwise print message with no error.
		if results.Err != nil {
			return results.Err
		}
		fmt.Println("No resources specified")
	} else if results.NumHandled == 0 {
		if results.NumResources == 1 {
			return fmt.Errorf("Failed to apply '%s' resource: %v", results.SingleKind, results.ResErrs)
		} else if results.SingleKind != "" {
			return fmt.Errorf("Failed to apply any '%s' resources: %v", results.SingleKind, results.ResErrs)
		} else {
			return fmt.Errorf("Failed to apply any resources: %v", results.ResErrs)
		}
	} else if len(results.ResErrs) == 0 {
		if results.SingleKind != "" {
			fmt.Printf("Successfully applied %d '%s' resource(s)\n", results.NumHandled, results.SingleKind)
		} else {
			fmt.Printf("Successfully applied %d resource(s)\n", results.NumHandled)
		}
	} else {
		if results.NumHandled-len(results.ResErrs) > 0 {
			fmt.Printf("Partial success: ")
			if results.SingleKind != "" {
				fmt.Printf("applied the first %d out of %d '%s' resources:\n",
					results.NumHandled, results.NumResources, results.SingleKind)
			} else {
				fmt.Printf("applied the first %d out of %d resources:\n",
					results.NumHandled, results.NumResources)
			}
		}
		return fmt.Errorf("Hit error(s): %v", results.ResErrs)
	}

	return nil
}
