// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

	log "github.com/Sirupsen/logrus"
	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
)

func Delete(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl delete ([--scope=<SCOPE>] [--node=<NODE>] [--orchestrator=<ORCH>]
                    [--workload=<WORKLOAD>] (<KIND> [<NAME>]) |
                   --filename=<FILE>)
                   [--skip-not-exists] [--config=<CONFIG>]

Examples:
  # Delete a policy using the type and name specified in policy.yaml.
  calicoctl delete -f ./policy.yaml

  # Delete a policy based on the type and name in the YAML passed into stdin.
  cat policy.yaml | calicoctl delete -f -

  # Delete policy with name "foo"
  calicoctl delete policy foo

Options:
  -h --help                 Show this screen.
  -s --skip-not-exists      Skip over and treat as successful, resources that
                            don't exist.
  -f --filename=<FILENAME>  Filename to use to delete the resource.  If set to
                            "-" loads from stdin.
  -n --node=<NODE>          The node (this may be the hostname of the compute
                            server if your installation does not explicitly set
                            the names of each Calico node).
     --orchestrator=<ORCH>  The orchestrator (valid for workload endpoints).
     --workload=<WORKLOAD>  The workload (valid for workload endpoints).
     --scope=<SCOPE>        The scope of the resource type.  One of global,
                            node.  This is only valid for BGP peers and is used
                            to indicate whether the peer is a global peer or
                            node-specific.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  The delete command is used to delete a set of resources by filename or stdin,
  or by type and identifiers.  JSON and YAML formats are accepted for file and
  stdin format.

  Valid resource types are:

    * node
    * bgpPeer
    * hostEndpoint
    * workloadEndpoint
    * ipPool
    * policy
    * profile

  The resource type is case insensitive and may be pluralized.

  Attempting to delete a resource that does not exists is treated as a
  terminating error unless the --skip-not-exists flag is set.  If this flag is
  set, resources that do not exist are skipped.

  When deleting resources by type, only a single type may be specified at a
  time.  The name is required along with any and other identifiers required to
  uniquely identify a resource of the specified type.

  The output of the command indicates how many resources were successfully
  deleted, and the error reason if an error occurred.  If the --skip-not-exists
  flag is set then skipped resources are included in the success count.

  The resources are deleted in the order they are specified.  In the event of a
  failure deleting a specific resource it is possible to work out which
  resource failed based on the number of resources successfully deleted.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
	}

	results := executeConfigCommand(parsedArgs, actionDelete)
	log.Infof("results: %+v", results)

	if results.fileInvalid {
		fmt.Printf("Failed to execute command: %v\n", results.err)
		os.Exit(1)
	} else if results.numHandled == 0 {
		if results.numResources == 0 {
			fmt.Printf("No resources specified in file\n")
		} else if results.numResources == 1 {
			fmt.Printf("Failed to delete '%s' resource: %v\n", results.singleKind, results.err)
		} else if results.singleKind != "" {
			fmt.Printf("Failed to delete any '%s' resources: %v\n", results.singleKind, results.err)
		} else {
			fmt.Printf("Failed to delete any resources: %v\n", results.err)
		}
		os.Exit(1)
	} else if results.err == nil {
		if results.singleKind != "" {
			fmt.Printf("Successfully deleted %d '%s' resource(s)\n", results.numHandled, results.singleKind)
		} else {
			fmt.Printf("Successfully deleted %d resource(s)\n", results.numHandled)
		}
	} else {
		fmt.Printf("Partial success: ")
		if results.singleKind != "" {
			fmt.Printf("deleted the first %d out of %d '%s' resources:\n",
				results.numHandled, results.numResources, results.singleKind)
		} else {
			fmt.Printf("deleted the first %d out of %d resources:\n",
				results.numHandled, results.numResources)
		}
		fmt.Printf("Hit error: %v\n", results.err)
		os.Exit(1)
	}
}
