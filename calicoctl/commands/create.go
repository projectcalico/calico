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

	log "github.com/Sirupsen/logrus"
	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico-containers/calicoctl/commands/constants"
)

func Create(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl create --filename=<FILENAME> [--skip-exists] [--config=<CONFIG>]

Examples:
  # Create a policy using the data in policy.yaml.
  calicoctl create -f ./policy.yaml

  # Create a policy based on the JSON passed into stdin.
  cat policy.json | calicoctl create -f -

Options:
  -h --help                 Show this screen.
  -f --filename=<FILENAME>  Filename to use to create the resource.  If set to "-" loads from stdin.
  -s --skip-exists          Skip over and treat as successful any attempts to create an entry that
                            already exists.
  -c --config=<CONFIG>      Filename containing connection configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  The create command is used to create a set of resources by filename or stdin.  JSON and
  YAML formats are accepted.

  Valid resource types are node, bgpPeer, hostEndpoint, workloadEndpoint, policy, pool and
  profile.

  Attempting to create a resource that already exists is treated as a terminating error unless the
  --skip-exists flag is set.  If this flag is set, resources that already exist are skipped.

  The output of the command indicates how many resources were successfully created, and the error
  reason if an error occurred.  If the --skip-exists flag is set then skipped resources are
  included in the success count.

  The resources are created in the order they are specified.  In the event of a failure
  creating a specific resource it is possible to work out which resource failed based on the
  number of resources successfully created.`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return err
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	results := executeConfigCommand(parsedArgs, actionCreate)
	log.Infof("results: %+v", results)

	if results.fileInvalid {
		fmt.Printf("Error processing input file: %v\n", results.err)
	} else if results.numHandled == 0 {
		if results.numResources == 0 {
			fmt.Printf("No resources specified in file\n")
		} else if results.numResources == 1 {
			fmt.Printf("Failed to create '%s' resource: %v\n", results.singleKind, results.err)
		} else if results.singleKind != "" {
			fmt.Printf("Failed to create any '%s' resources: %v\n", results.singleKind, results.err)
		} else {
			fmt.Printf("Failed to create any resources: %v\n", results.err)
		}
	} else if results.err == nil {
		if results.singleKind != "" {
			fmt.Printf("Successfully created %d '%s' resource(s)\n", results.numHandled, results.singleKind)
		} else {
			fmt.Printf("Successfully created %d resource(s)\n", results.numHandled)
		}
	} else {
		fmt.Printf("Partial success: ")
		if results.singleKind != "" {
			fmt.Printf("created the first %d out of %d '%s' resources:\n",
				results.numHandled, results.numResources, results.singleKind)
		} else {
			fmt.Printf("created the first %d out of %d resources:\n",
				results.numHandled, results.numResources)
		}
		fmt.Printf("Hit error: %v\n", results.err)
	}

	return results.err
}
