// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

func Validate(args []string) error {
	doc := `Usage:
  <BINARY_NAME> validate --filename=<FILENAME> [--recursive] [--skip-empty] [--allow-version-mismatch]

Examples:
  # Validate a policy using the data in policy.yaml.
  <BINARY_NAME> validate -f ./policy.yaml

  # Validate a policy based on the JSON passed into stdin.
  cat policy.json | <BINARY_NAME> validate -f -

Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to validate the resource.  If set to
                               "-" loads from stdin. If filename is a directory, this command is
                               invoked for each .json .yaml and .yml file within that directory,
                               terminating after the first failure.
  -R --recursive               Process the filename specified in -f or --filename recursively.
     --skip-empty              Do not error if any files or directory specified using -f or --filename contain no
                               data.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The validate command is used to validate a set of resources by filename
  or stdin.  JSON and YAML formats are accepted.

  Valid resource types are:

<RESOURCE_LIST>

  The validate command will parse and validate the specified resources offline
  without connecting to any datastore. This can be used to check resource syntax,
  structure, and schema validity before applying them.

  The output of the command indicates how many resources were successfully
  validated, and the error reason if an error occurred.

  The resources are validated in the order they are specified.  In the event of a
  failure validating a specific resource it is possible to work out which
  resource failed based on the number of resources successfully validated.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	// Replace <RESOURCE_LIST> with the list of resource types.
	doc = strings.Replace(doc, "<RESOURCE_LIST>", util.Resources(), 1)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	results := common.ExecuteConfigCommand(parsedArgs, common.ActionValidate)
	log.Infof("results: %+v", results)

	if results.FileInvalid {
		return fmt.Errorf("failed to execute command: %v", results.Err)
	} else if results.NumResources == 0 {
		// No resources specified. If there is an associated error use that, otherwise print message with no error.
		if results.Err != nil {
			return results.Err
		}
		fmt.Println("No resources specified")
	} else if results.NumHandled == 0 {
		if results.NumResources == 1 {
			return fmt.Errorf("failed to validate '%s' resource: %v", results.SingleKind, results.ResErrs)
		} else if results.SingleKind != "" {
			return fmt.Errorf("failed to validate any '%s' resources: %v", results.SingleKind, results.ResErrs)
		} else {
			return fmt.Errorf("failed to validate any resources: %v", results.ResErrs)
		}
	} else if len(results.ResErrs) == 0 {
		if results.SingleKind != "" {
			fmt.Printf("Successfully validated %d '%s' resource(s)\n", results.NumHandled, results.SingleKind)
		} else {
			fmt.Printf("Successfully validated %d resource(s)\n", results.NumHandled)
		}
	} else {
		if results.NumHandled-len(results.ResErrs) > 0 {
			fmt.Printf("Partial success: ")
			if results.SingleKind != "" {
				fmt.Printf("validated the first %d out of %d '%s' resources:\n",
					results.NumHandled, results.NumResources, results.SingleKind)
			} else {
				fmt.Printf("validated the first %d out of %d resources:\n",
					results.NumHandled, results.NumResources)
			}
		}
		return fmt.Errorf("hit error(s): %v", results.ResErrs)
	}

	return nil
}
