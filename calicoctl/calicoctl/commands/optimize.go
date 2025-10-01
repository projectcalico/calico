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
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

// Optimize reads resources from file/stdin, validates them (offline), and prints them in YAML.
// Initially this performs a no-op transformation; future iterations may modify resources.
func Optimize(args []string) error {
	doc := `Usage:
  <BINARY_NAME> optimize --filename=<FILENAME> [--recursive] [--skip-empty] [--allow-version-mismatch]

Examples:
  # Optimize a policy using the data in policy.yaml.
  <BINARY_NAME> optimize -f ./policy.yaml

  # Optimize a policy based on the JSON passed into stdin.
  cat policy.json | <BINARY_NAME> optimize -f -

Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to optimize the resource(s). If set to
                               "-" loads from stdin. If filename is a directory, this command is
                               invoked for each .json .yaml and .yml file within that directory,
                               terminating after the first failure.
  -R --recursive               Process the filename specified in -f or --filename recursively.
     --skip-empty              Do not error if any files or directory specified using -f or --filename contain no
                               data.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The optimize command reads a set of resources by filename or stdin, validates them offline
  (without connecting to any datastore), and then outputs the resources in YAML format.

  Valid resource types are:

<RESOURCE_LIST>

  Initially, optimize performs a no-op transformation (resources are printed unchanged).
  In future versions, certain resources may be transformed for better efficiency.`

	// Replace placeholders.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)
	doc = strings.Replace(doc, "<RESOURCE_LIST>", util.Resources(), 1)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	// Execute validation to load and verify resources offline.
	results := common.ExecuteConfigCommand(parsedArgs, common.ActionValidate)
	log.Infof("results: %+v", results)

	if results.FileInvalid {
		return fmt.Errorf("failed to execute command: %v", results.Err)
	}
	if results.Err != nil {
		return fmt.Errorf("failed to optimize resources: %v", results.Err)
	}

	// If there were per-resource errors, surface them after printing any that succeeded.
	// But first, print all successfully handled resources as YAML (no-op transformation).
	if results.NumResources == 0 {
		// No resources specified. If there is an associated error use that, otherwise print message with no error.
		if results.Err != nil {
			return results.Err
		}
		fmt.Println("No resources specified")
		return nil
	}

	// Print YAML for all successfully validated resources.
	rp := common.ResourcePrinterYAML{}
	if err := rp.Print(results.Client, results.Resources); err != nil {
		return err
	}

	if len(results.ResErrs) > 0 {
		var errStr string
		for i, err := range results.ResErrs {
			errStr += err.Error()
			if (i + 1) != len(results.ResErrs) {
				errStr += "\n"
			}
		}
		return errors.New(errStr)
	}

	return nil
}
