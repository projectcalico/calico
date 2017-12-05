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

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calico_upgrade/pkg/commands/constants"
	"github.com/projectcalico/calico/calico_upgrade/pkg/upgradeclients"
	"github.com/projectcalico/calico/calico_upgrade/pkg/migrate"
)

func Validate(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calico-upgrade validate [--calicov3-config=<V3CONFIG>] [--calicov2-config=<V2CONFIG>]

Example:
  calico-upgrade --calicov3-config=/path/to/v3/config --calicov2-config=/path/to/v2/config validate

Options:
  -h --help                  Show this screen.
  --calicov2-config=<CONFIG> Path to the file containing connection
                             configuration in YAML or JSON format for
							 the Calico v1 API.
                             [default: ` + constants.DefaultConfigPath + `]
  --calicov3-config=<CONFIG> Path to the file containing connection
                             configuration in YAML or JSON format for
							 the Calico v3 API.
                             [default: ` + constants.DefaultConfigPath + `]

Description:
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	cfv2 := parsedArgs["--calicov2-config"].(string)
	cfv3 := parsedArgs["--calicov3-config"].(string)

	_, clientV2, err := upgradeclients.LoadClients(cfv3, cfv2)
	if err != nil {
		fmt.Printf("Failed to create Calico API client: %s\n", err)
		os.Exit(1)
	}

	cData, err := migrate.QueryAndConvertResources(clientV2)

	// Any resource names we plan to change should be reported to the user.
	if len(cData.NameConversions) > 0 {
		fmt.Println("The following resource names will be changed:")
		for _, change := range cData.NameConversions {
			fmt.Printf(" -  %s: %s -> %s\n", change.Kind, change.Original, change.New)
		}
	}

	// After we've converted the names we might end up with clashing names that the user will need to update.
	if len(cData.NameClashes) > 0 {
		fmt.Println("The following names clashed after conversion was applied:")
		for _, nError := range cData.NameClashes {
			fmt.Println(nError)
		}
	}

	// Errors with data that cannot be converted.
	if len(cData.ConversionErrors) > 0 {
		fmt.Println("The following errors were seen during validation, please resolve these errors " +
			"and run `calico-upgrade validate` again:")
		for _, cError := range cData.ConversionErrors {
			fmt.Println(cError)
		}
	}

	// Errors with validation logic, user should report these.
	if len(cData.ConversedValidationErrors) > 0 {
		fmt.Println("Errors with validation were seen, please report these to the Calico team " +
			"on Github by filing an issue (https://github.com/projectcalico/calico/issues):")
		for _, vError := range cData.ConversedValidationErrors {
			fmt.Println(vError)
		}
	}

	// Some data will be dropped and recreated by the Kubernetes Policy Controller.
	if len(cData.HandledByPolicyCtrl) > 0 {
		fmt.Println("The following data will be skipped as it will be recreated by the Kubernetes " +
			"Policy Controller:")
		for _, skipped := range cData.HandledByPolicyCtrl {
			fmt.Printf(" -  %s\n", skipped)
		}
	}

	if cData.HasErrors() {
		fmt.Println("Please correct the above errors and run `calico-upgrade validate` again.")
		os.Exit(1)
	}

	fmt.Println("Validation was successful, please install Calico v3.0 and then run `calico-upgrade start-upgrade` " +
		"to migrate your data.")
}
