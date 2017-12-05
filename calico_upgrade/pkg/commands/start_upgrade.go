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

func StartUpgrade(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calico-upgrade start-upgrade [--calicov3-config=<V3CONFIG>] [--calicov2-config=<V2CONFIG>]

Example:
  calico-upgrade --calicov3-config=/path/to/v3/config --calicov2-config=/path/to/v2/config start-upgrade

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

	clientV3, clientV2, err := upgradeclients.LoadClients(cfv3, cfv2)
	if err != nil {
		fmt.Printf("Failed to create Calico API client: %s\n", err)
		os.Exit(1)
	}

	_, err = migrate.MigrateData(clientV3, clientV2)
	if err != nil {
		fmt.Println("There were errors seen when running `start-upgrade`, please follow the steps above " +
			"to resolve the errors.")
		os.Exit(1)
	}

	fmt.Println("The data migration was successful, please run `calico-upgrade complete-upgrade` to finish upgrade.")
}
