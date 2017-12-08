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

	"github.com/projectcalico/calico/calico_upgrade/pkg/clients"
	"github.com/projectcalico/calico/calico_upgrade/pkg/constants"
	"github.com/projectcalico/calico/calico_upgrade/pkg/migrate"
)

func Abort(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calico-upgrade abort
      [--apiconfigv3=<V3_APICONFIG>]
      [--apiconfigv1=<V1_APICONFIG>]

Example:
  calico-upgrade abort --apiconfigv3=/path/to/v3/config --apiconfigv1=/path/to/v1/config

Options:
  -h --help                    Show this screen.
  --apiconfigv3=<V3_APICONFIG> Path to the file containing connection
                               configuration in YAML or JSON format for
                               the Calico v1 API.
                               [default: ` + constants.DefaultConfigPathV3 + `]
  --apiconfigv1=<V1_APICONFIG> Path to the file containing connection
                               configuration in YAML or JSON format for
                               the Calico v3 API.
                               [default: ` + constants.DefaultConfigPathV1 + `]

Description:
  Abort an upgrade that was started using 'calico-upgrade start'. In the event
  of a failure that requires an explicit abort, the start command indicates
  that the abort command should be executed.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option:\n  calico-upgrade %s\nUse flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
	}
	cfv3 := parsedArgs["--apiconfigv3"].(string)
	cfv1 := parsedArgs["--apiconfigv1"].(string)

	// Obtain the v1 and v3 clients.
	_, clientv1, err := clients.LoadClients(cfv3, cfv1)
	if err != nil {
		printFinalMessage("Failed to abort the upgrade.\n"+
			"Error accessing the Calico API: %v", err)
		os.Exit(1)
	}

	// Ensure the migration code displays messages (this is basically indicating that it
	// is being called from the calico-upgrade script).
	migrate.DisplayStatusMessages(true)

	// Perform the upgrade abort.
	res := migrate.Abort(clientv1)
	if res == migrate.ResultOK {
		// We aborted successfully.
		printFinalMessage("Successfully aborted the upgrade process.")
	} else {
		printFinalMessage("Failed to abort the upgrade - please retry the command.\n" +
			"The previous messages may contain more details.")
		os.Exit(1)
	}
}
