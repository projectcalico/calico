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

func Start(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calico-upgrade start
      [--apiconfigv3=<V3_APICONFIG>]
      [--apiconfigv1=<V1_APICONFIG>]
      [--output-dir=<OUTPUTDIR>]
      [--ignore-v3-data]

Example:
  calico-upgrade start --apiconfigv3=/path/to/v3/config --apiconfigv1=/path/to/v1/config

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
  --output-dir=<OUTPUTDIR>     Directory to store the data migration reports in.
                               [default: ` + constants.GetDefaultOutputDir() + `]
  --ignore-v3-data             Ignore any existing Calico data that is in the
                               v3 format. The migrated data will overwrite
                               any common resources, and leave other resources
                               unchanged. If there is v3 data present, we
                               recommend you remove all Calico data from the
                               v3 datastore before upgrading, however, this
                               option may be used if that is not possible, or
                               if you know all of the data present will be
                               updated by the upgrade.

Description:
  Start the upgrade process to migrate from the Calico v1 data format to the
  Calico v3 data format required by Calico v3.0+.

  Before running this command, all calico/node instances should be running
  the latest 2.x release. This command temporarily pauses Calico networking
  across your cluster which means no new endpoints can be created until the
  upgrade is complete. Note that existing endpoints will continue to be
  networked with Calico during the upgrade process.

  When this command completes successfully, upgrade all of your calico/node
  instances and orchestrator plugins to the required 3.x release. Once each
  node is upgraded you can complete the upgrade using the
  'calico-update complete' command which resumes Calico networking and allows
  new endpoints to be created.

  This command generates the following set of reports (if it contains no data
  an individual report is not generated).

` + constants.ReportHelp
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
	output := parsedArgs["--output-dir"].(string)
	ignoreV3Data := parsedArgs["--ignore-v3-data"].(bool)

	// Obtain the v1 and v3 clients.
	clientv3, clientv1, err := clients.LoadClients(cfv3, cfv1)
	if err != nil {
		printFinalMessage("Failed to start the upgrade.\n"+
			"Error accessing the Calico API: %v", err)
		os.Exit(1)
	}

	// Ensure the migration code displays messages (this is basically indicating that it
	// is being called from the calico-upgrade script).
	migrate.DisplayStatusMessages(true)
	migrate.Interactive(true)

	// Ensure we are able to write the output report to the designated output directory.
	ensureDirectory(output)

	// Perform the data migration. This may return OK, Fail, FailNeedsRetry or
	// FailNeedsAbort.
	data, res := migrate.Migrate(clientv3, clientv1, ignoreV3Data)

	if res == migrate.ResultOK {
		// We migrated the data successfully. Include a report.
		printFinalMessage("Successfully migrated Calico v1 data to v3 format.\n" +
			"Follow the upgrade remaining upgrade instructions to complete the upgrade.")
		printAndOutputReport(output, data)
	} else {
		if data == nil || !data.HasErrors() {
			// We failed to migrate the data and it is not due to conversion errors. In this
			// case refer to previous messages.
			printFinalMessage("Failed to migrate Calico v1 data to v3 format.\n" +
				"See previous messages for details.")
		} else {
			// We failed to migrate the data and it appears to be due to conversion errors.
			// In this case refer to the report for details.
			printFinalMessage("Failed to migrate Calico v1 data to v3 format.\n" +
				"See reports below for details of any conversion errors.")
			printAndOutputReport(output, data)
		}

		// If we need to retry or we still need to abort then notify the user with an extra
		// message.
		if res == migrate.ResultFailNeedsRetry {
			fmt.Println("\n\nPlease retry the command.")
		} else if res == migrate.ResultFailNeedsAbort {
			fmt.Println("\n\nPlease run the `calico-upgrade abort` command to ensure Calico networking is resumed.")
		}

		os.Exit(1)
	}
}
