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
	"github.com/projectcalico/calico/calico_upgrade/pkg/commands/constants"
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
  --output-dir=<OUTPUTDIR>     Directory in which the data migration reports
                               are written to.
                               [default: ` + constants.GetDefaultOutputDir() + `]
  --ignore-v3-data             Ignore any existing Calico data that is in the
                               v3 format.  The migrated data will overwrite
                               any common resources, and leave other resources
                               unchanged.  If there is v3 data present, we
                               recommend you remove all Calico data from the
                               v3 datastore before upgrading, however, this
                               option may be used if that is not possible, or
                               if you know all of the data present will be
                               updated by the upgrade.

Description:
  Start the upgrade process to migrate from the Calico v1 data format to the
  Calico v3 data format required by Calico v3.0+.

  Before running this command, all calico/node instances should be running
  the latest 2.x release.  This command will temporarily pause Calico
  networking across your cluster which means no new endpoints can be created
  until the upgrade is complete.  Note that existing endpoints will continue
  to be networked with Calico during the upgrade process.

  When this command completes successfully, upgrade all of your calico/node
  instances to the required 3.x release.  Once each node is upgrade you can
  complete the upgrade using the 'calico-update complete' command which will
  unpause Calico networking and allow new endpoints to be created.

  This command generates the following set of reports (if it contains no data
  an individual report is not generated).

    ` + constants.FileConvertedNames + `
      This contains a mapping between the v1 resource name and the v3 resource
      name.  This will contain an entry for every v1 resource that was
      migrated.

    ` + constants.FileNameClashes + `
      This contains a list of resources that after conversion to v3 have
      names that are identical to other converted resources.  This may occur
      because name formats in Calico v3 are in some cases more restrictive
      than previous versions and the mapping used to convert a v1 name to a
      v3 name is algorithmic.  Generally, name clashes should be rare.

    ` + constants.FileConversionErrors + `
      This contains a full list of all of the errors converting the v1 data to
      v3 format.  There may be multiple conversion errors for a single
      resource.  Provided the v1 format data is correct, conversion errors
      should be rare.

    ` + constants.FilePolicyController + `
      This contains a list of the v1 resources that we are not migrating
      because the name of the resource indicates that the resource is created
      by the policy controller and will automatically be created when the
      policy controller is upgraded.

    ` + constants.FileValidationErrors + `
      This contains a list of errors that occurred when validating the v3
      resources that were otherwise successfully converted from v1.  These
      errors usually suggest an issue with the migration script itself and it
      is recommended to raise a GitHub issue at
         https://github.com/projectcalico/calico/issues
      and await a patch before continuing with the upgrade.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option: 'calico-upgrade %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
	}
	cfv3 := parsedArgs["--apiconfigv3"].(string)
	cfv1 := parsedArgs["--apiconfigv1"].(string)
	ignoreV3Data := parsedArgs["--ignore-v3-data"].(bool)
	output := parsedArgs["--output-dir"].(string)

	// Ensure we are able to write the output report to the designated output directory.
	ensureDirectory(output)

	// Obtain the v1 and v3 clients.
	clientv3, clientv1, err := clients.LoadClients(cfv3, cfv1)
	if err != nil {
		fmt.Printf("Failed to access the Calico API: %s\n", err)
		fmt.Println(constants.Exiting)
		os.Exit(1)
	}

	// Ensure the migration code displays messages (this is basically indicating that it
	// is being called from the calico-upgrade script).
	migrate.DisplayStatusMessages(true)

	// Perform the data migration.
	data, res := migrate.Migrate(clientv3, clientv1, ignoreV3Data)

	if res == migrate.ResultOK {
		// We migrated the data successfully.  Include a report.
		printFinalMessage("Successfully migrated Calico v1 data to v3 format.\n" +
			"Follow the upgrade remaining upgrade instructions to complete the upgrade.")
		printAndOutputReport(output, data)
	} else {
		if data == nil || !data.HasErrors() {
			// We failed to migrate the data and it is not due to conversion errors.  In this
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
			fmt.Println("\n\nPlease run the `calico-upgrade abort` command to ensure Calico networking is unpaused.")
		}

		os.Exit(1)
	}
}
