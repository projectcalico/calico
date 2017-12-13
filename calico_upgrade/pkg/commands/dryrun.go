// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

func DryRun(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calico-upgrade dry-run
      [--apiconfigv3=<V3_APICONFIG>]
      [--apiconfigv1=<V1_APICONFIG>]
      [--output-dir=<OUTPUTDIR>]
      [--ignore-v3-data]

Example:
  calico-upgrade dry-run --apiconfigv3=/path/to/v3/config --apiconfigv1=/path/to/v1/config

Options:
  -h --help                    Show this screen.
  --apiconfigv3=<V3_APICONFIG> Path to the file containing connection
                               configuration in YAML or JSON format for
                               the Calico v3 API.
                               [default: ` + constants.DefaultConfigPathV3 + `]
  --apiconfigv1=<V1_APICONFIG> Path to the file containing connection
                               configuration in YAML or JSON format for
                               the Calico v1 API.
                               [default: ` + constants.DefaultConfigPathV1 + `]
  --output-dir=<OUTPUTDIR>     Directory to store the data migration reports in.
                               [default: ` + constants.GetDefaultOutputDir() + `]
  --ignore-v3-data             Ignore any existing Calico data that is in the
                               v3 format. If there is v3 data present, we
                               recommend you remove all Calico data from the
                               v3 datastore before upgrading, however, this
                               option may be used if that is not possible, or
                               if you know all of the data present will be
                               updated by the upgrade.

Description:
  This command performs a dry-run of the data migration. This validates that
  the v1 formatted data will be successfully converted and that the v3
  datastore is in the correct state for the data migration.

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
	ch := &cliHelper{}

	// Obtain the v1 and v3 clients.
	clientv3, clientv1, err := clients.LoadClients(cfv3, cfv1)
	if err != nil {
		ch.Separator()
		ch.Msg("Failed to validate v1 to v3 conversion.")
		ch.Bullet(fmt.Sprintf("Error accessing the Calico API: %v", err))
		ch.NewLine()
		os.Exit(1)
	}

	m := migrate.New(clientv3, clientv1, ch)

	// Ensure we are able to write the output report to the designated output directory.
	ensureDirectory(output)

	// Perform the validation.
	data := validate(m, ch, output, ignoreV3Data)
	if len(data.Resources) == 0 {
		// For non-KDD this will be an error case and so we won't hit this.
		ch.Msg("There is no data requiring conversion. You may proceed with the upgrade without " +
			"migrating the data.")
	} else {
		ch.Msg("See report(s) below for details of the conversion.")
		printAndOutputReport(output, data)
	}
	ch.NewLine()
}

// validate performs the migration validation that is shared by both the dry-run
// command and the start command. Returns true if there is data to migrate, false
// otherwise.
func validate(m migrate.Interface, ch *cliHelper, output string, ignoreV3Data bool) *migrate.MigrationData {
	// Validate the conversion and that the destination is empty.
	data, cerr := m.ValidateConversion()
	clean, derr := m.IsDestinationEmpty()

	// If we didn't hit any conversion errors and the destination is clean (or the --ignore-v3-data
	// option is set), then the validation was successful.
	if cerr == nil && derr == nil && (clean || ignoreV3Data) {
		ch.Separator()
		ch.Msg("Successfully validated v1 to v3 conversion.")
		return data
	}

	// We hit an error in one of the validations. Output final messages to include details of
	// both validations.
	ch.Separator()
	ch.Msg("Failed to validate v1 to v3 conversion.")
	if data != nil && data.HasErrors() {
		ch.Bullet("errors converting data, see report(s) below for details")
	} else if cerr != nil {
		ch.Bullet(cerr.Error())
	}
	if !clean && !ignoreV3Data {
		ch.Bullet("The v3 datastore is not clean. We recommend that you remove any calico " +
			"data before attempting the upgrade. If you want to keep the existing v3 data, you may use " +
			"the '--ignore-v3-data' flag when running the 'start-upgrade' command to force the upgrade, in which " +
			"case the v1 data will be converted and will overwrite matching entries in the v3 datastore.")
	} else if derr != nil {
		ch.Bullet(derr.Error())
	}
	// Include the report for any errors.
	if data != nil && data.HasErrors() {
		printAndOutputReport(output, data)
	}
	ch.NewLine()
	os.Exit(1)
	return nil
}
