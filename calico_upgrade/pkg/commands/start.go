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

	"github.com/projectcalico/calico/calico_upgrade/pkg/constants"
	"github.com/projectcalico/calico/calico_upgrade/pkg/migrate"
	"github.com/projectcalico/calico/calico_upgrade/pkg/migrate/clients"
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
                               the Calico v3 API.
                               [default: ` + constants.DefaultConfigPathV3 + `]
  --apiconfigv1=<V1_APICONFIG> Path to the file containing connection
                               configuration in YAML or JSON format for
                               the Calico v1 API.
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
	ch := &cliHelper{}

	// Obtain the v1 and v3 clients.
	clientv3, clientv1, err := clients.LoadClients(cfv3, cfv1)
	if err != nil {
		ch.Separator()
		ch.Msg("Failed to start the upgrade.")
		ch.Bullet(fmt.Sprintf("Error accessing the Calico API: %v", err))
		ch.NewLine()
		os.Exit(1)
	}

	m := migrate.New(clientv3, clientv1, ch)

	// Ensure we are able to write the output report to the designated output directory.
	ensureDirectory(output)

	// Perform the validation. If this fails it will sys exit with a non-zero rc.
	data := validate(m, ch, output, ignoreV3Data)
	if len(data.Resources) == 0 {
		// For non-KDD this will be an error case and so we won't hit this.
		ch.Msg("There is no data requiring conversion. You may proceed with the upgrade without " +
			"migrating the data.")
		ch.NewLine()
		return
	}

	// The start command is interactive to prevent accidentally kicking off the migration.
	ch.NewLine()
	if clientv1.IsKDD() {
		ch.Msg("You are about to start the migration of Calico v1 data format to " +
			"Calico v3 data format. No Calico configuration should be modified using " +
			"calicoctl during this time.")
	} else {
		ch.Msg("You are about to start the migration of Calico v1 data format to " +
			"Calico v3 data format. During this time and until the upgrade is completed " +
			"Calico networking will be paused - which means no new Calico networked " +
			"endpoints can be created. No Calico configuration should be modified using " +
			"calicoctl during this time.")
	}
	ch.NewLine()
	ch.ConfirmProceed()

	// Perform the data migration.
	data, err = m.Migrate()
	if err == nil {
		ch.Separator()
		ch.Msg("Successfully migrated Calico v1 data to v3 format.")
		ch.Msg("Follow the detailed upgrade instructions available in the release " +
			"documentation to complete the upgrade.  This includes:")
		ch.Bullet("upgrading your calico/node instances and orchestrator plugins (e.g. CNI) " +
			"to the required v3.x release")
		if !clientv1.IsKDD() {
			ch.Bullet("running 'calico-upgrade complete' to complete the upgrade and " +
				"resume Calico networking")
		}
		ch.NewLine()
		ch.Msg("See report(s) below for details of the migrated data.")
		printAndOutputReport(output, data)
		ch.NewLine()
		return
	}

	// We failed to migrate. Make sure we tell the user if the error indicates
	// that an Abort is required.
	ch.Separator()
	ch.Msg("Failed to migrate Calico v1 data to v3 format.")
	me, ok := err.(migrate.MigrationError)
	if !ok {
		// We should never hit this since the errors should always be of type
		// MigrationError - but better to handle nicely.
		ch.Bullet(fmt.Sprintf("unexpected error: %v", err))
		ch.NewLine()
		os.Exit(1)
	}

	canRetry := true
	switch me.Type {
	case migrate.ErrorGeneric:
		ch.Bullet(err.Error())
	case migrate.ErrorConvertingData:
		ch.Bullet(err.Error())
		ch.Msg("Conversion errors should have been resolved during validation.  This suggests " +
			"another user is either attempting to upgrade at the same time or is modifying " +
			"Calico configuration during the upgrade.")
		ch.NewLine()
		ch.Msg("See report(s) below for details of the converted data.")
		printAndOutputReport(output, data)
	case migrate.ErrorMigratingData:
		ch.Bullet(fmt.Sprintf(err.Error()))
		ch.NewLine()
		ch.Msg("Please note that the migration script may have written data into the " +
			"v3 datastore. We recommend that you remove the Calico data from the v3 " +
			"datastore before proceeding.")
		canRetry = false
	}

	if me.NeedsAbort && !clientv1.IsKDD() {
		ch.NewLine()
		ch.Msg("IMPORTANT NOTE: The command was unable to abort the migration leaving Calico networking " +
			"in a paused state (no new endpoints will be able to be deployed). Please run the " +
			"abort command to resume normal service.")
		ch.Msg("See previous output for additional details.")
		canRetry = false
	}

	if canRetry {
		ch.NewLine()
		ch.Msg("Please resolve the errors and retry the command.")
	}
	ch.NewLine()
	os.Exit(1)
}
