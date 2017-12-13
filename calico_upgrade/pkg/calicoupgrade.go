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

package main

import (
	"fmt"
	"os"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calico_upgrade/pkg/commands"
	"github.com/projectcalico/libcalico-go/lib/logutils"
)

func main() {
	doc := `Usage:
  calico-upgrade [options] <command> [<args>...]

    dry-run   Perform a dry-run of the data migration. This validates that the
              v1 formatted data will be successfully converted and that the v3
              datastore is in the correct state for the data migration. This
              command outputs a full report of any migrated names, migration
              errors, or migrated name conflicts. See Description section
              below for details.
    start     Start the upgrade process. This does the following:
              -  performs a dry-run to verify the data will be migrated
                 successfully
              -  pauses Calico networking: this prevents new endpoints from
                 being created while allowing existing endpoints to remain
                 networked
              -  migrates the data from v1 to v3 format
    complete  This resumes Calico networking for the v3.x nodes.
    abort     This aborts the upgrade process by resuming Calico networking
              for the v2.x nodes.
    version   Display the version of calico-upgrade.

Options:
  -h --help               Show this screen.
  -l --log-level=<level>  Set the log level (one of panic, fatal, error,
                          warn, info, debug) [default: panic]

Description:
  The calico-upgrade command line tool is used to assist with the migration of
  v1-formatted data to the v3 format used by Calico v3.x.

  See 'calico-upgrade <command> --help' to read about a specific subcommand.
`
	arguments, _ := docopt.Parse(doc, nil, true, commands.VERSION_SUMMARY, true, false)

	log.AddHook(logutils.ContextHook{})
	log.SetFormatter(&logutils.Formatter{})
	log.SetLevel(log.PanicLevel)
	if logLevel := arguments["--log-level"]; logLevel != nil {
		parsedLogLevel, err := log.ParseLevel(logLevel.(string))
		if err != nil {
			fmt.Printf("Unknown log level: %s, expected one of: \n"+
				"panic, fatal, error, warn, info, debug.\n", logLevel)
			os.Exit(1)
		} else {
			log.SetLevel(parsedLogLevel)
			log.Infof("Log level set to %v", parsedLogLevel)
		}
	}

	if arguments["<command>"] != nil {
		command := arguments["<command>"].(string)
		args := append([]string{command}, arguments["<args>"].([]string)...)

		switch command {
		case "dry-run":
			commands.DryRun(args)
		case "start":
			commands.Start(args)
		case "complete":
			commands.Complete(args)
		case "abort":
			commands.Abort(args)
		case "version":
			commands.Version(args)
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %q\n", command)
			fmt.Println(doc)
			os.Exit(1)
		}
	}
}
