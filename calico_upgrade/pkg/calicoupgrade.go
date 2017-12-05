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

package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/docopt/docopt-go"
	"github.com/projectcalico/calico/calico_upgrade/pkg/commands"
)

func main() {
	doc := `Usage:
  calico-upgrade [options] <command> [<args>...]

    validate
    start-upgrade
    complete-upgrade
    convert-manifest

Options:
  -h --help               Show this screen.
  -l --log-level=<level>  Set the log level (one of panic, fatal, error,
                          warn, info, debug) [default: panic]

Description:
  The calico-upgrade command line tool is used to assist with the migration of Calico v2 data
  when upgrading your deployment to Calico v3.

  See 'calico-upgrade <command> --help' to read about a specific subcommand.
`
	arguments, _ := docopt.Parse(doc, nil, true, commands.VERSION_SUMMARY, true, false)

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
		case "validate":
			commands.Validate(args)
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %q\n", command)
			fmt.Println(doc)
			os.Exit(1)
		}
	}
}
