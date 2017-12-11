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

	"github.com/docopt/docopt-go"
	"github.com/projectcalico/calicoctl/calicoctl/commands"
	log "github.com/sirupsen/logrus"
)

func main() {
	doc := `Usage:
  calicoctl [options] <command> [<args>...]

    create    Create a resource by filename or stdin.
    replace   Replace a resource by filename or stdin.
    apply     Apply a resource by filename or stdin.  This creates a resource
              if it does not exist, and replaces a resource if it does exists.
    delete    Delete a resource identified by file, stdin or resource type and
              name.
    get       Get a resource identified by file, stdin or resource type and
              name.
    convert   Convert config files between different API versions.
    ipam      IP address management.
    node      Calico node management.
    version   Display the version of calicoctl.

Options:
  -h --help               Show this screen.
  -l --log-level=<level>  Set the log level (one of panic, fatal, error,
                          warn, info, debug) [default: panic]

Description:
  The calicoctl command line tool is used to manage Calico network and security
  policy, to view and manage endpoint configuration, and to manage a Calico
  node instance.

  See 'calicoctl <command> --help' to read about a specific subcommand.
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
		case "create":
			commands.Create(args)
		case "replace":
			commands.Replace(args)
		case "apply":
			commands.Apply(args)
		case "delete":
			commands.Delete(args)
		case "get":
			commands.Get(args)
		case "convert":
			commands.Convert(args)
		case "version":
			commands.Version(args)
		case "node":
			commands.Node(args)
		case "ipam":
			commands.IPAM(args)
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %q\n", command)
			fmt.Println(doc)
			os.Exit(1)
		}
	}
}
