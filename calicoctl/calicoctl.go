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
	"flag"
	"fmt"

	"os"

	"github.com/docopt/docopt-go"
	"github.com/tigera/libcalico-go/calicoctl/commands"
)

func main() {
	usage := `Usage: calicoctl <command> [<args>...]

    create         Create a resource by filename or stdin.
    replace        Replace a resource by filename or stdin.
    apply          Apply a resource by filename or stdin.  This creates a resource if
                   it does not exist, and replaces a resource if it does exists.
    delete         Delete a resource identified by file, stdin or resource type and name.
    get            Get a resource identified by file, stdin or resource type and name.
    version        Display the version of calicoctl.

See 'calicoctl <command> --help' to read about a specific subcommand.`
	var err error
	doc := commands.EtcdIntro + usage

	if os.Getenv("GLOG") != "" {
		flag.Parse()
		flag.Lookup("logtostderr").Value.Set("true")
		flag.Lookup("v").Value.Set("10")
	}

	arguments, _ := docopt.Parse(doc, nil, true, "calicoctl", true, false)

	if arguments["<command>"] != nil {
		command := arguments["<command>"].(string)
		args := append([]string{command}, arguments["<args>"].([]string)...)

		switch command {
		case "create":
			err = commands.Create(args)
		case "replace":
			err = commands.Replace(args)
		case "apply":
			err = commands.Apply(args)
		case "delete":
			err = commands.Delete(args)
		case "get":
			err = commands.Get(args)
		case "version":
			err = commands.Version(args)
		default:
			fmt.Println(usage)
		}
	}

	if err != nil {
		os.Exit(1)
	}
}
