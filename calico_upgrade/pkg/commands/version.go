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
)

var VERSION, BUILD_DATE, GIT_REVISION string
var VERSION_SUMMARY string

func init() {
	VERSION_SUMMARY = "calico-upgrade version " + VERSION + ", build " + GIT_REVISION
}

func Version(args []string) {
	doc := `Usage:
  calico-upgrade version

Options:
  -h --help             Show this screen.

Description:
  Display the version of calico-upgrade.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option:\n  calico-upgrade %s\nUse flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
	}

	fmt.Println("Client Version:   ", VERSION)
	fmt.Println("Build date:       ", BUILD_DATE)
	fmt.Println("Git commit:       ", GIT_REVISION)
}
