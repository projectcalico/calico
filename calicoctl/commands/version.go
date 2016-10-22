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

	"github.com/docopt/docopt-go"
)

var VERSION, BUILD_DATE, GIT_REVISION string
var VERSION_SUMMARY string

func init() {
	VERSION_SUMMARY = "calicoctl version " + VERSION + ", build " + GIT_REVISION
}

func Version(args []string) error {
	doc := `Usage:
  calicoctl version

Options:
  -h --help   Show this screen.

Description:
  Display the version of calicoctl.`
	arguments, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return err
	}
	if len(arguments) == 0 {
		return nil
	}

	fmt.Println("Version:     ", VERSION)
	fmt.Println("Build date:  ", BUILD_DATE)
	fmt.Println("Git commit:  ", GIT_REVISION)
	return nil
}
