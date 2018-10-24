// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/projectcalico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var VERSION, GIT_REVISION string
var VERSION_SUMMARY string

func init() {
	VERSION_SUMMARY = "calicoctl version " + VERSION + ", build " + GIT_REVISION
}

func Version(args []string) {
	doc := `Usage:
  calicoctl version [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: ` + constants.DefaultConfigPath + `]

Description:
  Display the version of calicoctl.
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(1)
	}
	if len(parsedArgs) == 0 {
		return
	}

	fmt.Println("Client Version:   ", VERSION)
	fmt.Println("Git commit:       ", GIT_REVISION)

	// Load the client config and connect.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ctx := context.Background()
	ci, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		fmt.Println("Unable to retrieve Cluster Version or Type: ", err)
		os.Exit(1)
	}

	v := ci.Spec.CalicoVersion
	if v == "" {
		v = "unknown"
	}
	t := ci.Spec.ClusterType
	if t == "" {
		t = "unknown"
	}

	fmt.Println("Cluster Version:  ", v)
	fmt.Println("Cluster Type:     ", t)
}
