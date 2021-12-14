// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package migrate

import (
	"context"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func Unlock(args []string) error {
	doc := `Usage:
  <BINARY_NAME> datastore migrate unlock [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  Unlock the datastore to complete migration. This once again allows
  Calico resources to take effect in the cluster.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	err = common.CheckVersionMismatch(parsedArgs["--config"], parsedArgs["--allow-version-mismatch"])
	if err != nil {
		return err
	}

	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	// Get the cluster information resource
	ctx := context.Background()
	clusterinfo, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("Error retrieving ClusterInformation for unlocking: %s", err)
	}

	// Change the Datastore to not ready in order to lock it.
	t := true
	clusterinfo.Spec.DatastoreReady = &t

	// Update the cluster information resource
	_, err = client.ClusterInformation().Update(ctx, clusterinfo, options.SetOptions{})
	if err != nil {
		return fmt.Errorf("Error updating ClusterInformation for unlocking: %s", err)
	}

	fmt.Print("Datastore unlocked.\n")
	return nil
}
