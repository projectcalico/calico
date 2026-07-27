// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/networkpolicy"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func MigratePolicyNames(args []string) error {
	doc := `Usage:
  <BINARY_NAME> datastore migrate-policy-names [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  Rewrite policy names in the datastore to drop the legacy "default." tier
  prefix, aligning the stored name with the v3 resource name introduced in
  v3.32.

  This is only needed for an etcdv3 datastore (for example OpenStack) that was
  created before v3.32 and upgraded in place. A Kubernetes datastore is
  migrated automatically by kube-controllers. The command is safe to re-run.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	err = common.CheckVersionMismatch(parsedArgs["--config"], parsedArgs["--allow-version-mismatch"])
	if err != nil {
		return err
	}

	cf := parsedArgs["--config"].(string)
	c, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}

	ca, ok := c.(bapi.BackendAccessor)
	if !ok {
		return fmt.Errorf("configured client does not expose a datastore backend")
	}

	migrated, err := migratePolicyNames(context.Background(), ca.Backend())
	if err != nil {
		return err
	}

	fmt.Printf("Policy name migration complete, migrated %d policies.\n", migrated)
	return nil
}

// migratePolicyNames rewrites every tiered policy whose datastore name still
// differs from its v3 name, returning the number migrated. It stops at the first
// error; because each rewrite is idempotent the command can simply be re-run.
func migratePolicyNames(ctx context.Context, bc bapi.Client) (int, error) {
	migrated := 0
	for _, kind := range networkpolicy.PolicyKinds {
		kvps, err := bc.List(ctx, model.ResourceListOptions{Kind: kind}, "")
		if err != nil {
			return migrated, fmt.Errorf("list %s: %w", kind, err)
		}
		for _, kvp := range kvps.KVPairs {
			did, err := networkpolicy.MigratePolicyKVP(ctx, bc, kvp)
			if err != nil {
				return migrated, err
			}
			if did {
				migrated++
			}
		}
	}
	return migrated, nil
}
