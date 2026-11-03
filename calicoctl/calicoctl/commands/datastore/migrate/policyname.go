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

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/networkpolicy"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// MigratePolicyNames rewrites default-tier policy names in an etcdv3 datastore to
// drop the legacy tier prefix, matching the v3 name introduced in v3.32. Safe to re-run.
func MigratePolicyNames(config string, allowVersionMismatch bool) error {
	if err := common.CheckVersionMismatch(config, allowVersionMismatch); err != nil {
		return err
	}

	c, err := clientmgr.NewClient(config)
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
