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

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Unlock unlocks the datastore to complete migration. This once again allows
// Calico resources to take effect in the cluster.
func Unlock(config string, allowVersionMismatch bool) error {
	if err := common.CheckVersionMismatch(config, allowVersionMismatch); err != nil {
		return err
	}

	client, err := clientmgr.NewClient(config)
	if err != nil {
		return err
	}

	// Get the cluster information resource
	ctx := context.Background()
	clusterinfo, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("error retrieving ClusterInformation for unlocking: %s", err)
	}

	// Change the Datastore to not ready in order to lock it.
	t := true
	clusterinfo.Spec.DatastoreReady = &t

	// Update the cluster information resource
	_, err = client.ClusterInformation().Update(ctx, clusterinfo, options.SetOptions{})
	if err != nil {
		return fmt.Errorf("error updating ClusterInformation for unlocking: %s", err)
	}

	fmt.Print("Datastore unlocked.\n")
	return nil
}
