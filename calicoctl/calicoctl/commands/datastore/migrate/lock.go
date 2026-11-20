// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Lock locks the datastore to prepare it for migration. This prevents any new
// Calico resources from affecting the cluster but does not prevent updating or
// creating new Calico resources.
func Lock(config string, allowVersionMismatch bool) error {
	if err := common.CheckVersionMismatch(config, allowVersionMismatch); err != nil {
		return err
	}

	// Native v3 CRD mode rejects user writes to ClusterInformation, so say so
	// up front instead of surfacing the webhook's denial.
	cfg, err := clientmgr.LoadClientConfig(config)
	if err != nil {
		return err
	}
	if err := checkLockSupported(cfg, "lock"); err != nil {
		return err
	}
	client, err := clientmgr.NewClientFromConfig(cfg)
	if err != nil {
		return err
	}

	// Ensure that the cluster information resource is initialized.
	ctx := context.Background()
	if err := client.EnsureInitialized(ctx, "", ""); err != nil {
		return fmt.Errorf("unable to initialize cluster information for the datastore migration: %s", err)
	}

	// Get the cluster information resource
	clusterinfo, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("error retrieving ClusterInformation for locking: %s", err)
	}

	// Change the Datastore to not ready in order to lock it.
	f := false
	clusterinfo.Spec.DatastoreReady = &f

	// Update the cluster information resource
	_, err = client.ClusterInformation().Update(ctx, clusterinfo, options.SetOptions{})
	if err != nil {
		return fmt.Errorf("error updating ClusterInformation for locking: %s", err)
	}

	fmt.Print("Datastore locked.\n")
	return nil
}

// checkLockSupported returns an error when the datastore uses native
// projectcalico.org/v3 CRDs. In that mode an admission webhook lets only Calico
// components write ClusterInformation, so calicoctl can neither lock nor unlock
// the datastore. action names the operation for the error message.
func checkLockSupported(cfg *apiconfig.CalicoAPIConfig, action string) error {
	if cfg.Spec.DatastoreType != apiconfig.Kubernetes || !k8s.UsingV3CRDs(&cfg.Spec) {
		return nil
	}
	return fmt.Errorf("cannot %s the datastore: this cluster uses native projectcalico.org/v3 CRDs, "+
		"where ClusterInformation is read-only to users and only Calico components can change datastoreReady", action)
}
