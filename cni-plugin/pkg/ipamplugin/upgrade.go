// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package ipamplugin

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/pkg/upgrade"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// RunUpgrade migrates the node's IP allocations from host-local IPAM to
// calico-ipam. The node name is read from KUBERNETES_NODE_NAME. The migration
// loop retries on transient errors until ctx is cancelled or it succeeds.
func RunUpgrade(ctx context.Context) error {
	logrus.Info("migrating from host-local to calico-ipam...")

	nodename := os.Getenv("KUBERNETES_NODE_NAME")
	if nodename == "" {
		return fmt.Errorf("KUBERNETES_NODE_NAME not specified, refusing to migrate")
	}
	logCtxt := logrus.WithField("node", nodename)

	cfg, err := apiconfig.LoadClientConfig("")
	if err != nil {
		return fmt.Errorf("failed to load api client config: %w", err)
	}
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	calicoClient, err := client.New(*cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize api client: %w", err)
	}

	for {
		if err := upgrade.Migrate(ctx, calicoClient, nodename); err == nil {
			break
		} else if ctx.Err() != nil {
			return fmt.Errorf("ipam migration aborted: %w", ctx.Err())
		} else {
			logCtxt.WithError(err).Error("failed to migrate ipam, retrying...")
			time.Sleep(time.Second)
		}
	}
	logCtxt.Info("migration from host-local to calico-ipam complete")
	return nil
}
