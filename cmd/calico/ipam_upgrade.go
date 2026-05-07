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

package main

import (
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
)

func newIPAMUpgradeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ipam-upgrade",
		Short: "Migrate node IP allocations from host-local to calico-ipam",
		Long: `Migrate the node's IP allocations from the host-local CNI IPAM
plugin to calico-ipam. Reads the node name from the KUBERNETES_NODE_NAME
environment variable and writes a marker file once migration succeeds so
subsequent invocations are a no-op.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ipamplugin.RunUpgrade(cmd.Context())
		},
	}
}
