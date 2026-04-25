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

	"github.com/projectcalico/calico/node/pkg/node"
)

// newComponentCommand on Windows registers the subset of in-cluster components
// that cross-compile (node, felix, confd). The Linux-only components — typha,
// pod2daemon (csi/flexvol), kube-controllers, goldmane, guardian, dikastes,
// key-cert-provisioner, webhooks, whisker-backend, apiserver — depend on
// syscall.Mount, syslog, eBPF, and other Linux-only facilities and are not
// included in the Windows binary.
func newComponentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component",
		Short: "Run Calico components (internal use by the operator)",
	}

	cmd.AddCommand(
		node.NewCommand(),
		node.NewFelixCommand(),
		node.NewConfdCommand(),
	)

	return cmd
}
