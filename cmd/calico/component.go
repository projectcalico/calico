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

	"github.com/projectcalico/calico/app-policy/pkg/dikastes"
	"github.com/projectcalico/calico/goldmane/cmd/goldmane"
	"github.com/projectcalico/calico/guardian/cmd/guardian"
	"github.com/projectcalico/calico/key-cert-provisioner/pkg/keycert"
	"github.com/projectcalico/calico/kube-controllers/pkg/kubecontrollers"
	"github.com/projectcalico/calico/node/pkg/node"
	"github.com/projectcalico/calico/pod2daemon/pkg/csi"
	"github.com/projectcalico/calico/pod2daemon/pkg/flexvol"
	"github.com/projectcalico/calico/typha/cmd/typha"
	"github.com/projectcalico/calico/webhooks/pkg/webhook"
	"github.com/projectcalico/calico/whisker-backend/cmd/whiskerbackend"
)

func newComponentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component",
		Short: "Run Calico components (internal use by the operator)",
	}

	// Top-level components — each is a standalone daemon.
	cmd.AddCommand(
		node.NewFelixCommand(),
		node.NewConfdCommand(),
		goldmane.NewCommand(),
		guardian.NewCommand(),
		whiskerbackend.NewCommand(),
		keycert.NewCommand(),
		typha.NewCommand(),
		dikastes.NewCommand(),
		csi.NewCommand(),
		flexvol.NewCommand(),
		webhook.NewCommand(),
		kubecontrollers.NewCommand(),
	)

	// Components with their own CLI framework that need shims.
	cmd.AddCommand(
		newAPIServerCommand(),
		newCNICommand(),
	)

	// Node lifecycle operations.
	cmd.AddCommand(node.NewCommand())

	return cmd
}
