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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/app-policy/pkg/dikastes"
	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	goldmane "github.com/projectcalico/calico/goldmane/pkg/daemon"
	guardian "github.com/projectcalico/calico/guardian/pkg/daemon"
	"github.com/projectcalico/calico/key-cert-provisioner/pkg/keycert"
	"github.com/projectcalico/calico/kube-controllers/pkg/kubecontrollers"
	"github.com/projectcalico/calico/node/pkg/node"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/pod2daemon/pkg/csi"
	"github.com/projectcalico/calico/pod2daemon/pkg/flexvol"
	typha "github.com/projectcalico/calico/typha/pkg/daemon"
	"github.com/projectcalico/calico/webhooks/pkg/webhook"
	whiskerbackend "github.com/projectcalico/calico/whisker-backend/cmd/app"
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "calico",
		Short:        "Calico networking and security",
		Long:         "Calico is an open source networking and network security solution for containers, virtual machines, and native host-based workloads.",
		SilenceUsage: true,
	}

	// Components with NewCommand() in their package.
	cmd.AddCommand(
		goldmane.NewCommand(),
		guardian.NewCommand(),
		whiskerbackend.NewCommand(),
		keycert.NewCommand(),
		typha.NewCommand(),
		kubecontrollers.NewCommand(),
		dikastes.NewCommand(),
		csi.NewCommand(),
		flexvol.NewCommand(),
		webhook.NewCommand(),
		node.NewCommand(),
	)

	// Components with their own CLI framework that need shims.
	cmd.AddCommand(
		newAPIServerCommand(),
		newCtlCommand(),
		newCNICommand(),
	)

	// Health and utility commands.
	cmd.AddCommand(
		newHealthCommand(),
		newKubeControllersHealthCommand(),
		newVersionCommand(),
	)

	return cmd
}

func main() {
	// When installed as a CNI plugin on the host, the binary may be invoked
	// directly by the container runtime. Detect this and dispatch accordingly.
	_, filename := filepath.Split(os.Args[0])
	switch filename {
	case "calico-ipam", "calico-ipam.exe":
		ipamplugin.Main(buildinfo.Version)
		return
	case "calicoctl", "calicoctl.exe":
		// Dispatch to ctl subcommand when invoked as calicoctl.
		os.Args = append([]string{"calico", "ctl"}, os.Args[1:]...)
	}
	if os.Getenv("CNI_COMMAND") != "" {
		plugin.Main(buildinfo.Version)
		return
	}

	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
