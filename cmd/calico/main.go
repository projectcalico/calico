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

	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "calico",
		Short:        "Calico networking and security",
		Long:         "Calico is an open source networking and network security solution for containers, virtual machines, and native host-based workloads.",
		SilenceUsage: true,
	}

	// Component subcommands (internal use by the operator).
	cmd.AddCommand(newComponentCommand())

	// User-facing commands.
	cmd.AddCommand(
		newCtlCommand(),
		newHealthCommand(),
		newVersionCommand(),
	)

	return cmd
}

func main() {
	// When installed as a CNI plugin or as calicoctl, the binary may be
	// invoked directly by the container runtime or as a symlink. Detect
	// these invocations and dispatch accordingly.
	_, filename := filepath.Split(os.Args[0])
	switch filename {
	case "calico-ipam":
		ipamplugin.Main(buildinfo.Version)
		return
	case "calicoctl":
		// Dispatch to the ctl subcommand. Insert "ctl" between argv[0] and
		// the original args rather than replacing argv[0]; this preserves
		// os.Args[0] for anything downstream that reads it (panic traces,
		// log prefixes, kubectl-plugin detection).
		os.Args = append([]string{os.Args[0], "ctl"}, os.Args[1:]...)
	default:
		// CNI_COMMAND is the env-based dispatch used when the container
		// runtime invokes the CNI plugin directly. Only honor it when no
		// subcommand was passed, so that e.g. "calicoctl get nodes" run
		// in a shell that happens to have CNI_COMMAND set doesn't silently
		// dispatch to the plugin.
		if len(os.Args) == 1 && os.Getenv("CNI_COMMAND") != "" {
			plugin.Main(buildinfo.Version)
			return
		}
	}

	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
