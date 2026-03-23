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

	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "calico",
		Short: "Calico networking and security",
		Long:  "Calico is an open source networking and network security solution for containers, virtual machines, and native host-based workloads.",
		// Don't show usage on errors from subcommands.
		SilenceUsage: true,
	}

	cmd.AddCommand(
		newGoldmaneCommand(),
		newGuardianCommand(),
		newWhiskerBackendCommand(),
		newKeyCertCommand(),
		newTyphaCommand(),
		newKubeControllersCommand(),
		newCheckStatusCommand(),
		newAPIServerCommand(),
		newWebhooksCommand(),
		newDikastesCommand(),
		newHealthzCommand(),
		newCSICommand(),
		newVersionCommand(),
	)

	return cmd
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
