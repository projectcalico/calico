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

package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/cluster"
)

func newClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Access cluster information",
	}
	cmd.AddCommand(newClusterDiagsCommand())
	return cmd
}

func newClusterDiagsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diags",
		Short: "Collect snapshot of diagnostic info and logs related to Calico at the cluster-level",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Build the args array for the existing docopt-based implementation.
			synthArgs := []string{"cluster", "diags"}
			if since, _ := cmd.Flags().GetString("since"); since != "" {
				synthArgs = append(synthArgs, "--since="+since)
			}
			if maxLogs, _ := cmd.Flags().GetInt("max-logs"); maxLogs != 5 {
				synthArgs = append(synthArgs, fmt.Sprintf("--max-logs=%d", maxLogs))
			}
			if maxP, _ := cmd.Flags().GetInt("max-parallelism"); maxP != 10 {
				synthArgs = append(synthArgs, fmt.Sprintf("--max-parallelism=%d", maxP))
			}
			if nodes, _ := cmd.Flags().GetString("focus-nodes"); nodes != "" {
				synthArgs = append(synthArgs, "--focus-nodes="+nodes)
			}
			if config, _ := cmd.Flags().GetString("config"); config != "" {
				synthArgs = append(synthArgs, "--config="+config)
			}
			if skip, _ := cmd.Flags().GetBool("skip-temp-dir-cleanup"); skip {
				synthArgs = append(synthArgs, "--skip-temp-dir-cleanup")
			}
			if allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch"); allowMismatch {
				synthArgs = append(synthArgs, "--allow-version-mismatch")
			}
			return cluster.Diags(synthArgs)
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().String("since", "", "Only collect logs newer than provided relative duration (e.g. 30m, 2h).")
	cmd.Flags().Int("max-logs", 5, "Only collect up to this number of logs, for each kind of Calico component.")
	cmd.Flags().Int("max-parallelism", 10, "Maximum number of parallel threads to use for collecting logs.")
	cmd.Flags().String("focus-nodes", "", "Comma-separated list of nodes from which to try first to collect logs.")
	cmd.Flags().Bool("skip-temp-dir-cleanup", false, "Don't clean up the temporary directory.")
	return cmd
}
