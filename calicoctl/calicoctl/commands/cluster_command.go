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
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/cluster"
)

func newClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Access cluster information",
		Long:  `Access cluster-wide Calico information.`,
	}
	cmd.AddCommand(newClusterDiagsCommand())
	return cmd
}

func newClusterDiagsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diags",
		Short: "Collect snapshot of diagnostic info and logs related to Calico at the cluster-level",
		Long: `Collect a snapshot of cluster-wide Calico diagnostics and logs. Unlike node
diags, which runs on a single host, this gathers information across the
cluster.`,
		Example: `  calicoctl cluster diags`,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			since, _ := cmd.Flags().GetString("since")
			maxLogs, _ := cmd.Flags().GetInt("max-logs")
			maxParallelism, _ := cmd.Flags().GetInt("max-parallelism")
			focusNodes, _ := cmd.Flags().GetString("focus-nodes")
			skipTempDirCleanup, _ := cmd.Flags().GetBool("skip-temp-dir-cleanup")
			return cluster.Diags(config, since, maxLogs, maxParallelism, focusNodes, skipTempDirCleanup)
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
