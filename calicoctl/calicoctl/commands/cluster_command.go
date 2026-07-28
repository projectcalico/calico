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
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
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
cluster, and bundles it into a .tar.gz file.

Run in an interactive terminal with no targeting flags, it starts a wizard: it
asks whether the problem affects particular pods or nodes, lets you pick them
from a list, suggests healthy nodes or pods to collect alongside for comparison,
and asks when the problem started and how each affected pod/node is involved. A
confirmation screen shows exactly what will be collected before anything runs.
Those answers and targeting choices - and the time they were made - are saved in
bundle-info.yaml at the top of the bundle.

The problem and comparison nodes are collected in full. Every other node is
swept for logs up to the --max-logs cap (5 per kind of Calico pod, e.g.
calico-node or Typha) to keep the bundle a reasonable size.

For scripts and pipelines (or any non-interactive run), give the targeting
directly: --problem-nodes / --problem-pods for the affected nodes (collected in
full, exempt from --max-logs), --comparison-nodes for healthy nodes to contrast
against, and --focus-nodes to prefer particular nodes when spending the
--max-logs budget. With no targeting flags at all, it collects from every node.

Collection is resilient to a stuck cluster: a command that produces no output
for --command-timeout is killed (and noted in the bundle), the whole run is
abandoned after --overall-timeout, and Ctrl-C stops it early. In every case a
bundle of whatever was collected so far is still written.`,
		Example: `  # Ask where the problem is, then collect (interactive terminals only).
  calicoctl cluster diags

  # Target the affected nodes directly, with two healthy nodes for contrast.
  calicoctl cluster diags --problem-nodes=worker-1,worker-2 --comparison-nodes=worker-7,worker-8

  # Target by pod; the nodes hosting them are collected in full.
  calicoctl cluster diags --problem-pods=calico-system/calico-node-abcde`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := cluster.Options{}
			opts.Config, _ = cmd.Flags().GetString("config")
			opts.MaxLogs, _ = cmd.Flags().GetInt("max-logs")
			opts.MaxParallelism, _ = cmd.Flags().GetInt("max-parallelism")
			opts.CommandTimeout, _ = cmd.Flags().GetString("command-timeout")
			opts.OverallTimeout, _ = cmd.Flags().GetString("overall-timeout")
			opts.FocusNodes, _ = cmd.Flags().GetString("focus-nodes")
			opts.ProblemNodes, _ = cmd.Flags().GetString("problem-nodes")
			opts.ProblemPods, _ = cmd.Flags().GetString("problem-pods")
			opts.ComparisonNodes, _ = cmd.Flags().GetString("comparison-nodes")
			opts.SkipTempDirCleanup, _ = cmd.Flags().GetBool("skip-temp-dir-cleanup")
			return cluster.Diags(opts)
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().Int("max-logs", 5, "Only collect up to this number of logs, for each kind of Calico component.")
	cmd.Flags().Int("max-parallelism", 10, "Maximum number of parallel threads to use for collecting logs.")
	cmd.Flags().String("command-timeout", "5m", "Kill an individual collection command if it produces no output for this long (e.g. 30s, 5m).")
	cmd.Flags().String("overall-timeout", "10m", "Abort the whole collection after this long, writing a bundle of whatever was collected so far.")
	cmd.Flags().String("focus-nodes", "", "Comma-separated list of nodes from which to try first to collect logs.")
	cmd.Flags().String("problem-nodes", "", "Comma-separated list of nodes where the problem is occurring; collected in full.")
	cmd.Flags().String("problem-pods", "", "Comma-separated list of pods (namespace/pod) having trouble; their nodes are collected in full.")
	cmd.Flags().String("comparison-nodes", "", "Comma-separated list of healthy nodes to also collect in full, for comparison.")
	cmd.Flags().Bool("skip-temp-dir-cleanup", false, "Don't clean up the temporary directory.")

	// Offer live node-name completion for the node-targeting flags.
	for _, flag := range []string{"focus-nodes", "problem-nodes", "comparison-nodes"} {
		_ = cmd.RegisterFlagCompletionFunc(flag, completeNodeNames)
	}
	return cmd
}

// completeNodeNames provides shell completion of cluster node names for the
// node-targeting flags. It completes the final comma-separated element, so
// "node-a,node-<TAB>" suggests remaining node names. Failures (no cluster
// access) degrade to no suggestions rather than an error.
func completeNodeNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	config, _ := cmd.Flags().GetString("config")
	kubeClient, _, _, err := clientmgr.GetClients(config)
	if err != nil || kubeClient == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nl, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	// Support completing the last element of a comma-separated list.
	prefix := ""
	last := toComplete
	if idx := strings.LastIndex(toComplete, ","); idx >= 0 {
		prefix = toComplete[:idx+1]
		last = toComplete[idx+1:]
	}
	var comps []string
	for _, node := range nl.Items {
		if strings.HasPrefix(node.Name, last) {
			comps = append(comps, prefix+node.Name)
		}
	}
	return comps, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}
