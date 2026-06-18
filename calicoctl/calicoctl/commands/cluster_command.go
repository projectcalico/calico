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
	"fmt"
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
			if maxLogs, _ := cmd.Flags().GetInt("max-logs"); maxLogs != 5 {
				synthArgs = append(synthArgs, fmt.Sprintf("--max-logs=%d", maxLogs))
			}
			if maxP, _ := cmd.Flags().GetInt("max-parallelism"); maxP != 10 {
				synthArgs = append(synthArgs, fmt.Sprintf("--max-parallelism=%d", maxP))
			}
			if nodes, _ := cmd.Flags().GetString("focus-nodes"); nodes != "" {
				synthArgs = append(synthArgs, "--focus-nodes="+nodes)
			}
			if nodes, _ := cmd.Flags().GetString("problem-nodes"); nodes != "" {
				synthArgs = append(synthArgs, "--problem-nodes="+nodes)
			}
			if pods, _ := cmd.Flags().GetString("problem-pods"); pods != "" {
				synthArgs = append(synthArgs, "--problem-pods="+pods)
			}
			if nodes, _ := cmd.Flags().GetString("comparison-nodes"); nodes != "" {
				synthArgs = append(synthArgs, "--comparison-nodes="+nodes)
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
	cmd.Flags().Int("max-logs", 5, "Only collect up to this number of logs, for each kind of Calico component.")
	cmd.Flags().Int("max-parallelism", 10, "Maximum number of parallel threads to use for collecting logs.")
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
