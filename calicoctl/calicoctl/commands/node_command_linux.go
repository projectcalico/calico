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

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/node"
)

func newNodeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Calico node management",
	}
	cmd.AddCommand(
		newNodeStatusCommand(),
		newNodeDiagsCommand(),
		newNodeChecksystemCommand(),
		newNodeRunCommand(),
	)
	return cmd
}

func newNodeStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "View the current status of a Calico node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return node.Status([]string{"node", "status"})
		},
	}
}

func newNodeDiagsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diags",
		Short: "Gather a diagnostics bundle for a Calico node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return node.Diags([]string{"node", "diags"})
		},
	}
	cmd.Flags().String("log-dir", "/var/log/calico", "The directory containing Calico logs.")
	return cmd
}

func newNodeChecksystemCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checksystem",
		Short: "Verify the compute host is able to run a Calico node instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			return node.Checksystem([]string{"node", "checksystem"})
		},
	}
	cmd.Flags().StringP("kernel-config", "f", "", "Override the Kernel config file location.")
	return cmd
}

func newNodeRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the Calico node container image",
		RunE: func(cmd *cobra.Command, args []string) error {
			return node.Run([]string{"node", "run"})
		},
	}
	cmd.Flags().String("ip", "", "Set the local IPv4 routing address for this node.")
	cmd.Flags().String("ip6", "", "Set the local IPv6 routing address for this node.")
	cmd.Flags().String("as", "", "Set the AS number for this node.")
	cmd.Flags().String("name", "", "The name of the Calico node.")
	cmd.Flags().String("ip-autodetection-method", "first-found", "Specify the autodetection method for detecting the local IPv4 routing address.")
	cmd.Flags().String("ip6-autodetection-method", "first-found", "Specify the autodetection method for detecting the local IPv6 routing address.")
	cmd.Flags().String("log-dir", "/var/log/calico", "The directory containing Calico logs.")
	cmd.Flags().String("node-image", "quay.io/calico/node:latest", "Docker image to use for Calico's per-node container.")
	cmd.Flags().String("backend", "bird", "Specify which networking backend to use (bird|none).")
	cmd.Flags().Bool("dryrun", false, "Output the appropriate command, without starting the container.")
	cmd.Flags().Bool("init-system", false, "Run the appropriate command to use with an init system.")
	cmd.Flags().Bool("no-default-ippools", false, "Do not create default pools upon startup.")
	cmd.Flags().String("felix-config", "", "Path to the file containing Felix configuration.")
	addConfigFlag(cmd)
	return cmd
}
