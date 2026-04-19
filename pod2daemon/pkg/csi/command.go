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

package csi

import "github.com/spf13/cobra"

// NewCommand returns a cobra command that runs the Calico CSI node driver.
func NewCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "csi",
		Short: "Run the Calico CSI node driver",
		Run: func(cmd *cobra.Command, args []string) {
			Run(cfg)
		},
	}

	cmd.Flags().StringVar(&cfg.LogLevel, "loglevel", "", "Log level for the driver")
	cmd.Flags().StringVar(&cfg.Endpoint, "endpoint", "", "Unix domain socket path for Kubelet communication")
	cmd.Flags().StringVar(&cfg.NodeID, "nodeid", "", "Node ID unique to the node")

	return cmd
}
