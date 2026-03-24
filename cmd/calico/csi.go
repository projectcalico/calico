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

	"github.com/projectcalico/calico/pod2daemon/pkg/csi"
)

func newCSICommand() *cobra.Command {
	var logLevel string
	var endpoint string
	var nodeID string

	cmd := &cobra.Command{
		Use:   "csi",
		Short: "Run the Calico CSI node driver",
		Run: func(cmd *cobra.Command, args []string) {
			csi.Run(logLevel, endpoint, nodeID)
		},
	}

	cmd.Flags().StringVar(&logLevel, "loglevel", "", "Log level for the driver")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Unix domain socket path for Kubelet communication")
	cmd.Flags().StringVar(&nodeID, "nodeid", "", "Node ID unique to the node")

	return cmd
}
