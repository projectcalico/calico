// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/nat"
)

func init() {
	ctCommand.AddCommand(ctCleanupCmd)
	rootCmd.AddCommand(ctCommand)
}

var ctCleanupCmd = &cobra.Command{
	Use:   "clean",
	Short: "removes connect-time BPF programs",
	Run: func(cmd *cobra.Command, args []string) {
		if err := nat.RemoveConnectTimeLoadBalancer(""); err != nil {
			log.WithError(err).Error("Failed to clean up connect-time load balancer.")
		}
	},
}

// ctCommand represents the connect-time command
var ctCommand = &cobra.Command{
	Use:   "connect-time",
	Short: "Manipulates connect-time load balancing programs",
}
