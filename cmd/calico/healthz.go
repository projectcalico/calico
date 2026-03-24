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

	"github.com/projectcalico/calico/app-policy/pkg/healthz"
)

func newHealthzCommand() *cobra.Command {
	var dialPath string

	cmd := &cobra.Command{
		Use:   "healthz (liveness|readiness)",
		Short: "Check Dikastes health status",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			check := args[0]
			if check != "liveness" && check != "readiness" {
				fmt.Fprintf(os.Stderr, "Invalid check type %q, expected \"liveness\" or \"readiness\"\n", check)
				os.Exit(1)
			}
			healthz.Run(dialPath, check)
		},
	}

	cmd.Flags().StringVar(&dialPath, "dialPath", healthz.DefaultDialPath, "Path to health check gRPC service")

	return cmd
}
