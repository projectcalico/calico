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

	"github.com/projectcalico/calico/kube-controllers/pkg/status"
)

func newCheckStatusCommand() *cobra.Command {
	var file string
	var checkReady bool
	var checkLive bool

	cmd := &cobra.Command{
		Use:   "check-status",
		Short: "Check kube-controllers health status",
		Run: func(cmd *cobra.Command, args []string) {
			if !checkReady && !checkLive {
				fmt.Println("No command specified to check-status")
				os.Exit(1)
			}

			st, err := status.ReadStatusFile(file)
			if err != nil {
				fmt.Printf("Failed to read status file %s: %v\n", file, err)
				os.Exit(1)
			}

			if st.GetReadiness() {
				fmt.Println("Ready")
				os.Exit(0)
			}

			fmt.Println(st.GetNotReadyConditions())
			os.Exit(1)
		},
	}

	cmd.Flags().StringVarP(&file, "file", "f", status.DefaultStatusFile, "File to read with status information")
	cmd.Flags().BoolVarP(&checkReady, "ready", "r", false, "Check readiness")
	cmd.Flags().BoolVarP(&checkLive, "live", "l", false, "Check liveness")

	return cmd
}
