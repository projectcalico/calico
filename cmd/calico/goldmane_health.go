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
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/goldmane/pkg/daemon"
)

func newGoldmaneHealthCommand() *cobra.Command {
	var checkReady bool
	var checkLive bool

	cmd := &cobra.Command{
		Use:   "goldmane-check",
		Short: "Check goldmane health status",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := daemon.ConfigFromEnv()
			if !cfg.HealthEnabled {
				os.Exit(0)
			}

			if !checkReady && !checkLive {
				fmt.Println("One of --ready or --live must be set")
				os.Exit(1)
			}

			var path string
			if checkReady {
				path = "readiness"
			} else {
				path = "liveness"
			}

			resp, err := http.Get(fmt.Sprintf("http://localhost:%d/%s", cfg.HealthPort, path))
			if err != nil {
				fmt.Printf("Error making health check request: %v\n", err)
				os.Exit(1)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				fmt.Printf("Health check failed with status code: %d\n", resp.StatusCode)
				os.Exit(1)
			}
			os.Exit(0)
		},
	}

	cmd.Flags().BoolVarP(&checkReady, "ready", "r", false, "Check readiness")
	cmd.Flags().BoolVarP(&checkLive, "live", "l", false, "Check liveness")

	return cmd
}
