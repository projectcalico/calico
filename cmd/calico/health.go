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
	"time"

	"github.com/spf13/cobra"
)

func newHealthCommand() *cobra.Command {
	var host string
	var port int
	var checkType string

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check component health via HTTP",
		Long: `Generic HTTP health check for any component using the standard
HealthAggregator pattern. Sends an HTTP GET to the component's
/readiness or /liveness endpoint and exits with code 0 on success.`,
		Run: func(cmd *cobra.Command, args []string) {
			if checkType != "readiness" && checkType != "liveness" {
				fmt.Fprintf(os.Stderr, "Invalid check type %q, expected \"readiness\" or \"liveness\"\n", checkType)
				os.Exit(1)
			}

			url := fmt.Sprintf("http://%s:%d/%s", host, port, checkType)
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
				os.Exit(1)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				os.Exit(0)
			}
			fmt.Fprintf(os.Stderr, "Health check failed with status code: %d\n", resp.StatusCode)
			os.Exit(1)
		},
	}

	cmd.Flags().StringVar(&host, "host", "localhost", "Host to check")
	cmd.Flags().IntVar(&port, "port", 0, "Port to check")
	cmd.Flags().StringVar(&checkType, "type", "readiness", "Check type: readiness or liveness")
	_ = cmd.MarkFlagRequired("port")

	return cmd
}
