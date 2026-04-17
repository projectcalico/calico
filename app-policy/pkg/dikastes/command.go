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

package dikastes

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/app-policy/pkg/healthz"
)

// NewCommand returns a cobra command tree for the Dikastes application-layer policy engine.
func NewCommand() *cobra.Command {
	var listen string
	var dial string
	var debug bool

	cmd := &cobra.Command{
		Use:   "dikastes",
		Short: "Run the Dikastes application-layer policy engine",
	}

	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Dikastes authorization server",
		Run: func(cmd *cobra.Command, args []string) {
			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}
			RunServer(listen, dial)
		},
	}

	clientCmd := &cobra.Command{
		Use:   "client <namespace> <account>",
		Short: "Send a test authorization check",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}
			method, err := cmd.Flags().GetString("method")
			if err != nil {
				logrus.WithError(err).Fatal("Failed to get method flag")
			}
			RunClient(dial, args[0], args[1], method)
		},
	}
	clientCmd.Flags().String("method", "", "HTTP method for the check request")

	var dialPath string
	healthCmd := &cobra.Command{
		Use:   "health (liveness|readiness)",
		Short: "Check Dikastes health status via gRPC",
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
	healthCmd.Flags().StringVar(&dialPath, "dial-path", healthz.DefaultDialPath, "Path to health check gRPC service")

	cmd.PersistentFlags().StringVarP(&listen, "listen", "l", DefaultListenPath, "Unix domain socket path")
	cmd.PersistentFlags().StringVarP(&dial, "dial", "d", DefaultDialTarget, "Target to dial")
	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "Log at Debug level")

	cmd.AddCommand(serverCmd)
	cmd.AddCommand(clientCmd)
	cmd.AddCommand(healthCmd)

	return cmd
}
