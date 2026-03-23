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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/app-policy/pkg/dikastes"
)

func newDikastesCommand() *cobra.Command {
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
			dikastes.RunServer(listen, dial)
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
			method, _ := cmd.Flags().GetString("method")
			dikastes.RunClient(dial, args[0], args[1], method)
		},
	}
	clientCmd.Flags().String("method", "", "HTTP method for the check request")

	cmd.PersistentFlags().StringVarP(&listen, "listen", "l", dikastes.DefaultListenPath, "Unix domain socket path")
	cmd.PersistentFlags().StringVarP(&dial, "dial", "d", dikastes.DefaultDialTarget, "Target to dial")
	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "Log at Debug level")

	cmd.AddCommand(serverCmd)
	cmd.AddCommand(clientCmd)

	return cmd
}
