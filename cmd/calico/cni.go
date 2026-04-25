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

//go:build linux || windows

package main

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/cni-plugin/pkg/install"
	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// newCNICommand is defined here rather than in the CNI package because the CNI
// plugin/IPAM entry points are simple function calls, not full CLI frameworks.
// The container runtime also invokes the binary directly (detected in main.go
// via CNI_COMMAND env var or binary name), bypassing this subcommand entirely.
func newCNICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cni",
		Short: "Run the Calico CNI plugin",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install the Calico CNI plugin on the host",
		Run: func(cmd *cobra.Command, args []string) {
			if err := install.Install(buildinfo.Version); err != nil {
				logrus.WithError(err).Fatal("Error installing CNI plugin")
			}
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:                "plugin",
		Short:              "Run the Calico CNI plugin",
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			plugin.Main(buildinfo.Version)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:                "ipam",
		Short:              "Run the Calico CNI IPAM plugin",
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			ipamplugin.Main(buildinfo.Version)
		},
	})

	return cmd
}
