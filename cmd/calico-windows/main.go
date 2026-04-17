// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/cni-plugin/pkg/install"
	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	"github.com/projectcalico/calico/node/pkg/node"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// main is the Windows combined calico binary. On Linux, cmd/calico is used instead.
// This binary imports only Windows-safe packages, avoiding the Linux-only
// dependencies in the full calico binary (typha, pod2daemon, dikastes, etc.).
//
// When symlinked or copied as "calico-ipam.exe", dispatches to the IPAM
// plugin. When CNI_COMMAND is set, dispatches to the CNI plugin. Otherwise,
// runs the Cobra command tree.
func main() {
	_, filename := filepath.Split(os.Args[0])
	switch filename {
	case "calico-ipam", "calico-ipam.exe":
		ipamplugin.Main(buildinfo.Version)
		return
	}
	if os.Getenv("CNI_COMMAND") != "" {
		plugin.Main(buildinfo.Version)
		return
	}

	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "calico-windows",
		Short:        "Calico Windows",
		SilenceUsage: true,
	}

	nodeCmd := node.NewCommand()
	nodeCmd.AddCommand(node.NewFelixCommand())
	nodeCmd.AddCommand(node.NewConfdCommand())

	cmd.AddCommand(
		nodeCmd,
		newCNICommand(),
		newVersionCommand(),
	)

	return cmd
}

func newCNICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cni",
		Short: "CNI plugin operations",
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

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			buildinfo.PrintVersion()
		},
	}
}
