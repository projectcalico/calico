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

	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// addPlatformCommands wires up the Linux-only subcommands — the in-cluster
// components (felix, typha, kube-controllers, ...) and the CNI shim. Only
// Linux ships these because felix and the CNI plugin pull in Linux-only
// netlink and BPF dependencies.
func addPlatformCommands(cmd *cobra.Command) {
	cmd.AddCommand(newComponentCommand())
}

// runCNIMode invokes the CNI plugin or IPAM plugin entry point. Reached only
// when dispatch picks modeCNI or modeCNIIPAM, which the basename rules and
// CNI_COMMAND env var only do under Linux container runtimes.
func runCNIMode(mode dispatchMode) {
	switch mode {
	case modeCNIIPAM:
		ipamplugin.Main(buildinfo.Version)
	case modeCNI:
		plugin.Main(buildinfo.Version)
	}
}
