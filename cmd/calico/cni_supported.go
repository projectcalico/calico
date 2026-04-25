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
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// addCNICommand registers the `cni` cobra subcommand (install / plugin / ipam).
// Available on Linux and Windows — the cni-plugin packages are cross-platform
// with netlink/HCN dataplane selected via build tags. Not available on macOS
// etc., where the combined binary is calicoctl-only.
func addCNICommand(cmd *cobra.Command) {
	cmd.AddCommand(newCNICommand())
}

// runCNIMode invokes the CNI or IPAM plugin entry point. Reached via argv[0]
// basename ("calico-ipam") or via the CNI_COMMAND env var — dispatch selects
// the mode before reaching here.
func runCNIMode(mode dispatchMode) {
	switch mode {
	case modeCNIIPAM:
		ipamplugin.Main(buildinfo.Version)
	case modeCNI:
		plugin.Main(buildinfo.Version)
	}
}
