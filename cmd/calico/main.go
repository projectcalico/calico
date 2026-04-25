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
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Platform-specific hooks. Default to no-ops on macOS, where the binary is
// calicoctl-only; linux/windows files override these in init().
var (
	addCNICommand       = func(*cobra.Command) {}
	addComponentCommand = func(*cobra.Command) {}
	runCNIMode          = func(dispatchMode) {
		fmt.Fprintln(os.Stderr, "CNI plugin invocation is not supported on this platform")
		os.Exit(1)
	}
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "calico",
		Short:        "Calico networking and security",
		Long:         "Calico is an open source networking and network security solution for containers, virtual machines, and native host-based workloads.",
		SilenceUsage: true,
	}

	cmd.AddCommand(
		newCtlCommand(),
		newHealthCommand(),
		newVersionCommand(),
	)
	addCNICommand(cmd)
	addComponentCommand(cmd)

	return cmd
}

// dispatchMode selects which handler main runs.
type dispatchMode int

const (
	// modeCobra runs the full Cobra command tree rooted at "calico" (with
	// "ctl", "health", "version", and on Linux the "component" subcommand).
	modeCobra dispatchMode = iota

	// modeCalicoctl runs the ctl command tree as the root so help text
	// reads "calicoctl <subcommand>" rather than "calico ctl <subcommand>".
	modeCalicoctl

	// modeCNI runs the CNI plugin entry point.
	modeCNI

	// modeCNIIPAM runs the IPAM plugin entry point.
	modeCNIIPAM
)

// dispatch decides which handler to run based on argv and the CNI_COMMAND
// env var. It is pure so the dispatch rules can be covered by unit tests
// without invoking the actual handlers.
//
// Rules:
//   - argv[0] basename of "calico-ipam" (or "calico-ipam.exe" on Windows) →
//     CNI IPAM plugin.
//   - argv[0] basename starting with "calicoctl" → run the ctl command tree
//     as root. The prefix match covers the plain "calicoctl" name as well as
//     the per-platform release artifacts (e.g. "calicoctl-linux-amd64",
//     "calicoctl-windows-amd64.exe") so users don't have to rename the
//     downloaded binary.
//   - Otherwise, CNI_COMMAND in the env dispatches to the CNI plugin, but
//     only when no subcommand args were passed. This guards against a stray
//     CNI_COMMAND in a shell environment silently hijacking "calicoctl get
//     nodes" or "calico component foo".
//   - Otherwise, the full Cobra tree.
func dispatch(args []string, cniCommand string) dispatchMode {
	_, filename := filepath.Split(args[0])
	filename = strings.TrimSuffix(filename, ".exe")
	switch {
	case filename == "calico-ipam":
		return modeCNIIPAM
	case strings.HasPrefix(filename, "calicoctl"):
		return modeCalicoctl
	default:
		if len(args) == 1 && cniCommand != "" {
			return modeCNI
		}
		return modeCobra
	}
}

// newCalicoctlCommand returns the ctl command tree ready to run as a root
// command — it renames the Use field so help output reads "calicoctl ..."
// instead of "ctl ...".
func newCalicoctlCommand() *cobra.Command {
	cmd := newCtlCommand()
	cmd.Use = "calicoctl"
	return cmd
}

func main() {
	mode := dispatch(os.Args, os.Getenv("CNI_COMMAND"))

	switch mode {
	case modeCNIIPAM, modeCNI:
		runCNIMode(mode)
		return
	}

	var root *cobra.Command
	if mode == modeCalicoctl {
		root = newCalicoctlCommand()
	} else {
		root = newRootCommand()
	}

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
