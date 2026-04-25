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

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "calico",
		Short:        "Calico networking and security",
		Long:         "Calico is an open source networking and network security solution for containers, virtual machines, and native host-based workloads.",
		SilenceUsage: true,
	}

	// User-facing commands. These work on every platform we ship a binary
	// for — Linux nodes, plus the macOS and Windows calicoctl downloads.
	cmd.AddCommand(
		newCtlCommand(),
		newHealthCommand(),
		newVersionCommand(),
	)

	// In-cluster component subcommands and the CNI shim are Linux-only —
	// felix, the dataplane, and the CNI plugin all have Linux-only
	// dependencies that don't cross-compile.
	addPlatformCommands(cmd)

	return cmd
}

// dispatchMode selects which handler main runs.
type dispatchMode int

const (
	// modeCobra runs the Cobra command tree (including the calicoctl subcommand).
	modeCobra dispatchMode = iota
	// modeCNI runs the CNI plugin entry point.
	modeCNI
	// modeCNIIPAM runs the IPAM plugin entry point.
	modeCNIIPAM
)

// dispatch decides which handler to run based on argv and the CNI_COMMAND
// env var, and returns the (possibly rewritten) argv to use. It is pure so
// that the dispatch rules can be covered by unit tests without invoking the
// actual handlers.
//
// Rules:
//   - argv[0] basename of "calico-ipam" → CNI IPAM plugin.
//   - argv[0] basename starting with "calicoctl" → Cobra, with "ctl" inserted
//     between argv[0] and the rest of the args. The prefix match covers the
//     plain "calicoctl" name as well as the per-platform release artifacts
//     (e.g. "calicoctl-linux-amd64", "calicoctl-windows-amd64.exe") so users
//     don't have to rename the downloaded binary. argv[0] itself is preserved
//     so panic traces, log prefixes, and kubectl-plugin detection still see
//     the original invocation name.
//   - Otherwise, CNI_COMMAND in the env dispatches to the CNI plugin, but
//     only when no subcommand args were passed. This guards against a stray
//     CNI_COMMAND in a shell environment silently hijacking "calicoctl get
//     nodes" or "calico component foo".
//   - Otherwise, Cobra.
func dispatch(args []string, cniCommand string) (dispatchMode, []string) {
	_, filename := filepath.Split(args[0])
	switch {
	case filename == "calico-ipam":
		return modeCNIIPAM, args
	case strings.HasPrefix(filename, "calicoctl"):
		rewritten := append([]string{args[0], "ctl"}, args[1:]...)
		return modeCobra, rewritten
	default:
		if len(args) == 1 && cniCommand != "" {
			return modeCNI, args
		}
		return modeCobra, args
	}
}

func main() {
	mode, newArgs := dispatch(os.Args, os.Getenv("CNI_COMMAND"))
	os.Args = newArgs

	switch mode {
	case modeCNIIPAM, modeCNI:
		runCNIMode(mode)
		return
	}

	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
