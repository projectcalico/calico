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

	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "calico",
		Short:        "Calico networking and security",
		Long:         "Calico is an open source networking and network security solution for containers, virtual machines, and native host-based workloads.",
		SilenceUsage: true,
	}

	// Component subcommands (internal use by the operator).
	cmd.AddCommand(newComponentCommand())

	// User-facing commands.
	cmd.AddCommand(
		newCtlCommand(),
		newHealthCommand(),
		newVersionCommand(),
	)

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
//   - argv[0] basename of "calicoctl" → Cobra, with "ctl" inserted between
//     argv[0] and the rest of the args. argv[0] itself is preserved so that
//     panic traces, log prefixes, and kubectl-plugin detection still see the
//     original invocation name.
//   - argv[0] basename of "uds" → Cobra, with "component flexvol" inserted
//     so kubelet's "<plugin-dir>/uds <init|mount|unmount>" calls route
//     into the flexvol subcommand.
//   - Otherwise, CNI_COMMAND in the env dispatches to the CNI plugin. If
//     args[1] is a known top-level cobra subcommand, prefer cobra — that
//     guards against a stray CNI_COMMAND silently hijacking "calico
//     component foo".
//   - Otherwise, Cobra.
func dispatch(args []string, cniCommand string) (dispatchMode, []string) {
	_, filename := filepath.Split(args[0])
	switch filename {
	case "calico-ipam":
		return modeCNIIPAM, args
	case "calicoctl":
		rewritten := append([]string{args[0], "ctl"}, args[1:]...)
		return modeCobra, rewritten
	case "uds":
		rewritten := append([]string{args[0], "component", "flexvol"}, args[1:]...)
		return modeCobra, rewritten
	default:
		if cniCommand != "" {
			if len(args) > 1 && isCobraSubcommand(args[1]) {
				return modeCobra, args
			}
			return modeCNI, args
		}
		return modeCobra, args
	}
}

// isCobraSubcommand reports whether s is a known top-level subcommand of the
// calico cobra tree. Used by dispatch to disambiguate when CNI_COMMAND is set.
func isCobraSubcommand(s string) bool {
	switch s {
	case "component", "ctl", "health", "version", "help":
		return true
	}
	return false
}

func main() {
	mode, newArgs := dispatch(os.Args, os.Getenv("CNI_COMMAND"))
	os.Args = newArgs

	switch mode {
	case modeCNIIPAM:
		ipamplugin.Main(buildinfo.Version)
		return
	case modeCNI:
		plugin.Main(buildinfo.Version)
		return
	}

	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
