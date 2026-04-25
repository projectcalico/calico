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

//go:build !linux

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// addPlatformCommands is a no-op on non-Linux platforms. The combined calico
// binary on macOS and Windows ships only the user-facing CLI commands (ctl,
// health, version) — the in-cluster components and CNI plugin have
// Linux-only dependencies and don't cross-compile.
func addPlatformCommands(_ *cobra.Command) {}

// runCNIMode should not be reachable on non-Linux platforms — dispatch returns
// modeCNI / modeCNIIPAM only when invoked under a Linux container runtime
// (CNI_COMMAND env var or the calico-ipam basename). Treat reaching here as
// an unsupported invocation rather than crashing silently.
func runCNIMode(_ dispatchMode) {
	fmt.Fprintln(os.Stderr, "CNI plugin invocation is not supported on this platform")
	os.Exit(1)
}
