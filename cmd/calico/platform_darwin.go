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

	"github.com/spf13/cobra"
)

// On macOS the binary ships only the user-facing CLI commands (ctl, health,
// version) — the in-cluster components and the CNI plugin have Linux/Windows
// dependencies that don't cross-compile.

func addCNICommand(_ *cobra.Command) {}

func addComponentCommand(_ *cobra.Command) {}

func runCNIMode(_ dispatchMode) {
	fmt.Fprintln(os.Stderr, "CNI plugin invocation is not supported on this platform")
	os.Exit(1)
}
