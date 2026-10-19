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

// Package deletevm deletes the CI GCE VM by name, finding its zone if ZONE is not
// given. Best-effort: the VM's max-run-duration is the backstop, so a failure here
// is logged, not fatal. Runs in the workflow's onExit cleanup step.
package deletevm

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/projectcalico/calico/toolchain/internal/scratchutils/gce"
	"github.com/projectcalico/calico/toolchain/internal/scratchutils/util"
)

// Run executes the deletevm subcommand and returns its exit code. Every failure to
// delete returns 0 -- the VM's max-run-duration is the backstop, so a cleanup step
// should not fail the workflow. A missing VM_NAME is not that: it means the step is
// misconfigured and deleted nothing, which is worth failing on.
func Run() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	name := os.Getenv("VM_NAME")
	if name == "" {
		fmt.Fprintln(os.Stderr, "deletevm: VM_NAME must be set")
		return 1
	}
	project := util.EnvOr("GCP_VM_PROJECT", "unique-caldron-775")
	// The cleanup step injects the SA as an env var, not a mounted file.
	if err := util.SetupComputeADC(); err != nil {
		fmt.Fprintf(os.Stderr, "deletevm: %v (leaving to max-run-duration)\n", err)
		return 0
	}

	client, err := gce.New(ctx, project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deletevm: %v (leaving to max-run-duration)\n", err)
		return 0
	}

	zone := os.Getenv("ZONE")
	if zone == "" {
		if zone, err = client.FindZone(ctx, name); err != nil {
			fmt.Fprintf(os.Stderr, "deletevm: find zone for %s: %v (leaving to max-run-duration)\n", name, err)
			return 0
		}
	}
	if zone == "" {
		fmt.Printf("[deletevm] no VM %s found; nothing to delete\n", name)
		return 0
	}

	fmt.Printf("[deletevm] deleting %s in %s\n", name, zone)
	if err := client.Delete(ctx, zone, name); err != nil {
		fmt.Fprintf(os.Stderr, "deletevm: %v (leaving to max-run-duration)\n", err)
		return 0
	}
	fmt.Printf("[deletevm] deleted %s\n", name)
	return 0
}
