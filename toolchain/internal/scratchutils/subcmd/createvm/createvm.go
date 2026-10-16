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

// Package createvm creates the CI GCE VM from the ci-base image — docker, go,
// kind, kubectl and gh prebaked, so no startup script — and writes its zone to
// ZONE_OUT for the next workflow step. It does not wait or SSH; the run step's
// connect is the readiness check. Config comes from env vars the workflow sets;
// the compute SA is a mounted key file (COMPUTE_SA_KEY) or its env var (see util).
package createvm

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectcalico/calico/toolchain/internal/scratchutils/gce"
	"github.com/projectcalico/calico/toolchain/internal/scratchutils/util"
)

// Run executes the createvm subcommand and returns its exit code.
func Run() int {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "createvm: %v\n", err)
		return 1
	}
	return 0
}

func run(ctx context.Context) error {
	name := os.Getenv("VM_NAME")
	if name == "" {
		return fmt.Errorf("VM_NAME must be set")
	}
	// No default family. Families are per toolchain version
	// (ci-base-1-27-2-21-1-8), so a baked-in name goes stale at the next release,
	// and a stale family either stops resolving or, worse, resolves to an image
	// from a different Go line. The caller has to say which it wants.
	image := os.Getenv("GOOGLE_VM_IMAGE")
	family := os.Getenv("GOOGLE_VM_IMAGE_FAMILY")
	if image == "" && family == "" {
		return fmt.Errorf("set GOOGLE_VM_IMAGE to an exact image, or GOOGLE_VM_IMAGE_FAMILY to a family such as ci-base-1-27-2-21-1-8")
	}
	project := util.EnvOr("GCP_VM_PROJECT", "unique-caldron-775")
	zoneOut := util.EnvOr("ZONE_OUT", "/tmp/vm-zone")
	// Point ADC at the compute SA (mounted key file, or materialized from its env var).
	if err := util.SetupComputeADC(); err != nil {
		return err
	}

	maxRun, err := parseMaxRun(util.EnvOr("GOOGLE_VM_MAX_RUN_DURATION", "90m"))
	if err != nil {
		return err
	}
	diskGB, err := parseDiskGB(util.EnvOr("GOOGLE_VM_DISK_SIZE", "200GB"))
	if err != nil {
		return err
	}

	client, err := gce.New(ctx, project)
	if err != nil {
		return err
	}

	zones := strings.Fields(util.EnvOr("GOOGLE_VM_ZONES", "us-central1-a us-central1-b us-central1-c us-central1-f"))
	if len(zones) == 0 {
		return fmt.Errorf("GOOGLE_VM_ZONES is empty")
	}
	// Bound the whole create so an operation that never reaches DONE fails the step
	// instead of hanging it until the workflow's own timeout. Derived from the zone
	// count so every zone gets its full per-zone budget.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(len(zones))*gce.PerZoneTimeout+time.Minute)
	defer cancel()

	cfg := gce.Config{
		Name:        name,
		Zones:       zones,
		MachineType: util.EnvOr("GOOGLE_VM_MACHINE_TYPE", "n2-standard-16"),
		DiskType:    util.EnvOr("GOOGLE_VM_DISK_TYPE", "pd-ssd"),
		DiskSizeGB:  diskGB,
		// ci-base has the toolchain baked in (built by
		// toolchain/vm-images/ci-base/build-image.sh), so the VM boots ready and
		// the job does no installs. Override for stock Ubuntu. GOOGLE_VM_IMAGE
		// pins one exact image (e.g. ci-base-1-27-2-llvm21-1-8-9cc1214) so the
		// image can be rolled without rebuilding this binary; unset, the family
		// gives whatever is newest.
		Image:        os.Getenv("GOOGLE_VM_IMAGE"),
		ImageFamily:  util.EnvOr("GOOGLE_VM_IMAGE_FAMILY", "ci-base"),
		ImageProject: util.EnvOr("GOOGLE_VM_IMAGE_PROJECT", "unique-caldron-775"),
		MaxRun:       maxRun,
		Labels: map[string]string{
			"ci-runner":   "true",
			"ci-project":  "kindrig",
			"ci-workflow": util.EnvOr("CI_WORKFLOW_LABEL", "unknown"),
		},
	}

	from := "family " + cfg.ImageFamily
	if cfg.Image != "" {
		from = "image " + cfg.Image
	}
	fmt.Printf("[createvm] creating %s (%s) from %s in %s across %v\n", name, cfg.MachineType, from, project, cfg.Zones)
	zone, err := client.Create(ctx, cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(zoneOut, []byte(zone), 0o644); err != nil {
		return fmt.Errorf("write zone to %s: %w", zoneOut, err)
	}
	// Readiness is the run step's job: runonvm must connect to ship and run anyway,
	// so that connect is the check.
	fmt.Printf("[createvm] %s created in %s (zone -> %s)\n", name, zone, zoneOut)
	return nil
}

// parseMaxRun parses the VM's reclaim deadline. Non-positive is rejected rather
// than passed on: instanceSpec omits the whole Scheduling block when MaxRun is not
// positive, so "0s" would create a VM with no deadline at all -- and deletevm
// returning 0 on any failure assumes that deadline is there to catch it.
func parseMaxRun(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("GOOGLE_VM_MAX_RUN_DURATION %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("GOOGLE_VM_MAX_RUN_DURATION %q: must be positive", s)
	}
	return d, nil
}

// parseDiskGB accepts "200GB", "200G", or "200" and returns the GB count.
func parseDiskGB(s string) (int64, error) {
	// Errors quote s, not trimmed: report what the caller actually set.
	trimmed := strings.TrimSpace(strings.ToUpper(s))
	trimmed = strings.TrimSuffix(strings.TrimSuffix(trimmed, "GB"), "G")
	n, err := strconv.ParseInt(strings.TrimSpace(trimmed), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("GOOGLE_VM_DISK_SIZE %q: want e.g. 200GB: %w", s, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("GOOGLE_VM_DISK_SIZE %q: must be positive", s)
	}
	return n, nil
}
