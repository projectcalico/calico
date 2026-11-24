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

// Package capability confirms, before any spec runs, that a lane's cluster has
// the capabilities its config fragments declare. An over-declared lane would
// otherwise fail every affected spec for one unrelated reason.
package capability

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/projectcalico/calico/e2e/pkg/platform"
	"github.com/projectcalico/calico/e2e/pkg/testconfig"
)

// Declarations maps each capability a lane declares to the config files that
// declared it, so a failure can name the fragment to fix.
type Declarations map[platform.Capability][]string

// DeclarationsFrom loads each config on its own and records which of them
// provides each capability. Loading them merged would lose that.
func DeclarationsFrom(paths []string) (Declarations, error) {
	decls := Declarations{}
	for _, p := range paths {
		cfg, err := testconfig.Load(p)
		if err != nil {
			return nil, err
		}
		for _, c := range cfg.Provides {
			decls[platform.Capability(c)] = append(decls[platform.Capability(c)], p)
		}
	}
	return decls, nil
}

// Result is what the check found across every capability.
type Result struct {
	// Missing is every declared capability the cluster doesn't have, or that
	// no probe could confirm. Any entry fails the lane.
	Missing []Miss

	// Undeclared is every capability the cluster has that no fragment
	// declared. It's a lead for a human, never a failure.
	Undeclared []platform.Capability

	// Unchecked is every capability whose probe couldn't decide, such as an
	// Installation read on a manifest install.
	Unchecked []Skip

	// SetupErr is why the check couldn't run at all, such as an unreadable
	// config or kubeconfig. It fails the lane.
	SetupErr error
}

// CouldNotRun is the result of a check that failed before probing anything.
func CouldNotRun(err error) *Result {
	return &Result{SetupErr: err}
}

// Miss is a declared capability the check couldn't confirm.
type Miss struct {
	Capability platform.Capability
	DeclaredBy []string
	Saw        string
}

// Skip is a capability the check couldn't decide either way.
type Skip struct {
	Capability platform.Capability
	Why        string
}

// Failed reports whether the lane must stop before running specs.
func (r *Result) Failed() bool {
	return r.SetupErr != nil || len(r.Missing) > 0
}

// Check runs every probe once, declared or not, and compares what it sees with
// what the lane declared. It fails only on a declared capability that is
// absent, since proving absence can't tell "not installed" from "broken".
func Check(ctx context.Context, cluster *Cluster, decls Declarations) *Result {
	result := &Result{}

	// A declaration no spec can require is a typo, so fail it.
	for c, files := range decls {
		if !slices.Contains(platform.All, c) {
			result.Missing = append(result.Missing, Miss{
				Capability: c,
				DeclaredBy: files,
				Saw:        "not a capability any spec can require; see e2e/pkg/describe/capabilities.go",
			})
		}
	}

	// Probe every capability, declared or not, and sort each outcome.
	for _, c := range platform.All {
		files, declared := decls[c]
		found, err := probes[c](ctx, cluster)

		switch {
		case err != nil && declared:
			result.Missing = append(result.Missing, Miss{Capability: c, DeclaredBy: files, Saw: "probe failed: " + err.Error()})
		case err != nil:
			result.Unchecked = append(result.Unchecked, Skip{Capability: c, Why: "probe failed: " + err.Error()})
		case found.unchecked:
			result.Unchecked = append(result.Unchecked, Skip{Capability: c, Why: found.detail})
		case declared && !found.present:
			result.Missing = append(result.Missing, Miss{Capability: c, DeclaredBy: files, Saw: found.detail})
		case !declared && found.present:
			result.Undeclared = append(result.Undeclared, c)
		}
	}

	slices.SortFunc(result.Missing, func(a, b Miss) int {
		return strings.Compare(string(a.Capability), string(b.Capability))
	})
	return result
}

// Summary describes the result for a human reading the lane's log.
func (r *Result) Summary() string {
	var b strings.Builder
	if r.SetupErr != nil {
		fmt.Fprintf(&b, "check could not run: %v\n", r.SetupErr)
	}
	for _, m := range r.Missing {
		fmt.Fprintf(&b, "missing %s, declared by %s: %s\n", m.Capability, strings.Join(m.DeclaredBy, ", "), m.Saw)
	}
	for _, s := range r.Unchecked {
		fmt.Fprintf(&b, "unchecked %s: %s\n", s.Capability, s.Why)
	}
	for _, c := range r.Undeclared {
		fmt.Fprintf(&b, "undeclared %s: the cluster has it but no fragment provides it\n", c)
	}
	return b.String()
}
