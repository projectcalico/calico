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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	in := flag.String("in", "", "path to a Semaphore end-to-end pipeline YAML (required)")
	branch := flag.String("branch", "master", "target branch the cron checks out (master|release-vX.Y); RELEASE_STREAM derives from it")
	schedule := flag.String("schedule", "", "cron schedule expression, e.g. \"0 3 * * 2\" (required)")
	name := flag.String("name", "", "cron metadata.name (default: e2e-<pipeline>-<stream>)")
	out := flag.String("out", "", "output path for the generated CronWorkflow (default: stdout)")
	flag.Parse()

	if *in == "" || *schedule == "" {
		fmt.Fprintln(os.Stderr, "error: --in and --schedule are required")
		flag.Usage()
		os.Exit(2)
	}

	p, err := LoadPipeline(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cronName := *name
	if cronName == "" {
		base := strings.TrimSuffix(filepath.Base(*in), filepath.Ext(*in))
		cronName = fmt.Sprintf("e2e-%s-%s", base, streamFromBranch(*branch))
	}

	yaml, todos := Emit(p, EmitOptions{Name: cronName, Branch: *branch, Schedule: *schedule})

	if *out == "" {
		fmt.Print(yaml)
	} else if err := os.WriteFile(*out, []byte(yaml), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %q: %v\n", *out, err)
		os.Exit(1)
	}

	// Surface CONVERTER-TODOs (also embedded as comments in the output) and
	// exit non-zero so the skill / CI knows a human must review this pipeline.
	if len(todos) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d CONVERTER-TODO(s) — review required:\n", len(todos))
		for _, t := range todos {
			fmt.Fprintf(os.Stderr, "  - %s\n", t)
		}
		os.Exit(3)
	}
}

var releaseBranchRe = regexp.MustCompile(`^release-(v[0-9]+\.[0-9]+)$`)

// streamFromBranch derives RELEASE_STREAM from a branch name, matching
// global_prologue.sh: release-vX.Y → vX.Y, otherwise master.
func streamFromBranch(branch string) string {
	if m := releaseBranchRe.FindStringSubmatch(branch); m != nil {
		return m[1]
	}
	return "master"
}
