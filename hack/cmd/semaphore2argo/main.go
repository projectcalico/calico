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
	"sort"
)

func main() {
	in := flag.String("in", "", "path to a Semaphore end-to-end pipeline YAML (required)")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "error: --in is required")
		flag.Usage()
		os.Exit(2)
	}

	p, err := LoadPipeline(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// The CronWorkflow emitter is implemented in a follow-up commit. For now,
	// report the resolved job list so the parse/expand core can be exercised
	// (and eyeballed against the pipeline) on its own.
	jobs := Expand(p)
	fmt.Printf("pipeline %q: %d resolved job(s)\n", p.Name, len(jobs))
	for _, j := range jobs {
		keys := make([]string, 0, len(j.Env))
		for k := range j.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("  - [%s] %s\n", j.Block, j.Job)
		for _, k := range keys {
			fmt.Printf("      %s=%s\n", k, j.Env[k])
		}
	}
}
