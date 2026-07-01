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

// Command argo-jobreport enumerates the concrete e2e jobs of a generated Argo
// CronWorkflow and/or a Semaphore pipeline, and diffs them — the job-parity
// harness that proves a conversion is faithful (same jobs, same resolved
// params). See .argoci/DESIGN.md.
//
// Usage:
//
//	argo-jobreport --cron .argoci/cron/e2e-nftables-master.yaml       # CSV of Argo jobs
//	argo-jobreport --semaphore .semaphore/end-to-end/pipelines/nftables.yml
//	argo-jobreport --diff --semaphore <pipeline> --cron <cron>        # parity check
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectcalico/calico/hack/argoci/convert"
	"github.com/projectcalico/calico/hack/argoci/parity"
)

func main() {
	cron := flag.String("cron", "", "generated CronWorkflow YAML to enumerate")
	sem := flag.String("semaphore", "", "Semaphore pipeline YAML to enumerate (reference side)")
	diff := flag.Bool("diff", false, "compare --semaphore and --cron; exit non-zero on mismatch")
	flag.Parse()

	switch {
	case *diff:
		if *sem == "" || *cron == "" {
			fatal("--diff requires both --semaphore and --cron")
		}
		os.Exit(runDiff(semaphoreJobs(*sem), cronJobs(*cron)))
	case *cron != "":
		fmt.Print(parity.CSV(cronJobs(*cron)))
	case *sem != "":
		fmt.Print(parity.CSV(semaphoreJobs(*sem)))
	default:
		fatal("provide --cron and/or --semaphore (with --diff to compare)")
	}
}

// runDiff prints the parity result and returns the process exit code.
func runDiff(sem, argo []map[string]string) int {
	onlyS, onlyA := parity.Diff(sem, argo)
	if len(onlyS) == 0 && len(onlyA) == 0 {
		fmt.Printf("PARITY OK: %d jobs match\n", len(sem))
		return 0
	}
	fmt.Printf("PARITY MISMATCH: sem=%d argo=%d; %d only-in-semaphore, %d only-in-argo\n",
		len(sem), len(argo), len(onlyS), len(onlyA))
	for _, s := range onlyS {
		fmt.Printf("\n--- only in Semaphore ---\n%s", s)
	}
	for _, s := range onlyA {
		fmt.Printf("\n--- only in Argo ---\n%s", s)
	}
	return 1
}

// semaphoreJobs enumerates the reference side via the trusted converter
// expansion (also independently cross-checked by generate_e2e_report.py).
func semaphoreJobs(path string) []map[string]string {
	p, err := convert.LoadPipeline(path)
	if err != nil {
		fatal(err.Error())
	}
	rjs := convert.Expand(p)
	jobs := make([]map[string]string, len(rjs))
	for i, rj := range rjs {
		jobs[i] = rj.Env
	}
	return jobs
}

// cronJobs enumerates the Argo side by parsing the emitted YAML independently.
func cronJobs(path string) []map[string]string {
	jobs, err := EnumerateCron(path)
	if err != nil {
		fatal(err.Error())
	}
	return jobs
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error: "+msg)
	os.Exit(2)
}
