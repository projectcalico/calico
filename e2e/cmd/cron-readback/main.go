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

// cron-readback checks each live ArgoCI cron's E2E_TEST_CONFIG against the
// merged cron files. It exits 1 on a difference and 2 when ArgoCI can't be read.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/projectcalico/calico/e2e/pkg/cronreadback"
)

const (
	exitMismatch = 1
	exitError    = 2
)

func main() {
	repoRoot := flag.String("repo-root", ".", "path to the repository root")
	branch := flag.String("branch", "master", "branch whose crons to check; the live names carry it as a suffix")
	repo := flag.String("repo", "calico", "repo name, without the owner, that ArgoCI labels the repo's cron runs with")
	server := flag.String("server", os.Getenv("ARGO_SERVER"), "Argo server; defaults to ARGO_SERVER, then the public ArgoCI")
	namespace := flag.String("namespace", envOr("ARGO_NAMESPACE", cronreadback.DefaultNamespace), "namespace the crons live in")
	dump := flag.String("dump", "", "print the raw JSON of this one live cron and exit")
	list := flag.Bool("list-expected", false, "print the cells the cron files declare and exit, without reading ArgoCI")
	flag.Parse()

	if *list {
		os.Exit(runList(*repoRoot, *branch))
	}
	if *server == "" {
		*server = cronreadback.DefaultServer
	}
	client := cronreadback.NewClient(*server, *namespace, os.Getenv("ARGO_TOKEN"))

	if *dump != "" {
		os.Exit(runDump(client, *dump))
	}
	os.Exit(run(client, *repoRoot, *branch, *repo))
}

// runDump prints one live cron's raw JSON, so the shape the check parses can be
// checked against the real thing.
func runDump(client *cronreadback.Client, name string) int {
	data, err := client.GetRaw(context.Background(), name)
	if err != nil {
		return fail(err)
	}
	fmt.Println(string(data))
	return 0
}

// runList prints every expected cell, one per line, so what the files declare
// can be inspected without credentials.
func runList(repoRoot, branch string) int {
	expected, err := cronreadback.LoadExpected(repoRoot, branch)
	if err != nil {
		return fail(err)
	}
	for _, cron := range expected {
		fmt.Printf("%s (%s)\n", cron.Name, cron.File)
		for _, cell := range slices.Sorted(maps.Keys(cron.Cells)) {
			fmt.Printf("  %s: %s\n", cell, cron.Cells[cell])
		}
	}
	fmt.Printf("%d crons, %d cells\n", len(expected), cronreadback.CellCount(expected))
	return 0
}

// run compares the live crons with the files and returns the exit code.
func run(client *cronreadback.Client, repoRoot, branch, repo string) int {
	expected, err := cronreadback.LoadExpected(repoRoot, branch)
	if err != nil {
		return fail(err)
	}
	live, err := cronreadback.ReadLive(context.Background(), client, expected, repo, branch)
	if err != nil {
		return fail(err)
	}

	findings := cronreadback.Compare(expected, live)
	for _, f := range findings {
		fmt.Println(f)
	}
	fmt.Printf("%d crons, %d cells checked on %s: %d differences\n", len(expected), cronreadback.CellCount(expected), branch, len(findings))
	if len(findings) > 0 {
		return exitMismatch
	}
	return 0
}

// fail reports err, with how to fix a rejected token, and returns the error
// exit code.
func fail(err error) int {
	fmt.Fprintln(os.Stderr, "cron-readback:", err)
	if errors.Is(err, cronreadback.ErrUnauthorized) {
		fmt.Fprintln(os.Stderr, "Set ARGO_TOKEN to a current ArgoCI token (and ARGO_SERVER if it is not the public ArgoCI).")
	}
	return exitError
}

// envOr returns the environment variable's value, or def when it is empty.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
