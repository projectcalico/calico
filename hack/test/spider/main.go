// Copyright (c) 2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// This code is a build-time tool to help optimize our test running by only running tests
// which are relevant for the given change set.
//
// It works by building a dependency tree of packages so that we can determine the full set
// of impacted packages, given a set of modified files. We then turn that into a set of
// packages which need to have their unit tests executed as a result of a given diff.

var shaA, shaB, commitRange, filterDir string

func init() {
	flag.StringVar(&shaA, "shaA", "", "First commit in diff calculation")
	flag.StringVar(&shaB, "shaB", "", "Second commit in diff calculation")
	flag.StringVar(&commitRange, "commit-range", "", "Range of commits, e.g. shaA...shaB")
	flag.StringVar(&filterDir, "filter-dir", "", "Directory to filter on")

	flag.Parse()
}

// canonical takes a full package path and returns the canonical name for it, relative to the repo root.
func canonical(pkg string) string {
	return strings.SplitAfter(pkg, "projectcalico/calico/")[1]
}

// isLocalDir takes a package path and returns whether or not it is a part of the monorepo.
func isLocalDir(pkg string) bool {
	return strings.Contains(pkg, "github.com/projectcalico/calico")
}

func filter(pkg string) string {
	// Ensure the filterDir ends with a slash.
	if !strings.HasSuffix(filterDir, "/") {
		filterDir = filterDir + "/"
	}
	if filterDir == "" || strings.HasPrefix(pkg, filterDir) {
		// No filter, or a filter is specified and matches.
		return strings.TrimPrefix(pkg, filterDir)
	}
	return ""
}

func loadPackages() []Package {
	var out, stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-json", "all")
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("%s: %s", err, stderr.String()))
	}
	splits := strings.SplitAfter(out.String(), "}\n")

	// Load each package.
	packages := []Package{}
	for _, s := range splits {
		if len(s) == 0 {
			// Sometimes we get empty strings here since the output from go list
			// isn't actually proper json.
			continue
		}

		pkg := Package{}
		err := json.Unmarshal([]byte(s), &pkg)
		if err != nil {
			panic(err)
		}

		// Filter out packages that aren't part of this repo.
		if isLocalDir(pkg.Dir) {
			// Canonicalize the package names, since by default the packages are
			// absolute paths based on the host filesystem.
			pkg.Dir = canonical(pkg.Dir)
			deps := []string{}
			for i := range pkg.Deps {
				if isLocalDir(pkg.Deps[i]) {
					deps = append(deps, canonical(pkg.Deps[i]))
				}
			}

			// Include test code as well.
			for _, d := range append(pkg.TestImports, pkg.XTestImports...) {
				if isLocalDir(d) {
					deps = append(deps, canonical(d))
				}
			}
			pkg.Deps = deps

			packages = append(packages, pkg)
		}
	}
	return packages
}

func getCommits() (string, string) {
	if shaA == "" && shaB == "" && commitRange == "" {
		panic("No commit information provided!")
	}

	if shaA != "" && shaB != "" {
		return shaA, shaB
	}

	splits := strings.Split(commitRange, "...")
	return splits[0], splits[1]
}

func main() {
	// Get the list of packages.
	packages := loadPackages()

	// Make a map of package, to all of the packages that import it either
	// directly or indirectly.
	packageToDeps := map[string]map[string]string{}
	for _, p := range packages {
		for _, d := range p.Deps {
			if packageToDeps[d] == nil {
				packageToDeps[d] = map[string]string{}
			}
			packageToDeps[d][p.Dir] = ""
		}
	}

	// Determine commits to compare.
	c1, c2 := getCommits()

	// Find all of the files that changed in the diff.
	// git diff --name-only SHA_A SHA_B
	var out, stderr bytes.Buffer
	cmd := exec.Command("git", "diff", "--name-only", c1, c2)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("%s: %s", err, stderr.String()))
	}

	// First, check if go.mod has changed. If it has, we can skip building a graph of changed / impacted
	// packages and instead just run all of the tests.
	if strings.Contains(out.String(), "go.mod") {
		// TODO: Be smarter - we can tell what imports changed, and run tests only in the affected packages.
		var out, stderr bytes.Buffer
		cmd = exec.Command("sh", "-c", "find . -name '*_test.go' | xargs dirname | sort -u")
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			panic(fmt.Sprintf("%s: %s", err, stderr.String()))
		}
		for _, p := range strings.Split(out.String(), "\n") {
			fmt.Println(p)
		}
		return
	}

	// From the list of files, condense that to a set of packages.
	changedPackages := map[string]string{}
	for _, f := range strings.Split(out.String(), "\n") {
		changedPackages[filepath.Dir(f)] = ""
	}

	// Based off of the changed packages, determine the full set of packages
	// that need to be built and tested.
	impactedPackages := map[string]string{}
	for pkg := range changedPackages {
		// Include the package that changed.
		impactedPackages[pkg] = ""

		// As well as any packages that import that package.
		for d := range packageToDeps[pkg] {
			impactedPackages[d] = ""
		}
	}

	// Loop through impacted packages a few times to make sure capture the full
	// depth of the dependency tree.
	for i := 0; i < 10; i++ {
		originalSize := len(impactedPackages)
		for pkg := range impactedPackages {
			for d := range packageToDeps[pkg] {
				impactedPackages[d] = ""
			}
		}
		finalSize := len(impactedPackages)
		if finalSize == originalSize {
			// No change, we reached out full set of impacted packages.
			break
		}
	}

	// Print out all of the packages that need rebuilding, sorted and filtered.
	sorted := []string{}
	for d := range impactedPackages {
		if p := filter(d); p != "" {
			if _, err := os.Stat(p); err != nil {
				// Filter out any packages which don't actually exist. If a changeset
				// removes a package, it will show up here, but there won't be any tests to run.
				continue
			}
			sorted = append(sorted, p)
		}
	}
	sort.Strings(sorted)

	for _, s := range sorted {
		fmt.Println(s)
	}
}

type Package struct {
	// The package's name / directory.
	Dir string `json:"Dir"`

	// List of other packages that this package imports - either directly or
	// indirectly.
	Deps []string `json:"Deps"`

	// List of imports from _test.go files within the package.
	TestImports []string `json:"TestImports"`

	// List of imports from _test.go files outside the package.
	XTestImports []string `json:"XTestImports"`
}
