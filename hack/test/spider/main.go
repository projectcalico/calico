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

var sha1, sha2, commitRange, filterDir string

func init() {
	flag.StringVar(&sha1, "sha1", "", "First commit in diff calculation")
	flag.StringVar(&sha2, "sha2", "", "Second commit in diff calculation")
	flag.StringVar(&commitRange, "commit-range", "", "Range of commits, e.g. SHA1...SHA2")
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
		pkg := Package{}
		json.Unmarshal([]byte(s), &pkg)

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
			pkg.Deps = deps

			// Filter out packages that aren't part of this repo.
			packages = append(packages, pkg)
		}
	}
	return packages
}

func getCommits() (string, string) {
	if sha1 == "" && sha2 == "" && commitRange == "" {
		panic("No commit information provided!")
	}

	if sha1 != "" && sha2 != "" {
		return sha1, sha2
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
	// git diff --name-only SHA1 SHA2
	var out, stderr bytes.Buffer
	cmd := exec.Command("git", "diff", "--name-only", c1, c2)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("%s: %s", err, stderr.String()))
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
}
