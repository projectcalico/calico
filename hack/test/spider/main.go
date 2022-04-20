package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var sha1, sha2, filterDir string

func init() {
	flag.StringVar(&sha1, "sha1", "HEAD", "First commit in diff calculation")
	flag.StringVar(&sha2, "sha2", "HEAD~1", "Second commit in diff calculation")
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

func filter(pkg string) bool {
	if filterDir == "" || strings.HasPrefix(pkg, filterDir) {
		// No filter, or a filter is specified and matches.
		return false
	}
	return true
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

func main() {
	// Get the list of packages.
	packages := loadPackages()

	// Make a map of package, to all of the packages that import it either
	// directly or indirectly.
	depTree := map[string]map[string]string{}
	for _, p := range packages {
		for _, d := range p.Deps {
			if depTree[d] == nil {
				depTree[d] = map[string]string{}
			}
			depTree[d][p.Dir] = ""
		}
	}

	// Find all of the files that changed in the diff.
	// git diff --name-only SHA1 SHA2
	var out, stderr bytes.Buffer
	cmd := exec.Command("git", "diff", "--name-only", sha1, sha2)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("%s: %s", err, stderr.String()))
	}

	changedPackages := map[string]string{}
	for _, f := range strings.Split(out.String(), "\n") {
		changedPackages[filepath.Dir(f)] = ""
	}

	// Based off of the changed packages, determine the full set of downstream packages
	// that need to be built and tested.
	allDownstream := map[string]string{}
	for changed := range changedPackages {
		for d := range depTree[changed] {
			allDownstream[d] = ""
		}
	}

	// Print out all of the packages that need rebuilding, sorted and filtered.
	sorted := []string{}
	for d := range allDownstream {
		if !filter(d) {
			sorted = append(sorted, d)
		}
	}
	sort.Strings(sorted)

	for _, s := range sorted {
		fmt.Println(s)
	}
}

// A list of Packages, as output by `go list -json all`
type Packages []Package

type Package struct {
	// The package's name / directory.
	Dir string `json:"Dir"`

	// List of other packages that this package imports - either directly or
	// indirectly.
	Deps []string `json:"Deps"`
}
