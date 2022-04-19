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

var sha1, sha2 string

func init() {
	flag.StringVar(&sha1, "sha1", "HEAD", "First commit in diff calculation")
	flag.StringVar(&sha2, "sha2", "HEAD~1", "Second commit in diff calculation")

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

func main() {
	// Read packages file.
	// TODO: Generate this.
	depsBytes, err := os.ReadFile("deps.json")
	if err != nil {
		panic(err)
	}

	// Split each.
	pkgs := strings.SplitAfter(string(depsBytes), "}\n")

	// Load each package.
	packages := []Package{}
	for _, p := range pkgs {
		pkg := Package{}
		json.Unmarshal([]byte(p), &pkg)

		// Filter out packages that aren't part of this repo.
		if isLocalDir(pkg.Dir) {
			packages = append(packages, pkg)
		}
	}

	// Make a map of package, to all of the packages that import it either
	// directly or indirectly.
	depTree := map[string]map[string]string{}
	for _, p := range packages {
		for _, d := range p.Deps {
			if isLocalDir(d) {
				relativeDep := canonical(d)
				relativeDir := canonical(p.Dir)

				if depTree[relativeDep] == nil {
					depTree[relativeDep] = map[string]string{}
				}
				depTree[relativeDep][relativeDir] = ""
			}
		}
	}

	// Find all of the files that changed in the diff.
	// git diff --name-only SHA1 SHA2
	var out, stderr bytes.Buffer
	cmd := exec.Command("git", "diff", "--name-only", sha1, sha2)
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
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

	// Print out all of the packages that need rebuilding.
	sorted := []string{}
	for d := range allDownstream {
		sorted = append(sorted, d)
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
