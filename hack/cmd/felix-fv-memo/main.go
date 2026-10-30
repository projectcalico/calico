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

// felix-fv-memo computes the cache keys that let CI skip Felix FV batches whose
// inputs match a batch that already passed.
//
// A lane's key hashes the tracked files that the felix module's change gate
// matches and that its class of lane can execute: of the Go files, those
// compiled into the FV binaries; of the rest, those memoExclusions leave in.
// The gate decides whether FV runs at all, so it must already cover the FV
// build; the tool fails if it does not.
//
// The bpf-gpl programs are inputs only to the BPF lanes; the non-BPF lanes run
// with those objects deleted so that a missed dependency fails rather than
// passing on a stale entry.
//
// Usage:
//
//	felix-fv-memo [-explain <class>] <workflow yaml> <felix module yaml>
//
// prints one "<FELIX_TEST_GROUP> <class> <lane key>" line per felix-fv matrix
// entry.  Fails if the gate misses part of the FV build.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// keyVersion is mixed into every key; bump it when the meaning of a cached
// pass changes in a way the hashed files do not capture.
const keyVersion = "v2"

type class string

const (
	classBPF    class = "bpf"
	classNonBPF class = "nonbpf"
)

// memoExclusions drop the gated non-Go files that one class of lane cannot
// execute.  Nothing checks these, unlike the Go files, so keep them coarse.
// A file the FV build compiles, such as a cgo header, stays regardless.
var memoExclusions = map[class][]string{
	classNonBPF: slices.Concat(commonExclusions, []string{`^felix/bpf-gpl/`}),
	classBPF:    commonExclusions,
}

var commonExclusions = []string{
	`(^|/)testdata/`,
	`(^|/)[^/]*\.md$`,
	`(^|/)(README|LICENSE|AUTHORS|COPYING)[^/]*$`,
	`(^|/)\.(gitignore|gitattributes|dockerignore|golangci\.yaml)$`,
	// The generated Go is what gets compiled.
	`\.proto$`,
	`^(felix|typha)/docs/`,
	`^felix/(debian|rpm|etc|utils|k8sfv)/`,
	// The gate also covers the Windows FVs.
	`^process/testing/`,
	// FV runs Typha from the calico image.
	`^typha/(Makefile$|utils/)`,
}

// fvBuild is what one class of lane compiles.
type fvBuild struct {
	// roots are compiled with their dependency closure.
	roots []string
	// testedRoots also contribute their tests and the tests' imports.
	testedRoots []string
	// shallowRoots contribute only their own files.
	shallowRoots []string
}

var nonBPFBuild = fvBuild{
	roots: []string{
		// Felix runs as the cmd/calico binary, via node's "felix" subcommand.
		"./felix/daemon",
		"github.com/projectcalico/calico/lib/logrusr",
		"github.com/projectcalico/calico/pkg/buildinfo",
		// Typha runs from the calico image as `component typha`.
		"./typha/cmd/typha",
		"./felix/fv/test-workload",
		"./felix/fv/test-connection",
		"./felix/fv/pktgen",
		"./felix/cmd/calico-bpf",
	},
	testedRoots: []string{"./felix/fv"},
	shallowRoots: []string{
		// cmd/calico links every component, but FV runs only its felix and
		// typha subcommands.
		"./cmd/calico",
		"./node/pkg/node",
		// Not run by FV, but a change to how keys are computed must change them.
		"./hack/cmd/felix-fv-memo",
	},
}

var fvBuilds = map[class]fvBuild{
	classNonBPF: nonBPFBuild,
	classBPF: {
		roots: nonBPFBuild.roots,
		// The BPF lanes also run a "ut" batch.
		testedRoots:  slices.Concat(nonBPFBuild.testedRoots, []string{"./felix/bpf", "./felix/bpf/ut"}),
		shallowRoots: nonBPFBuild.shallowRoots,
	},
}

// goBuildConfigs are the build configurations the FV binaries are compiled
// under; each can select different files.
var goBuildConfigs = []struct {
	env   []string
	flags []string
}{
	{env: []string{"CGO_ENABLED=1"}},
	{env: []string{"CGO_ENABLED=1"}, flags: []string{"-race"}},
	{env: []string{"CGO_ENABLED=0"}},
}

func main() {
	explain := flag.String("explain", "", "print the hashed inputs of this class (bpf or nonbpf) to stderr")
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: felix-fv-memo [-explain <class>] <workflow yaml> <felix module yaml>")
		os.Exit(2)
	}
	workflowPath, modulePath := flag.Arg(0), flag.Arg(1)

	repoRoot, err := gitOutput("rev-parse", "--show-toplevel")
	if err != nil {
		fail(err)
	}
	repoRoot = strings.TrimSpace(repoRoot)

	lanes, err := readLanes(modulePath)
	if err != nil {
		fail(err)
	}
	g, err := readGate(repoRoot, workflowPath, modulePath)
	if err != nil {
		fail(err)
	}
	tracked, err := trackedFiles(repoRoot)
	if err != nil {
		fail(err)
	}

	classKeys := map[class]string{}
	for _, c := range []class{classBPF, classNonBPF} {
		files, err := classKeyFiles(repoRoot, g, tracked, c)
		var ungated ungatedError
		if errors.As(err, &ungated) {
			fmt.Fprintf(os.Stderr, "felix-fv-memo: %v; add them to the change gate of %s in %s:\n", err, modulePath, workflowPath)
			for _, f := range ungated.inputs {
				fmt.Fprintln(os.Stderr, "  "+f)
			}
			os.Exit(1)
		}
		if err != nil {
			fail(err)
		}
		manifest, err := buildManifest(repoRoot, files)
		if err != nil {
			fail(err)
		}
		if string(c) == *explain {
			_, _ = os.Stderr.Write(manifest)
		}
		classKeys[c] = hashOf(keyVersion, string(manifest))
	}

	for _, l := range lanes {
		fmt.Printf("%s %s %s\n", l.group, l.class, hashOf(classKeys[l.class], l.group))
	}
}

type lane struct {
	group string
	class class
}

// readLanes returns the felix-fv matrix entries, identified by their
// FELIX_TEST_GROUP.
func readLanes(modulePath string) ([]lane, error) {
	raw, err := os.ReadFile(modulePath)
	if err != nil {
		return nil, err
	}
	var module struct {
		Steps []struct {
			Name   string `json:"name"`
			Matrix []struct {
				Name string `json:"name"`
				Env  []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"env"`
			} `json:"matrix"`
		} `json:"steps"`
	}
	if err := yaml.Unmarshal(raw, &module); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", modulePath, err)
	}

	var lanes []lane
	seen := map[string]bool{}
	for _, step := range module.Steps {
		if step.Name != "felix-fv" {
			continue
		}
		for _, entry := range step.Matrix {
			var group string
			for _, e := range entry.Env {
				if e.Name == "FELIX_TEST_GROUP" {
					group = e.Value
				}
			}
			if group == "" {
				return nil, fmt.Errorf("felix-fv matrix entry %q has no FELIX_TEST_GROUP", entry.Name)
			}
			if seen[group] {
				return nil, fmt.Errorf("FELIX_TEST_GROUP %q names two felix-fv matrix entries", group)
			}
			seen[group] = true
			lanes = append(lanes, lane{group: group, class: classOf(group)})
		}
	}
	if len(lanes) == 0 {
		return nil, fmt.Errorf("no felix-fv matrix entries in %s", modulePath)
	}
	return lanes, nil
}

// classOf must match how the lanes pick the dataplane: a group whose name
// contains "bpf" runs in BPF mode.
func classOf(group string) class {
	if strings.Contains(group, "bpf") {
		return classBPF
	}
	return classNonBPF
}

// gate is an ArgoCI `changes` block with its dependsOn components resolved.
// It matches the way ArgoCI does: each source is judged on its own, so one
// component's exclusions never suppress another's inclusions, but the
// module's own exclusions apply to every source.
type gate struct {
	sources []patterns
	exclude []*regexp.Regexp
}

type patterns struct {
	in, exclude []*regexp.Regexp
}

func (g gate) matches(path string) bool {
	if matchesAnyRegexp(g.exclude, path) {
		return false
	}
	for _, s := range g.sources {
		if matchesAnyRegexp(s.in, path) && !matchesAnyRegexp(s.exclude, path) {
			return true
		}
	}
	return false
}

// readGate returns the change gate that workflowPath puts on the include of
// modulePath.
func readGate(repoRoot, workflowPath, modulePath string) (gate, error) {
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		return gate{}, err
	}
	var workflow struct {
		Dependencies stringOrList `json:"dependencies"`
		Includes     []struct {
			Path    string `json:"path"`
			Changes *struct {
				In        []string `json:"in"`
				Exclude   []string `json:"exclude"`
				DependsOn []string `json:"dependsOn"`
			} `json:"changes"`
		} `json:"includes"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		return gate{}, fmt.Errorf("parsing %s: %w", workflowPath, err)
	}

	components := map[string]rawPatterns{}
	for _, path := range workflow.Dependencies {
		raw, err := os.ReadFile(filepath.Join(repoRoot, path))
		if err != nil {
			return gate{}, err
		}
		var deps struct {
			Components map[string]rawPatterns `json:"components"`
		}
		if err := yaml.Unmarshal(raw, &deps); err != nil {
			return gate{}, fmt.Errorf("parsing %s: %w", path, err)
		}
		for name, c := range deps.Components {
			components[name] = c
		}
	}

	for _, inc := range workflow.Includes {
		if filepath.Clean(inc.Path) != filepath.Clean(modulePath) {
			continue
		}
		ch := inc.Changes
		if ch == nil {
			return gate{}, fmt.Errorf("%s: the include of %s has no change gate", workflowPath, modulePath)
		}
		var g gate
		var err error
		if g.exclude, err = compileAll(ch.Exclude); err != nil {
			return gate{}, err
		}
		sources := []rawPatterns{{In: ch.In}}
		for _, name := range ch.DependsOn {
			c, ok := components[name]
			if !ok {
				return gate{}, fmt.Errorf("%s: dependsOn names unknown component %q", workflowPath, name)
			}
			sources = append(sources, c)
		}
		for _, s := range sources {
			var p patterns
			if p.in, err = compileAll(s.In); err != nil {
				return gate{}, err
			}
			if p.exclude, err = compileAll(s.Exclude); err != nil {
				return gate{}, err
			}
			g.sources = append(g.sources, p)
		}
		return g, nil
	}
	return gate{}, fmt.Errorf("%s does not include %s", workflowPath, modulePath)
}

type rawPatterns struct {
	In      []string `json:"in"`
	Exclude []string `json:"exclude"`
}

type stringOrList []string

func (s *stringOrList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	return json.Unmarshal(data, (*[]string)(s))
}

// classKeyFiles returns the files that the key of a class of lane hashes, or
// an ungatedError if the gate misses part of its FV build.
func classKeyFiles(repoRoot string, g gate, tracked map[string]bool, c class) (map[string]bool, error) {
	build, err := listBuild(repoRoot, tracked, fvBuilds[c])
	if err != nil {
		return nil, fmt.Errorf("listing the %s FV build: %w", c, err)
	}
	files, err := keyFiles(g, tracked, build.files, memoExclusions[c])
	if err != nil {
		return nil, err
	}

	var ungated []string
	for f := range build.files {
		if !g.matches(f) {
			ungated = append(ungated, f)
		}
	}
	// Each component's deps.txt lists the versions of the modules it uses, so
	// that a dependency bump triggers only the components that use it.
	listed := map[string]bool{}
	for f := range files {
		if path.Base(f) != "deps.txt" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			return nil, err
		}
		for line := range strings.Lines(string(content)) {
			listed[strings.TrimSpace(line)] = true
		}
	}
	for m := range build.modules {
		if !listed[m] {
			ungated = append(ungated, "module "+m)
		}
	}
	if len(ungated) > 0 {
		slices.Sort(ungated)
		return nil, ungatedError{class: c, inputs: ungated}
	}
	return files, nil
}

type ungatedError struct {
	class  class
	inputs []string
}

func (e ungatedError) Error() string {
	return fmt.Sprintf("the %s FV build uses %d inputs that the felix module's change gate misses", e.class, len(e.inputs))
}

// keyFiles returns the tracked files that the gate matches and that are either
// compiled into the FV build or non-Go files that exclusions leave in.
func keyFiles(g gate, tracked, compiled map[string]bool, exclusions []string) (map[string]bool, error) {
	exclude, err := compileAll(exclusions)
	if err != nil {
		return nil, err
	}
	files := map[string]bool{}
	for f := range tracked {
		if !g.matches(f) {
			continue
		}
		if !compiled[f] && (strings.HasSuffix(f, ".go") || matchesAnyRegexp(exclude, f)) {
			continue
		}
		files[f] = true
	}
	return files, nil
}

// buildManifest returns one sorted "<path> <sha256>" line per file.
func buildManifest(repoRoot string, files map[string]bool) ([]byte, error) {
	var lines []string
	for f := range files {
		sum, err := fileSHA256(filepath.Join(repoRoot, f))
		if err != nil {
			return nil, err
		}
		lines = append(lines, f+" "+sum)
	}
	slices.Sort(lines)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// buildInputs are what an FV build compiles: files in the repo, and modules
// outside it as "<path> <version>".
type buildInputs struct {
	files, modules map[string]bool
}

func listBuild(repoRoot string, tracked map[string]bool, build fvBuild) (buildInputs, error) {
	used := buildInputs{files: map[string]bool{}, modules: map[string]bool{}}
	for _, cfg := range goBuildConfigs {
		for _, list := range []struct {
			args  []string
			roots []string
		}{
			{[]string{"-deps"}, build.roots},
			{[]string{"-deps", "-test"}, build.testedRoots},
			{nil, build.shallowRoots},
		} {
			pkgs, err := goList(repoRoot, cfg.env, slices.Concat([]string{"list", "-json"}, list.args, cfg.flags, list.roots))
			if err != nil {
				return buildInputs{}, err
			}
			for _, p := range pkgs {
				if err := addPackage(repoRoot, tracked, p, used); err != nil {
					return buildInputs{}, err
				}
			}
		}
	}
	return used, nil
}

type goPackage struct {
	ImportPath                                                                 string
	Dir                                                                        string
	Standard                                                                   bool
	Module                                                                     *module
	GoFiles, CgoFiles, CFiles, CXXFiles, HFiles, SFiles, SysoFiles, EmbedFiles []string
	CgoCFLAGS                                                                  []string
	Error                                                                      *struct{ Err string }
}

type module struct {
	Path, Version string
	Replace       *module
}

func addPackage(repoRoot string, tracked map[string]bool, p goPackage, used buildInputs) error {
	if p.Error != nil {
		return fmt.Errorf("go list: %s: %s", p.ImportPath, p.Error.Err)
	}
	// The toolchain is pinned by metadata.mk.
	if p.Standard {
		return nil
	}
	// The generated test main lives in the build cache, not the repo.
	if strings.HasSuffix(p.ImportPath, ".test") {
		return nil
	}
	rel, err := filepath.Rel(repoRoot, p.Dir)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		if p.Module == nil {
			return fmt.Errorf("package %s is outside the repo but has no module", p.ImportPath)
		}
		m := p.Module
		// The replacement is the code that gets built.
		if m.Replace != nil {
			m = m.Replace
		}
		used.modules[m.Path+" "+m.Version] = true
		return nil
	}
	for _, f := range slices.Concat(p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.HFiles, p.SFiles, p.SysoFiles, p.EmbedFiles) {
		used.files[filepath.ToSlash(filepath.Join(rel, f))] = true
	}
	if len(p.CgoFiles) == 0 {
		return nil
	}
	return addCgoIncludes(repoRoot, tracked, p, used.files)
}

var quotedInclude = regexp.MustCompile(`(?m)^\s*(?://\s*)?#\s*include\s+"([^"]+)"`)

// addCgoIncludes adds the tracked headers a cgo package's C code includes,
// transitively; they live outside the package directory, so go list does not
// report them.  Untracked headers, such as the libbpf checkout, are pinned by
// version variables in the Makefiles.
func addCgoIncludes(repoRoot string, tracked map[string]bool, p goPackage, used map[string]bool) error {
	var includeDirs []string
	for _, flag := range p.CgoCFLAGS {
		if dir, ok := strings.CutPrefix(flag, "-I"); ok {
			includeDirs = append(includeDirs, filepath.Clean(dir))
		}
	}

	var queue []string
	for _, f := range slices.Concat(p.CgoFiles, p.CFiles, p.HFiles) {
		queue = append(queue, filepath.Join(p.Dir, f))
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		if seen[path] {
			continue
		}
		seen[path] = true
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range quotedInclude.FindAllSubmatch(content, -1) {
			name := string(m[1])
			for _, dir := range slices.Concat([]string{filepath.Dir(path)}, includeDirs) {
				candidate := filepath.Join(dir, name)
				rel, err := filepath.Rel(repoRoot, candidate)
				if err != nil {
					return err
				}
				rel = filepath.ToSlash(rel)
				if _, err := os.Stat(candidate); err != nil {
					continue
				}
				// The compiler uses the first match, tracked or not.
				if tracked[rel] {
					used[rel] = true
					queue = append(queue, candidate)
				}
				break
			}
		}
	}
	return nil
}

// goListCache saves listing the roots that the classes of lane share twice.
var goListCache = map[string][]goPackage{}

func goList(dir string, env, args []string) ([]goPackage, error) {
	cacheKey := strings.Join(slices.Concat([]string{dir}, env, args), "\x1f")
	if pkgs, ok := goListCache[cacheKey]; ok {
		return pkgs, nil
	}
	pkgs, err := runGoList(dir, env, args)
	if err != nil {
		return nil, err
	}
	goListCache[cacheKey] = pkgs
	return pkgs, nil
}

func runGoList(dir string, env, args []string) ([]goPackage, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = slices.Concat(os.Environ(), []string{"GOOS=linux", "GOARCH=amd64"}, env)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	var pkgs []goPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			return pkgs, nil
		} else if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
}

func trackedFiles(repoRoot string) (map[string]bool, error) {
	out, err := gitOutput("-C", repoRoot, "ls-files")
	if err != nil {
		return nil, err
	}
	tracked := map[string]bool{}
	for f := range strings.Lines(out) {
		tracked[strings.TrimSuffix(f, "\n")] = true
	}
	return tracked, nil
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func matchesAnyRegexp(res []*regexp.Regexp, s string) bool {
	return slices.ContainsFunc(res, func(re *regexp.Regexp) bool { return re.MatchString(s) })
}

func fileSHA256(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

// hashOf hashes its parts, separated so that ("ab", "c") and ("a", "bc")
// differ.
func hashOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = fmt.Fprintf(h, "%d:%s;", len(p), p)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "felix-fv-memo:", err)
	os.Exit(1)
}
