package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func printUsageAndExit() {
	_, _ = fmt.Fprint(os.Stderr, `CI Dependency helper tool.

Usage:

  deps [options] modules <package>          # Print go modules that package depends on
  deps [options] local-dirs <package>       # Print in-repo go package dirs that
                                  # package depends on.
  deps [options] local-dirs-main-only <package> # Print in-repo go package dirs that
                                  # package depends on. (Main packages only.)
  deps [options] combined <package>         # Print modules then local dirs (prefixed
                                  # with "local:") for deps.txt generation.
  deps [options] test-exclusions <package>  # Print glob patterns to match *_test.go
                                  # files in dependency dirs outside the
                                  # package itself.
  deps [options] sem-change-in(-pretty) <package>[,<secondary package>...] # Print a SemaphoreCI
                                  # conditions DSL change_in() clause for
                                  # <package>, including non-test deps from
                                  # any <secondary package> clauses.

  deps [options] generate-semaphore-yamls          # Generate Semaphore pipeline YAMLs

Options:

  --pretty            # Pretty-print the output (only applies to sem-change-in).
  --loglevel <level>  # Logrus log level (debug, info, warn, error, fatal, panic). Default: warn

The test-exclusions and sem-change-in sub-commands are intended to be used with
packages at the top-level of the repo.  Test exclusions are based on whether
a dependency is within the package.

The change_in() clause always depends on the whole package directory itself.
Some non-Go dependencies are hard-coded in the tool.  For example, it knows
that node depends on felix/bpf-*.
`)
	os.Exit(1)
}

const mainBranchName = "master"

var (
	pretty   = flag.Bool("pretty", false, "Pretty-print the output (only applies to sem-change-in).")
	logLevel = flag.String("loglevel", "warn", "Logrus log level (debug, info, warn, error, fatal, panic).")
)

func main() {
	// We use stdout for the parseable output of the tool so we _do_ want
	// logging to go to stderr.
	logrus.SetOutput(os.Stderr)
	flag.CommandLine.Usage = printUsageAndExit
	flag.Parse()
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("Failed to parse log level %q: %s", *logLevel, err)
	}
	logrus.SetLevel(level)

	logutils.ConfigureFormatter("deps")

	args := flag.Args()
	if len(args) == 0 {
		logrus.Warnf("Missing sub-command")
		printUsageAndExit()
	}

	cmd := args[0]
	var pkg string
	if cmd != "generate-semaphore-yamls" {
		if len(args) != 2 {
			logrus.Warnf("Incorrect number of arguments for %s: %v", cmd, args)
			printUsageAndExit()
		}
		pkg = args[1]
	}

	switch cmd {
	case "modules":
		printModules(pkg)
	case "local-dirs":
		printLocalDirs(pkg, false)
	case "local-dirs-main-only":
		printLocalDirs(pkg, true)
	case "combined":
		printCombined(pkg)
	case "test-exclusions":
		printTestExclusions(pkg)
	case "sem-change-in":
		printSemChangeIn(pkg, *pretty)
	case "generate-semaphore-yamls":
		generateSemaphoreYamls()
	default:
		printUsageAndExit()
	}
}

var defaultInclusions = []string{
	"/metadata.mk",
	"/lib.Makefile",
	"/hack/test/certs/",
}

// nonGoDeps allows for adding additional inclusions to particular packages
// that can't otherwise be detected.  For example, the node image depends on the
// BPF binaries, which are in the felix/bpf* directories.
var nonGoDeps = map[string][]string{
	"node": {
		// confd templates.
		"/confd/etc",
		// BPF programs.
		"/felix/bpf-apache",
		"/felix/bpf-gpl",
		// Root-level Makefile is used to build operator and other images,
		// used by the STs.
		"/Makefile",
		// Kind cluster test infrastructure (scripts, helm values, configs).
		"/hack/test/kind",
	},

	"e2e": {
		// Root-level Makefile is used to build the operator and other images.
		"/Makefile",
	},

	// Whisker is not a go project so we list the whole thing.
	"whisker": {
		"/whisker",
	},
}

var defaultExclusions = []string{
	"/**/.gitignore",
	"/**/README*",
	"/**/LICENSE*",
	"/**/CONTRIBUTING*",
	"/**/AUTHORS*",
	"/**/DEVELOPER_GUIDE*",
	"/**/SECURITY.md",
	"/**/*.md",
}

// extraPrereqRegexps captures some out-of-band knowledge that helps to weed
// out false dependencies.  Before emitting a dependency on the key,
// it checks whether any files in the package match the given regexp.  If they
// don't the dependency is skipped.
var extraPrereqRegexps = map[string]*regexp.Regexp{
	// Every project that imports the libcalico-go client would depend on the
	// IPAM package due to transitive import.  Only list the IPAM package as a
	// dependency if it's actually used.
	"/libcalico-go/lib/ipam": regexp.MustCompile(`\.IPAM\(\)`),
}

// changeInRe matches the ${CHANGE_IN(<spec>)} macro.  changeInWithDependentsRe
// matches the ${CHANGE_IN_WITH_DEPENDENTS(<own spec>)} macro.  The two are
// disjoint: CHANGE_IN requires "(" immediately after "CHANGE_IN", which the
// _WITH_DEPENDENTS form does not satisfy, so the CHANGE_IN regex never matches
// (a substring of) the longer macro.
var (
	changeInRe               = regexp.MustCompile(`\$\{CHANGE_IN\(([^)]+)\)}`)
	changeInWithDependentsRe = regexp.MustCompile(`\$\{CHANGE_IN_WITH_DEPENDENTS\(([^)]*)\)}`)
)

// calculateDeps calculates the file-level dependencies of the input package
// specs.  Each package spec is a comma-delimited list of directories relative
// to the root of the repo.  The first entry in the list is the "primary"
// package for which we include all Go files, including test files and all
// their dependencies.  The subsequent items are "secondary" build-only
// dependencies, for which we include non-test files only.
func calculateDeps(packages set.Set[string]) map[string]*Deps {
	deps := map[string]*Deps{}
	for pkg := range packages.All() {
		deps[pkg] = nil
	}

	var lock sync.Mutex
	var eg errgroup.Group
	eg.SetLimit(runtime.NumCPU())
	for pkg := range deps {
		eg.Go(func() error {
			repl, err := calculateSemDeps(pkg)
			if err != nil {
				return fmt.Errorf("failed to calculate change_in for package %s: %w", pkg, err)
			}
			lock.Lock()
			deps[pkg] = repl
			lock.Unlock()
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		logrus.Fatalln("Failed to calculate change_in dependencies:", err)
	}
	return deps
}

func printSemChangeIn(pkg string, pretty bool) {
	changeIn, err := calculateChangeIn(pkg, pretty)
	if err != nil {
		logrus.Fatalf("Failed to calculate change_in for package %s: %v", pkg, err)
	}
	_, _ = fmt.Println(changeIn)
}

func calculateChangeIn(pkg string, pretty bool) (string, error) {
	deps, err := calculateSemDeps(pkg)
	if err != nil {
		return "", err
	}
	return formatChangeIn(deps.Inclusions, deps.Exclusions, pretty, ""), nil
}

func formatChangeIn(inclusions set.Set[string], exclusions set.Set[string], pretty bool, defaultBranchStanza string) string {
	incl := formatSemList(dropSubsumedInclusions(inclusions))
	excl := formatSemList(exclusions)
	if pretty {
		incl = "\n" + strings.ReplaceAll(incl, ",", ",\n  ") + "\n"
		excl = "\n" + strings.ReplaceAll(excl, ",", ",\n  ") + "\n"
	}
	out := fmt.Sprintf("change_in(%s, {pipeline_file: 'ignore', exclude: %s%s})", incl, excl, defaultBranchStanza)
	return out
}

// dropSubsumedInclusions removes inclusion globs already covered by a broader
// whole-directory glob ("<dir>/**") in the same set.  Merging several
// dependents' triggers (see mergeDepsSuperset) tends to union a whole-tree glob
// like "/felix/**" with narrower per-subdir globs like "/felix/fv/*.go"
// contributed by a dependent that only reaches part of that tree; the narrower
// entries are redundant and just add noise to the generated change_in() list.
func dropSubsumedInclusions(inclusions set.Set[string]) set.Set[string] {
	// A "<dir>/**" glob (with a wildcard-free prefix) subsumes anything under
	// "<dir>/".
	var prefixes []string
	for incl := range inclusions.All() {
		if dir, ok := strings.CutSuffix(incl, "/**"); ok && !strings.Contains(dir, "*") {
			prefixes = append(prefixes, dir+"/")
		}
	}
	if len(prefixes) == 0 {
		return inclusions // Nothing can subsume anything.
	}

	out := set.New[string]()
	for incl := range inclusions.All() {
		if !isSubsumed(incl, prefixes) {
			out.Add(incl)
		}
	}
	return out
}

// isSubsumed reports whether incl falls under a broader glob prefix other than
// its own.  Skipping incl's own prefix ("<dir>/**") keeps the broad glob itself,
// while a nested "<dir>/sub/**" is still dropped by the outer "<dir>/" prefix.
func isSubsumed(incl string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if incl == prefix+"**" {
			continue // The subsuming glob itself.
		}
		if strings.HasPrefix(incl, prefix) {
			return true
		}
	}
	return false
}

type Deps struct {
	Inclusions set.Set[string]
	Exclusions set.Set[string]
}

func calculateSemDeps(pkgList string) (deps *Deps, err error) {
	parts := strings.Split(pkgList, ",")
	primaryPkg := parts[0]
	otherPkgs := parts[1:]
	if len(otherPkgs) == 0 {
		logrus.Infof("Calculating deps for %s package", primaryPkg)
	} else {
		logrus.Infof("Calculating deps for %s package; including secondary deps: %v", primaryPkg, otherPkgs)
	}

	localDirs, err := loadLocalDirs(primaryPkg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to load local dirs: %w", err)
	}

	inclusions := set.New[string]()
	inclusions.Add("/" + primaryPkg + "/**")
	inclusions.AddAll(defaultInclusions)
	inclusions.AddAll(nonGoDeps[primaryPkg])
	// dirs under the primary package are covered by the "/<pkg>/**" glob above;
	// formatChangeIn's dropSubsumedInclusions drops the redundant per-dir globs.
	for _, dir := range localDirs {
		inclusions.Add(dir + "/*.go")
	}

	exclusions := set.From(calculateTestExclusionGlobs(primaryPkg, localDirs)...)
	exclusions.AddAll(defaultExclusions)

	// Some jobs depend on secondary packages.  For example, the node tests
	// also run typha, api server, etc.  Add inclusions for those.
	for _, otherPkg := range otherPkgs {
		otherPkgDirs, err := addSecondaryPkgInclusions(inclusions, otherPkg)
		if err != nil {
			return nil, err
		}
		exclusions.AddAll(calculateTestExclusionGlobs(primaryPkg, otherPkgDirs))
	}

	return &Deps{inclusions, exclusions}, nil
}

// addSecondaryPkgInclusions adds the build-input inclusions for one secondary
// package spec: either a "non-go:<path>" literal, or a Go package whose main
// package's dirs, Makefile, deps.txt, Dockerfiles and nonGoDeps are inputs.  It
// returns the package's local dirs (nil for a non-go: spec) so the caller can
// derive test-exclusion globs.
//
// We only list dependencies of "main" packages (loadLocalDirs mainDepsOnly).
// This prevents us from picking up test-only dependencies: for example,
// kube-controllers FV has utility packages that depend on felix's FV infra
// packages; without the filter we'd pick those up unintentionally.
func addSecondaryPkgInclusions(inclusions set.Set[string], pkg string) ([]string, error) {
	if after, ok := strings.CutPrefix(pkg, "non-go:"); ok {
		inclusions.Add(after)
		return nil, nil
	}
	dirs, err := loadLocalDirs(pkg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to load local dirs for secondary package %s: %w", pkg, err)
	}
	for _, dir := range dirs {
		inclusions.Add(dir + "/*.go")
	}
	inclusions.Add(pkg + "/Makefile")
	inclusions.Add(pkg + "/deps.txt")
	inclusions.Add(pkg + "/**/*Dockerfile*")
	inclusions.AddAll(nonGoDeps[pkg])
	return dirs, nil
}

// blockInfo is the slice of a Semaphore block that we need to resolve
// CHANGE_IN_WITH_DEPENDENTS macros: its name, the file it lives in, its raw
// run.when, its dependencies, and (if it uses the macro) the macro's own-spec.
type blockInfo struct {
	name         string
	file         string // originating template path, e.g. .semaphore/semaphore.yml.d/blocks/20-node.yml
	when         string
	dependencies []string
	isMacro      bool
	macroArg     string // own-spec inside CHANGE_IN_WITH_DEPENDENTS(...) (may be empty)
}

// blockGraph models the block dependency graph parsed from the template files.
type blockGraph struct {
	blocks     []*blockInfo            // in document order
	byName     map[string]*blockInfo   // name -> block
	dependents map[string][]*blockInfo // producer name -> blocks that depend on it
}

// parseBlockGraph YAML-parses the (un-indented) block templates into a
// dependency graph.  Block names are globally unique in Semaphore, so the
// reverse (producer -> dependents) map is unambiguous.
func parseBlockGraph(blocks []templateData) (*blockGraph, error) {
	g := &blockGraph{
		byName:     map[string]*blockInfo{},
		dependents: map[string][]*blockInfo{},
	}
	for _, t := range blocks {
		var parsed []struct {
			Name string `yaml:"name"`
			Run  struct {
				When string `yaml:"when"`
			} `yaml:"run"`
			Dependencies []string `yaml:"dependencies"`
		}
		if err := yaml.Unmarshal([]byte(t.content), &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse blocks from %s: %w", t.originalPath, err)
		}
		for _, p := range parsed {
			b := &blockInfo{
				name:         p.Name,
				file:         t.originalPath,
				when:         p.Run.When,
				dependencies: p.Dependencies,
			}
			if m := changeInWithDependentsRe.FindStringSubmatch(p.Run.When); m != nil {
				b.isMacro = true
				b.macroArg = strings.TrimSpace(m[1])
			}
			if prev, dup := g.byName[b.name]; dup {
				return nil, fmt.Errorf("duplicate block name %q (in %s and %s)", b.name, prev.file, b.file)
			}
			g.byName[b.name] = b
			g.blocks = append(g.blocks, b)
		}
	}
	// Build the reverse map and validate that every dependency names a real
	// block (catches typos and renames now that we have a block model).
	for _, b := range g.blocks {
		for _, dep := range b.dependencies {
			if _, ok := g.byName[dep]; !ok {
				return nil, fmt.Errorf("block %q (%s) depends on unknown block %q", b.name, b.file, dep)
			}
			g.dependents[dep] = append(g.dependents[dep], b)
		}
	}
	return g, nil
}

// macroBlocksInFile returns the CHANGE_IN_WITH_DEPENDENTS blocks originating in
// the given file, in document order.  buildSemaphoreYAML uses this to map the
// Nth macro occurrence in a file's content to the Nth such block.
func (g *blockGraph) macroBlocksInFile(file string) []*blockInfo {
	var out []*blockInfo
	for _, b := range g.blocks {
		if b.isMacro && b.file == file {
			out = append(out, b)
		}
	}
	return out
}

// calculateDependentMacroDeps resolves every ${CHANGE_IN_WITH_DEPENDENTS(...)}
// macro to a single merged Deps that is a superset of the producer's own spec
// and of every block that depends on the producer.  The result is keyed by
// block name; buildSemaphoreYAML maps each macro occurrence to its block by
// document order, so two blocks may share an identical own-spec arg.
//
// Producers can chain: a dependent may itself be a CHANGE_IN_WITH_DEPENDENTS
// producer (e.g. "Build: node image" both consumes "Build: nftables RPMs" and
// produces for others).  We resolve recursively so that a chained dependent
// contributes its *final* effective trigger (its own merge, transitively), which
// keeps the superset invariant intact up the chain.  The block dependency graph
// is a DAG (Semaphore forbids cycles), but we still guard against cycles.
func calculateDependentMacroDeps(g *blockGraph, deps map[string]*Deps) (map[string]*Deps, error) {
	resolved := map[string]*Deps{} // block name -> final effective trigger
	inProgress := set.New[string]()

	var resolve func(b *blockInfo) (*Deps, error)
	resolve = func(b *blockInfo) (*Deps, error) {
		if d, ok := resolved[b.name]; ok {
			return d, nil
		}
		if inProgress.Contains(b.name) {
			return nil, fmt.Errorf("dependency cycle detected involving block %q", b.name)
		}
		inProgress.Add(b.name)
		defer inProgress.Discard(b.name)

		// Start from the producer's own intrinsic trigger.
		own, err := calculateMacroOwnDeps(b.macroArg)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve own-spec for block %q: %w", b.name, err)
		}
		parts := []*Deps{own}

		dependents := g.dependents[b.name]
		if len(dependents) == 0 {
			logrus.Warnf("Block %q uses CHANGE_IN_WITH_DEPENDENTS but no block depends on it; its trigger reflects only its own spec.", b.name)
		}
		for _, dep := range dependents {
			var depDeps *Deps
			if dep.isMacro {
				// Chained producer: use its full (recursively-resolved) trigger.
				depDeps, err = resolve(dep)
			} else {
				depDeps, err = dependentChangeInDeps(dep, deps)
			}
			if err != nil {
				return nil, fmt.Errorf("block %q: dependent %q: %w", b.name, dep.name, err)
			}
			parts = append(parts, depDeps)
		}

		merged := mergeDepsSuperset(parts)
		// A dependent also runs when its own block file changes (its clause gets
		// that path added at format time), so the producer must too.
		for _, dep := range dependents {
			merged.Inclusions.Add("/" + dep.file)
		}
		resolved[b.name] = merged
		return merged, nil
	}

	out := map[string]*Deps{}
	for _, b := range g.blocks {
		if !b.isMacro {
			continue
		}
		merged, err := resolve(b)
		if err != nil {
			return nil, err
		}
		out[b.name] = merged
	}
	return out, nil
}

// dependentChangeInDeps returns the resolved Deps of a non-macro block that
// depends on a CHANGE_IN_WITH_DEPENDENTS producer.  The dependent's run.when
// must reduce to a single ${CHANGE_IN(...)} clause, optionally prefixed/suffixed
// by a *constant* boolean combinator (`${FORCE_RUN} or ...`, `false or ...`).
// A non-constant condition (branch matching, `and`, parentheses) could let the
// dependent run when its CHANGE_IN is false — which a single merged change_in
// clause cannot represent — so we fail loudly rather than emit an unsound
// superset.  The constant `or`-prefix is safe: in PR builds it is false (so the
// dependent reduces to CHANGE_IN), and in scheduled builds the producer's own
// macro resolves to `true` anyway.
func dependentChangeInDeps(dep *blockInfo, deps map[string]*Deps) (*Deps, error) {
	when := strings.TrimSpace(dep.when)
	matches := changeInRe.FindAllStringSubmatch(when, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf("its run.when must contain exactly one ${CHANGE_IN(...)} to be a CHANGE_IN_WITH_DEPENDENTS dependent, got %q", when)
	}
	full, arg := matches[0][0], matches[0][1]
	residual := strings.Replace(when, full, "", 1)
	for _, tok := range strings.Fields(residual) {
		switch tok {
		case "or", "false", "true", "${FORCE_RUN}":
		default:
			return nil, fmt.Errorf("its run.when has an unsupported form (only a single ${CHANGE_IN(...)} optionally combined with a constant `or` is allowed): %q", when)
		}
	}
	d := deps[arg]
	if d == nil {
		return nil, fmt.Errorf("no resolved deps for CHANGE_IN(%s)", arg)
	}
	return d, nil
}

// calculateMacroOwnDeps resolves a CHANGE_IN_WITH_DEPENDENTS own-spec.  Unlike a
// CHANGE_IN spec it has no "primary" whole-package element: every comma-separated
// entry is treated like a CHANGE_IN secondary (a non-go: path, or a Go package
// whose main-package deps are included), plus the default inclusions/exclusions.
func calculateMacroOwnDeps(spec string) (*Deps, error) {
	inclusions := set.New[string]()
	inclusions.AddAll(defaultInclusions)
	exclusions := set.From(defaultExclusions...)
	if strings.TrimSpace(spec) == "" {
		return &Deps{inclusions, exclusions}, nil
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := addSecondaryPkgInclusions(inclusions, part); err != nil {
			return nil, err
		}
	}
	return &Deps{inclusions, exclusions}, nil
}

// mergeDepsSuperset merges Deps into a single change_in clause that fires
// whenever any input clause would fire.  Inclusions are unioned; exclusions are
// INTERSECTED.  Intersecting is the sound direction: a pattern survives only if
// every input excludes it, so no input's exclusion can suppress another input's
// inclusion (which would cause an under-fire).  The result is a superset and may
// slightly over-fire (e.g. on a test file one input excludes but another's
// inclusion still matches) — harmless for a cache-cheap producer.
func mergeDepsSuperset(parts []*Deps) *Deps {
	inclusions := set.New[string]()
	for _, p := range parts {
		inclusions.AddSet(p.Inclusions)
	}
	exclusions := parts[0].Exclusions.Copy()
	for _, p := range parts[1:] {
		exclusions = intersectSets(exclusions, p.Exclusions)
	}
	return &Deps{Inclusions: inclusions, Exclusions: exclusions}
}

func intersectSets(a, b set.Set[string]) set.Set[string] {
	out := set.New[string]()
	for x := range a.All() {
		if b.Contains(x) {
			out.Add(x)
		}
	}
	return out
}

func filterInclusions(primaryPkg string, inclusions set.Set[string]) set.Typed[string] {
	out := set.New[string]()

	conditionalIncludes := map[string]*regexp.Regexp{}
	for item := range inclusions.All() {
		if r := extraPrereqRegexps[item]; r != nil {
			conditionalIncludes[item] = r
		} else {
			out.Add(item)
		}
	}

	if len(conditionalIncludes) == 0 {
		return out
	}

	dirFS := os.DirFS(".").(fs.ReadFileFS)
	err := fs.WalkDir(dirFS, primaryPkg, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if data, err := dirFS.ReadFile(path); err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		} else {
			for in, re := range conditionalIncludes {
				if re.Match(data) {
					out.Add(in)
					delete(conditionalIncludes, in)
				}
			}
		}
		if len(conditionalIncludes) == 0 {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		logrus.Fatalf("Failed to filter inclusions for %s: %v", primaryPkg, err)
	}

	return out
}

func formatSemList(s set.Set[string]) string {
	items := s.Slice()
	sort.Strings(items)

	var quoted []string
	for _, s := range items {
		quoted = append(quoted, fmt.Sprintf("'%s'", s))
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func printLocalDirs(pkg string, mainsOnly bool) {
	localDirs, err := loadLocalDirs(pkg, mainsOnly)
	if err != nil {
		logrus.Fatalln("Failed to load local dirs:", err)
		os.Exit(1)
	}
	logrus.Infof("Loaded %d local dirs.", len(localDirs))
	for _, dir := range localDirs {
		_, _ = fmt.Println(dir)
	}
}

func printCombined(pkg string) {
	printModules(pkg)
	localDirs, err := loadLocalDirs(pkg, true)
	if err != nil {
		logrus.Fatalln("Failed to load local dirs:", err)
		os.Exit(1)
	}
	if len(localDirs) > 0 {
		fmt.Println()
		for _, dir := range localDirs {
			// Strip leading "/" and prefix with "local:" so the Makefile
			// can grep these out easily.
			_, _ = fmt.Println("local:" + strings.TrimPrefix(dir, "/"))
		}
	}
}

func printTestExclusions(pkg string) {
	localDirs, err := loadLocalDirs(pkg, false)
	if err != nil {
		logrus.Fatalln("Failed to load local dirs:", err)
		os.Exit(1)
	}
	for _, dir := range calculateTestExclusionGlobs(pkg, localDirs) {
		_, _ = fmt.Println(dir)
	}
}

func calculateTestExclusionGlobs(pkg string, localDirs []string) []string {
	// If the dir is not within the package, write a glob that excludes its
	// tests.
	prefix := "/" + pkg + "/"
	exclusions := set.New[string]()
	for _, dir := range localDirs {
		if strings.HasPrefix(dir+"/", prefix) {
			// Within the main package, so don't exclude.
			continue
		}
		// Outside the main package. Include the top-level dir as a globbed
		// exclusion.
		parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
		exclusions.Add("/" + parts[0] + "/**/*_test.go")
	}
	s := exclusions.Slice()
	sort.Strings(s)
	return s
}

func loadLocalDirs(pkg string, mainDepsOnly bool) (out []string, err error) {
	packageDeps, err := loadPackageDeps(pkg, mainDepsOnly)
	if err != nil {
		logrus.Fatalln("Failed to load package deps:", err)
		os.Exit(1)
	}
	for _, pkg := range packageDeps {
		const ourPackage = "github.com/projectcalico/calico"
		if strings.HasPrefix(pkg, ourPackage+"/") {
			pkg = strings.TrimPrefix(pkg, ourPackage)
			out = append(out, pkg)
		}
	}

	out = filterInclusions(pkg, set.FromArray(out)).Slice()
	sort.Strings(out)
	return out, nil
}

func printModules(pkg string) {
	packageDeps, err := loadPackageDeps(pkg, false)
	if err != nil {
		logrus.Fatalf("Failed to load package deps for package %s: %s", pkg, err)
		os.Exit(1)
	}
	logrus.Infof("Loaded %d deps for package %q.", len(packageDeps), pkg)
	modules, err := loadGoMods()
	if err != nil {
		logrus.Fatalln("Failed to load go modules:", err)
		os.Exit(1)
	}
	logrus.Infof("Loaded %d go modules.", len(modules))

	// For ease, do the full cross product. Only takes ~100ms.
	var mods []string
	for _, mod := range modules {
		if mod.Replace != nil {
			mod = *mod.Replace
		}
		for _, pkg := range packageDeps {
			if strings.HasPrefix(pkg, mod.Path) {
				if mod.Version != "" {
					mods = append(mods, mod.Path+" "+mod.Version)
				} else {
					mods = append(mods, mod.Path)
				}
				break
			}
		}
	}
	sort.Strings(mods)
	for _, m := range mods {
		_, _ = fmt.Println(m)
	}
	logrus.Info("Done.")
}

func loadPackageDeps(pkg string, mainDepsOnly bool) ([]string, error) {
	pkgs := []string{"./..."}

	if mainDepsOnly {
		var err error
		pkgs, err = findMainPackages(pkg)
		if err != nil {
			return nil, err
		}
		if len(pkgs) == 0 {
			logrus.Infof("No main packages found in %s", pkg)
			return nil, nil
		}
	}

	args := append([]string{"list", "-deps"}, pkgs...)
	command := exec.Command("go", args...)
	command.Dir = pkg
	raw, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to load package deps for %v: %w", pkgs, err)
	}
	var out []string
	for line := range bytes.Lines(raw) {
		dep := string(bytes.TrimSpace(line))
		if strings.HasPrefix(dep, "github.com/projectcalico/api/") {
			// HACK, handle the API go mod replace.
			dep = strings.Replace(dep, "github.com/projectcalico/api/", "github.com/projectcalico/calico/api/", 1)
		}
		out = append(out, dep)
		logrus.Debugf("Loaded package: %s", strings.TrimRight(string(line), "\n"))
	}
	return out, nil
}

func findMainPackages(pkg string) ([]string, error) {
	command := exec.Command("go", "list", "-find", "-f", "{{.Name}} {{.ImportPath}}", "./...")
	command.Dir = pkg
	raw, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to find main packages in %s: %w", pkg, err)
	}
	var pkgs []string
	for line := range bytes.Lines(raw) {
		if !bytes.HasPrefix(line, []byte("main ")) {
			continue
		}
		mainPkg := string(bytes.TrimPrefix(line, []byte("main ")))
		mainPkg = strings.TrimSpace(mainPkg)
		pkgs = append(pkgs, mainPkg)
	}
	logrus.Infof("Found main packages in %s: %v", pkg, pkgs)
	return pkgs, nil
}

type module struct {
	Path    string
	Version string
	Replace *module
}

func loadGoMods() ([]module, error) {
	return loadGoToolJSON[module]("list", "-m", "-json", "all")
}

func loadGoToolJSON[Item any](args ...string) ([]Item, error) {
	cmd := exec.Command("go", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		errOut := stderr.Bytes()
		return nil, fmt.Errorf("%w, %s", err, string(errOut))
	}
	var items []Item
	decoder := json.NewDecoder(bytes.NewReader(out))
	for decoder.More() {
		var item Item
		if err := decoder.Decode(&item); err != nil {
			return nil, err
		}
		items = append(items, item)
		logrus.Debugf("Loaded item: %+v", item)
	}
	return items, nil
}

type templateData struct {
	originalPath string
	filename     string
	content      string
}

func generateSemaphoreYamls() {
	logrus.Info("Generating semaphore YAML pipeline files")
	semaphoreDir := ".semaphore"
	defaultBranchStanza, err := calculateBranchStanza(semaphoreDir)
	if err != nil {
		logrus.Fatalf("Failed to calculate default branch stanza: %v", err)
	}
	logrus.Infof("Using default branch stanza: %q", defaultBranchStanza)

	// Validate change_in lines in template blocks include pipeline_file stanza.
	if err := validateChangeInClauses(semaphoreDir); err != nil {
		logrus.Fatalf("Template validation failed: %v", err)
	}

	// Load all the template files
	templatesDir := filepath.Join(semaphoreDir, "semaphore.yml.d")
	templates, err := readTemplates(templatesDir)
	if err != nil {
		logrus.Fatalf("Failed to read templates: %v", err)
	}
	var globalExtraDeps []string
	for _, t := range templates {
		globalExtraDeps = append(globalExtraDeps, "/"+t.originalPath)
	}
	blocksDir := filepath.Join(semaphoreDir, "semaphore.yml.d", "blocks")
	blocks, err := readTemplates(blocksDir)
	if err != nil {
		logrus.Fatalf("Failed to read templates: %v", err)
	}

	// Parse the (still un-indented) blocks into a dependency graph so we can
	// resolve ${CHANGE_IN_WITH_DEPENDENTS(...)} macros: a "producer" block that
	// must run whenever any block that depends on it runs.
	graph, err := parseBlockGraph(blocks)
	if err != nil {
		logrus.Fatalf("Failed to parse block dependency graph: %v", err)
	}

	// For convenience when writing blocks we add an indent here.
	blocks = indentBlocks(blocks)

	// But after that, we can treat all templates equally.
	templates = append(templates, blocks...)
	sort.Slice(templates, func(i, j int) bool {
		// Sort only on the filename, so we make use of the numeric prefixes.
		return strings.Compare(templates[i].filename, templates[j].filename) < 0
	})

	// Next, collect all the CHANGE_IN placeholders and do the heavy-lift
	// calculation to figure out the dependencies.
	placeholders := extractChangeInPlaceholders(templates)
	deps := calculateDeps(placeholders)

	// Resolve the ${CHANGE_IN_WITH_DEPENDENTS(...)} macros now that every plain
	// CHANGE_IN clause has been resolved: each macro merges the producer's own
	// spec with the resolved change_in of every block that depends on it.
	macroDeps, err := calculateDependentMacroDeps(graph, deps)
	if err != nil {
		logrus.Fatalf("Failed to calculate CHANGE_IN_WITH_DEPENDENTS dependencies: %v", err)
	}

	// Build the main file, which is triggered by PRs and uses the calculated
	// dependencies.
	mainFile := filepath.Join(semaphoreDir, "semaphore.yml")
	err = buildSemaphoreYAML(mainFile, templates, globalExtraDeps, deps, macroDeps, graph, false, defaultBranchStanza)
	if err != nil {
		logrus.Fatalf("Failed to build semaphore YAML: %v", err)
	}

	// Build the scheduled file, which builds all our code, but not slow
	// third-party builds.
	scheduledFile := filepath.Join(semaphoreDir, "semaphore-scheduled-builds.yml")
	err = buildSemaphoreYAML(scheduledFile, templates, globalExtraDeps, nil, nil, graph, false, defaultBranchStanza)
	if err != nil {
		logrus.Fatalf("Failed to build semaphore YAML: %v", err)
	}

	// If needed, build the third-party file, which runs weekly.
	thirdPartyFile := filepath.Join(semaphoreDir, "semaphore-third-party-builds.yml")
	var weeklyTemplates []templateData
	foundWeekly := false
	for _, t := range templates {
		switch t.filename {
		case "01-preamble.yml",
			"02-global_job_config.yml",
			"10-prerequisites.yml",
			"09-blocks.yml":
			weeklyTemplates = append(weeklyTemplates, t)
		default:
			if strings.Contains(t.content, "WEEKLY_RUN") {
				weeklyTemplates = append(weeklyTemplates, t)
				foundWeekly = true
			}
		}
	}
	if foundWeekly {
		logrus.Infof("Found templates that run weekly, generating %s.", thirdPartyFile)
		err = buildSemaphoreYAML(thirdPartyFile, weeklyTemplates, globalExtraDeps, nil, nil, graph, true, defaultBranchStanza)
		if err != nil {
			logrus.Fatalf("Failed to build semaphore YAML: %v", err)
		}
	}

	logrus.Info("Semaphore YAML generation complete")
}

func buildSemaphoreYAML(file string, templates []templateData, globalExtraDeps []string, deps map[string]*Deps, macroDeps map[string]*Deps, graph *blockGraph, weekly bool, defaultBranchStanza string) error {
	var data bytes.Buffer

	data.WriteString(
		"# !! WARNING, DO NOT EDIT !! This file is generated from the templates\n" +
			"# in /.semaphore/semaphore.yml.d. To update, modify the relevant\n" +
			"# template and then run 'make gen-semaphore-yaml'.\n",
	)

	// Force the extraDeps := append(...) call below to allocate a fresh copy
	// by capping the len/cap of globalExtraDeps.
	globalExtraDeps = globalExtraDeps[:len(globalExtraDeps):len(globalExtraDeps)]

	weeklyRun := "false"
	if weekly {
		weeklyRun = "true"
	}
	forceRun := "false"
	if deps == nil {
		forceRun = "true"
	}
	for _, t := range templates {
		extraDeps := append(globalExtraDeps, "/"+t.originalPath)
		content := changeInRe.ReplaceAllStringFunc(t.content, func(match string) string {
			pkg := changeInRe.FindStringSubmatch(match)[1]
			if deps == nil {
				// Generating a daily/weekly file.
				return "true"
			}
			dep := deps[pkg]
			inclusions := dep.Inclusions.Copy()
			for _, d := range extraDeps {
				inclusions.Add(d)
			}
			return formatChangeIn(inclusions, dep.Exclusions, false, defaultBranchStanza)
		})
		// CHANGE_IN_WITH_DEPENDENTS expands, like CHANGE_IN, to a single
		// change_in(...) clause (so the folded-scalar post-processing applies
		// unchanged) — but its dependency set was pre-merged from the producer's
		// dependents in calculateDependentMacroDeps. The replacement is
		// block-specific (two blocks may share an arg), so we map each macro
		// occurrence to its block by document order within this file.
		fileMacroBlocks := graph.macroBlocksInFile(t.originalPath)
		macroIdx := 0
		content = changeInWithDependentsRe.ReplaceAllStringFunc(content, func(match string) string {
			if deps == nil {
				// Generating a daily/weekly file.
				return "true"
			}
			if macroIdx >= len(fileMacroBlocks) {
				// The regex found more macro occurrences than parseBlockGraph
				// mapped to blocks in this file (e.g. a macro outside a block's
				// run.when).  Fail clearly rather than index out of range.
				logrus.Fatalf("CHANGE_IN_WITH_DEPENDENTS in %s does not correspond to a parsed block; the macro is only supported in a block's run.when", t.originalPath)
			}
			b := fileMacroBlocks[macroIdx]
			macroIdx++
			md := macroDeps[b.name]
			if md == nil {
				logrus.Fatalf("No resolved CHANGE_IN_WITH_DEPENDENTS dependencies for block %q", b.name)
			}
			inclusions := md.Inclusions.Copy()
			for _, d := range extraDeps {
				inclusions.Add(d)
			}
			return formatChangeIn(inclusions, md.Exclusions, false, defaultBranchStanza)
		})
		content = strings.ReplaceAll(content, "${FORCE_RUN}", forceRun)
		content = strings.ReplaceAll(content, "${WEEKLY_RUN}", weeklyRun)
		content = strings.ReplaceAll(content, "${DEFAULT_BRANCH}", defaultBranchStanza)
		_, _ = data.WriteString(content)
	}

	return os.WriteFile(file, []byte(convertToFoldedScalars(data.String())), 0644)
}

func indentBlocks(blocks []templateData) []templateData {
	for i, block := range blocks {
		lines := strings.Split(block.content, "\n")
		var indented strings.Builder
		for _, line := range lines {
			if line == "" {
				// Ignore blank lines (and in particular, the empty "line" that
				// Split() creates if the content ends with a newline.
				continue
			}
			indented.WriteString("  " + line + "\n")
		}
		blocks[i].content = indented.String()
	}
	return blocks
}

func readTemplates(templatesDir string) ([]templateData, error) {
	templateFiles, err := os.ReadDir(templatesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}
	var templates []templateData
	for _, t := range templateFiles {
		if t.IsDir() {
			continue
		}
		if !strings.HasSuffix(t.Name(), ".yml") {
			continue
		}
		origPath := filepath.Join(templatesDir, t.Name())
		contentBytes, err := os.ReadFile(origPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read template file %s: %v", origPath, err)
		}
		content := string(contentBytes)
		// Clean up extra space at end of file; but ensure there's one newline.
		content = strings.TrimRight(content, "\n ")
		content += "\n"
		templates = append(templates, templateData{
			originalPath: origPath,
			filename:     t.Name(),
			content:      content,
		})
	}
	return templates, err
}

func mustReadFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		logrus.Fatalf("Failed to read %s: %v", path, err)
	}
	return b
}

func extractChangeInPlaceholders(templates []templateData) set.Set[string] {
	out := set.New[string]()
	for _, t := range templates {
		matches := changeInRe.FindAllStringSubmatch(t.content, -1)
		for _, m := range matches {
			out.Add(m[1])
		}
	}
	return out
}

func validateChangeInClauses(semaphoreDir string) error {
	root := filepath.Join(semaphoreDir, "semaphore.yml.d")
	var offending []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data := mustReadFile(path)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			l := scanner.Text()
			if strings.Contains(l, "change_in(") && !strings.Contains(l, "pipeline_file:") {
				offending = append(offending, fmt.Sprintf("%s: %s", path, l))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(offending) > 0 {
		return fmt.Errorf("all change_in clauses must include pipeline_file: 'ignore' (or 'track'). Offending lines:\n%s", strings.Join(offending, "\n"))
	}
	return nil
}

func calculateBranchStanza(semaphoreDir string) (string, error) {
	branch, err := calculateDefaultBranch(semaphoreDir)
	if err != nil {
		return "", err
	}
	if branch == mainBranchName {
		// Default, so no need to specify.
		return "", nil
	}
	return fmt.Sprintf(", default_branch: '%s'", branch), nil
}

func calculateDefaultBranch(semaphoreDir string) (string, error) {
	if branch := os.Getenv("DEFAULT_BRANCH_OVERRIDE"); branch != "" {
		// Manual override.
		logrus.Infof("Using DEFAULT_BRANCH_OVERRIDE for default branch: %s", branch)
		return branch, nil
	}

	releaseBranchPrefix := os.Getenv("RELEASE_BRANCH_PREFIX")
	if releaseBranchPrefix == "" {
		return "", fmt.Errorf("RELEASE_BRANCH_PREFIX not set")
	}
	releaseBranchRegexp := regexp.MustCompile(`^` + regexp.QuoteMeta(releaseBranchPrefix) + `-v[\d.-]+$`)

	// In CI, SEMAPHORE_GIT_BRANCH is set either to the current branch, if
	// we're building on a branch, or to the target branch if we're building
	// a PR. For stacked PRs (PR2 targets PR1's branch), the target branch
	// can be a non-master, non-release branch — ignore those and fall
	// through to detecting the default from the existing semaphore.yml.
	if branch := os.Getenv("SEMAPHORE_GIT_BRANCH"); branch != "" {
		if branch == mainBranchName || releaseBranchRegexp.MatchString(branch) {
			logrus.Infof("Using SEMAPHORE_GIT_BRANCH for default branch: %s", branch)
			return branch, nil
		}
		logrus.Infof("SEMAPHORE_GIT_BRANCH %q is not master or a release branch, ignoring.", branch)
	} else {
		// Fallback to git.
		out, err := exec.Command("git", "branch", "--show-current").Output()
		if err != nil {
			return "", fmt.Errorf("git branch --show-current failed: %w", err)
		}
		branch := strings.TrimSpace(string(out))

		if branch == mainBranchName {
			logrus.Info("On master branch, using that for default branch.")
			return branch, nil
		}

		if s := releaseBranchRegexp.FindString(branch); s != "" {
			// Explicitly on a release branch, so use that.
			logrus.Infof("On release branch %s, using that for default branch.", s)
			return s, nil
		}
		logrus.Infof("Branch %q is not master or a release branch.", branch)
	}

	// If we're not on a release branch, this is likely to be a PR build,
	// and the semaphore.yml should have inherited the default from whichever
	// branch it was based on.  Check there.
	logrus.Infof("Checking semaphore.yml for default branch.")
	detected, err := detectExistingDefaultBranch(filepath.Join(semaphoreDir, "semaphore.yml"))
	if err != nil {
		return "", fmt.Errorf("detect release branch from semaphore yaml: %w", err)
	}
	if detected != "" {
		logrus.Infof("Found default branch %s in semaphore.yml, using it for default branch.", detected)
		return detected, nil
	}

	logrus.Info("Found no default branch in semaphore.yml, assuming master.")
	return mainBranchName, nil
}

// convertToFoldedScalars post-processes generated YAML content to convert
// long when: "change_in(...)" lines into YAML folded block scalars (>-),
// with each dependency path on its own line. This makes diffs cleaner and
// reduces merge conflicts. The >- scalar folds newlines into spaces when
// parsed, so the resulting value is semantically identical.
func convertToFoldedScalars(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")
		if converted, ok := tryConvertWhenToFolded(trimmed); ok {
			result = append(result, converted...)
		} else {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

func tryConvertWhenToFolded(line string) ([]string, bool) {
	idx := strings.Index(line, `when: "`)
	if idx < 0 || !strings.Contains(line, "change_in(") || !strings.HasSuffix(line, `)"`) {
		return nil, false
	}

	indent := line[:idx]
	expr := line[idx+len(`when: "`) : len(line)-1]
	contentIndent := indent + "  "

	// Put each list item on its own line.
	multiline := strings.ReplaceAll(expr, "','", "',\n"+contentIndent+"'")
	// Put the options dict on its own line.
	multiline = strings.ReplaceAll(multiline, "], {", "],\n"+contentIndent+"{")

	fullMultiline := contentIndent + multiline
	foldedLines := strings.Split(fullMultiline, "\n")
	result := []string{indent + "when: >-"}
	result = append(result, foldedLines...)
	return result, true
}

func detectExistingDefaultBranch(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	re := regexp.MustCompile(`default_branch: '([^']+)'`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		return "", nil
	}
	branches := set.New[string]()
	branch := ""
	for _, m := range matches {
		branch = m[1]
		branches.Add(branch)
	}
	if branches.Len() > 1 {
		return "", fmt.Errorf("detected more than one branch in the current semaphore.yml, bailing out: %v", branches.Slice())
	}

	return branch, nil
}
