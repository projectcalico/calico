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

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func printUsageAndExit() {
	_, _ = fmt.Fprint(os.Stderr, `CI Dependency helper tool.

Usage:

  deps [options] modules <package>          # Print go modules that package depends on
  deps [options] local-dirs <package>       # Print in-repo go package dirs that
                                  # package depends on.
  deps local-dirs-main-only <package> # Print in-repo go package dirs that
                                  # package depends on. (Main packages only.)
  deps [options] local-dirs-main-only <package> # Print in-repo go package dirs that
                                  # package depends on. (Main packages only.)
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
	incl := formatSemList(inclusions)
	excl := formatSemList(exclusions)
	if pretty {
		incl = "\n" + strings.ReplaceAll(incl, ",", ",\n  ") + "\n"
		excl = "\n" + strings.ReplaceAll(excl, ",", ",\n  ") + "\n"
	}
	out := fmt.Sprintf("change_in(%s, {pipeline_file: 'ignore', exclude: %s%s})", incl, excl, defaultBranchStanza)
	return out
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
	for _, dir := range localDirs {
		if strings.HasPrefix(dir+"/", "/"+primaryPkg) {
			continue // covered by the whole-package inclusion.
		}
		inclusions.Add(dir + "/*.go")
	}

	exclusions := set.From(calculateTestExclusionGlobs(primaryPkg, localDirs)...)
	exclusions.AddAll(defaultExclusions)

	// Some jobs depend on secondary packages.  For example, the node tests
	// also run typha, api server, etc.  Add inclusions for those.
	for _, otherPkg := range otherPkgs {
		const nonGoPrefix = "non-go:"
		if after, ok := strings.CutPrefix(otherPkg, nonGoPrefix); ok {
			inclusions.Add(after)
			continue
		}

		// For secondary dependencies, we only list dependencies of "main"
		// packages.  This prevents us from picking up test-only dependencies.
		// For example, kube-controllers FV has utility packages that depend on
		// felix's FV infra packages.  If we didn't filter down to "main", we'd
		// pick those up unintentionally.
		otherPkgDirs, err := loadLocalDirs(otherPkg, true)
		if err != nil {
			return nil, fmt.Errorf("failed to load local dirs for secondary package %s: %w", otherPkg, err)
		}
		for _, dir := range otherPkgDirs {
			inclusions.Add(dir + "/*.go")
		}
		inclusions.Add(otherPkg + "/Makefile")
		inclusions.Add(otherPkg + "/deps.txt")
		inclusions.Add(otherPkg + "/**/*Dockerfile*")
		inclusions.AddAll(nonGoDeps[otherPkg])
		exclusions.AddAll(calculateTestExclusionGlobs(primaryPkg, otherPkgDirs))
	}

	return &Deps{inclusions, exclusions}, nil
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

	// Build the main file, which is triggered by PRs and uses the calculated
	// dependencies.
	mainFile := filepath.Join(semaphoreDir, "semaphore.yml")
	err = buildSemaphoreYAML(mainFile, templates, globalExtraDeps, deps, false, defaultBranchStanza)
	if err != nil {
		logrus.Fatalf("Failed to build semaphore YAML: %v", err)
	}

	// Build the scheduled file, which builds all our code, but not slow
	// third-party builds.
	scheduledFile := filepath.Join(semaphoreDir, "semaphore-scheduled-builds.yml")
	err = buildSemaphoreYAML(scheduledFile, templates, globalExtraDeps, nil, false, defaultBranchStanza)
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
		err = buildSemaphoreYAML(thirdPartyFile, weeklyTemplates, globalExtraDeps, nil, true, defaultBranchStanza)
		if err != nil {
			logrus.Fatalf("Failed to build semaphore YAML: %v", err)
		}
	}

	logrus.Info("Semaphore YAML generation complete")
}

func buildSemaphoreYAML(file string, templates []templateData, globalExtraDeps []string, deps map[string]*Deps, weekly bool, defaultBranchStanza string) error {
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
		changeInPattern := regexp.MustCompile(`\$\{CHANGE_IN\(([^)]+)\)}`)
		content := changeInPattern.ReplaceAllStringFunc(t.content, func(match string) string {
			pkg := changeInPattern.FindStringSubmatch(match)[1]
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
		content = strings.ReplaceAll(content, "${FORCE_RUN}", forceRun)
		content = strings.ReplaceAll(content, "${WEEKLY_RUN}", weeklyRun)
		content = strings.ReplaceAll(content, "${DEFAULT_BRANCH}", defaultBranchStanza)
		_, _ = data.WriteString(content)
	}

	return os.WriteFile(file, data.Bytes(), 0644)
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
	pattern := regexp.MustCompile(`\$\{CHANGE_IN\(([^)]+)\)}`)
	out := set.New[string]()
	for _, t := range templates {
		matches := pattern.FindAllStringSubmatch(t.content, -1)
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

	if branch := os.Getenv("SEMAPHORE_GIT_BRANCH"); branch != "" {
		// In CI, this env var is set either to the current branch, if we're
		// building on a branch, or to the target branch if we're building
		// a PR.
		logrus.Infof("Using SEMAPHORE_GIT_BRANCH for default branch: %s", branch)
		return branch, nil
	}

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

	// Check for release branch.
	releaseBranchPrefix := os.Getenv("RELEASE_BRANCH_PREFIX")
	if releaseBranchPrefix == "" {
		return "", fmt.Errorf("RELEASE_BRANCH_PREFIX not set")
	}
	releaseBranchRegexp := regexp.MustCompile(`^` + regexp.QuoteMeta(releaseBranchPrefix) + `-v[\d.-]+$`)
	if s := releaseBranchRegexp.FindString(branch); s != "" {
		// Explicitly on a release branch, so use that.
		logrus.Infof("On release branch %s, using that for default branch.", s)
		return s, nil
	}

	// If we're not on a release branch, this is likely to be a PR build,
	// and the semaphore.yml should have inherited the default from whichever
	// branch it was based on.  Check there.
	logrus.Infof("Branch %q is not a release branch, checking semaphore.yml for default branch.", branch)
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
