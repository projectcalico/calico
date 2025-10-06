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
	},

	// Whisker is not a go project so we list the whole thing.
	"whisker": {
		"/whisker",
	},

	// Process is not a go project so we list the whole thing.
	"process": {
		"/process",
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

func replaceSemChangeInPlaceholders(yamlFile string) {
	fileContents, err := os.ReadFile(yamlFile)
	if err != nil {
		logrus.Fatalf("Failed to read file %s: %s", yamlFile, err)
	}
	fileStat, err := os.Stat(yamlFile)
	if err != nil {
		logrus.Fatalf("Failed to stat file %s: %s", yamlFile, err)
	}

	changeInPattern := regexp.MustCompile(`\$\{CHANGE_IN\(([^)]+)\)}`)
	replacements := map[string][]byte{}
	for _, groups := range changeInPattern.FindAllSubmatch(fileContents, -1) {
		pkg := string(groups[1])
		if _, ok := replacements[pkg]; ok {
			continue // already calculated.
		}
		replacements[pkg] = nil
	}

	var lock sync.Mutex
	var eg errgroup.Group
	eg.SetLimit(runtime.NumCPU())
	for pkg := range replacements {
		eg.Go(func() error {
			repl, err := calculateChangeIn(pkg, false)
			if err != nil {
				return fmt.Errorf("failed to calculate change_in for package %s: %w", pkg, err)
			}
			lock.Lock()
			replacements[pkg] = []byte(repl)
			lock.Unlock()
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		logrus.Fatalln("Failed to calculate change_in replacements:", err)
	}

	newContents := changeInPattern.ReplaceAllFunc(fileContents, func(match []byte) []byte {
		pkg := changeInPattern.FindSubmatch(match)[1]
		return replacements[string(pkg)]
	})

	if err := os.WriteFile(yamlFile, newContents, fileStat.Mode()); err != nil {
		logrus.Fatalf("Failed to write file %s: %s", yamlFile, err)
	}
}

func printSemChangeIn(pkg string, pretty bool) {
	_, _ = fmt.Println(calculateChangeIn(pkg, pretty))
}

func calculateChangeIn(pkg string, pretty bool) (string, error) {
	parts := strings.Split(pkg, ",")
	pkg = parts[0]
	otherPkgs := parts[1:]
	if len(otherPkgs) == 0 {
		logrus.Infof("Calculating deps for %s package", pkg)
	} else {
		logrus.Infof("Calculating deps for %s package; including secondary deps: %v", pkg, otherPkgs)
	}

	localDirs, err := loadLocalDirs(pkg, false)
	if err != nil {
		return "", fmt.Errorf("failed to load local dirs: %w", err)
	}

	inclusions := set.New[string]()
	inclusions.Add("/" + pkg + "/**")
	inclusions.AddAll(defaultInclusions)
	inclusions.AddAll(nonGoDeps[pkg])
	for _, dir := range localDirs {
		if strings.HasPrefix(dir+"/", "/"+pkg) {
			continue // covered by the whole-package inclusion.
		}
		inclusions.Add(dir + "/*.go")
	}

	exclusions := set.From(calculateTestExclusionGlobs(pkg, localDirs)...)
	exclusions.AddAll(defaultExclusions)

	// Some jobs depend on secondary packages.  For example, the node tests
	// also run typha, api server, etc.  Add inclusions for those.
	for _, otherPkg := range otherPkgs {
		// For secondary dependencies, we only list dependencies of "main"
		// packages.  This prevents us from picking up test-only dependencies.
		// For example, kube-controllers FV has utility packages that depend on
		// felix's FV infra packages.  If we didn't filter down to "main", we'd
		// pick those up unintentionally.
		otherPkgDirs, err := loadLocalDirs(otherPkg, true)
		if err != nil {
			return "", fmt.Errorf("failed to load local dirs for secondary package %s: %w", otherPkg, err)
		}
		for _, dir := range otherPkgDirs {
			inclusions.Add(dir + "/*.go")
		}
		inclusions.Add(otherPkg + "/Makefile")
		inclusions.Add(otherPkg + "/deps.txt")
		inclusions.Add(otherPkg + "/**/*Dockerfile*")
		inclusions.AddAll(nonGoDeps[otherPkg])
		exclusions.AddAll(calculateTestExclusionGlobs(pkg, otherPkgDirs))
	}

	incl := formatSemList(inclusions)
	excl := formatSemList(exclusions)
	if pretty {
		incl = "\n" + strings.ReplaceAll(incl, ",", ",\n  ") + "\n"
		excl = "\n" + strings.ReplaceAll(excl, ",", ",\n  ") + "\n"
	}
	out := fmt.Sprintf("change_in(%s, {pipeline_file: 'ignore', exclude: %s})", incl, excl)
	return out, nil
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

func generateSemaphoreYamls() {
	logrus.Info("Generating semaphore YAML pipeline files")
	semaphoreDir := ".semaphore"
	mainFile := filepath.Join(semaphoreDir, "semaphore.yml")
	scheduledFile := filepath.Join(semaphoreDir, "semaphore-scheduled-builds.yml")
	thirdPartyFile := filepath.Join(semaphoreDir, "semaphore-third-party-builds.yml")

	branchStanza := calculateBranchStanza(semaphoreDir)
	logrus.Infof("Using branch stanza: %q", branchStanza)

	// Validate change_in lines in template blocks include pipeline_file stanza.
	if err := validateChangeInClauses(semaphoreDir); err != nil {
		logrus.Fatalf("Template validation failed: %v", err)
	}

	// Build the main + scheduled files (initially with placeholders intact).
	blocksContent, err := loadAndIndentAllBlocks(filepath.Join(semaphoreDir, "semaphore.yml.d", "blocks"))
	if err != nil {
		logrus.Fatalf("Failed to load blocks: %v", err)
	}
	preamble := mustReadFile(filepath.Join(semaphoreDir, "semaphore.yml.d", "01-preamble.yml"))
	globalCfg := mustReadFile(filepath.Join(semaphoreDir, "semaphore.yml.d", "02-global_job_config.yml"))
	promotions := mustReadFile(filepath.Join(semaphoreDir, "semaphore.yml.d", "03-promotions.yml"))
	afterPipeline := mustReadFile(filepath.Join(semaphoreDir, "semaphore.yml.d", "99-after_pipeline.yml"))

	mainContent := buildYAMLWithBlocks(preamble, globalCfg, promotions, blocksContent, afterPipeline)
	writeWithDisclaimer(mainFile, mainContent)

	scheduledContent := buildYAMLWithBlocks(preamble, globalCfg, promotions, blocksContent, afterPipeline)
	writeWithDisclaimer(scheduledFile, scheduledContent)

	// Extract CHANGE_IN placeholders BEFORE replacing them in main file.
	deps := extractChangeInPlaceholders(mainContent)
	logrus.Infof("Found %d CHANGE_IN placeholders", len(deps))

	// Replace placeholders in scheduled file with true.
	scheduledContent = mustReadFile(scheduledFile)
	for dep := range deps {
		placeholder := fmt.Sprintf("${CHANGE_IN(%s)}", dep)
		scheduledContent = bytes.ReplaceAll(scheduledContent, []byte(placeholder), []byte("true"))
	}
	mustWriteFile(scheduledFile, scheduledContent)

	// Expand CHANGE_IN placeholders in main file using existing function.
	replaceSemChangeInPlaceholders(mainFile)
	mainContent = mustReadFile(mainFile)

	// Apply FORCE/WEEKLY substitutions.
	mainContent = bytes.ReplaceAll(mainContent, []byte("${FORCE_RUN}"), []byte("false"))
	mainContent = bytes.ReplaceAll(mainContent, []byte("${WEEKLY_RUN}"), []byte("false"))
	mustWriteFile(mainFile, mainContent)

	scheduledContent = mustReadFile(scheduledFile)
	scheduledContent = bytes.ReplaceAll(scheduledContent, []byte("${FORCE_RUN}"), []byte("true"))
	scheduledContent = bytes.ReplaceAll(scheduledContent, []byte("${WEEKLY_RUN}"), []byte("false"))
	mustWriteFile(scheduledFile, scheduledContent)

	// Third-party builds file.
	thirdPartyBlocks := []string{
		"10-prerequisites.yml",
		"30-deep-packet-inspection.yml",
		"30-elasticsearch.yml",
		"30-fluentd.yml",
	}
	thirdBlocksContent, err := loadAndIndentSelectedBlocks(filepath.Join(semaphoreDir, "semaphore.yml.d", "blocks"), thirdPartyBlocks)
	if err != nil {
		logrus.Fatalf("Failed to load third-party blocks: %v", err)
	}
	thirdContent := buildYAMLWithBlocks(preamble, globalCfg, nil, thirdBlocksContent, nil)
	writeWithDisclaimer(thirdPartyFile, thirdContent)

	thirdPartyRaw := mustReadFile(thirdPartyFile)
	thirdPartyRaw = bytes.ReplaceAll(thirdPartyRaw, []byte("${FORCE_RUN}"), []byte("true"))
	thirdPartyRaw = bytes.ReplaceAll(thirdPartyRaw, []byte("${WEEKLY_RUN}"), []byte("true"))
	// Replace any CHANGE_IN placeholders with true.
	changeInPattern := regexp.MustCompile(`\$\{CHANGE_IN\([^}]+\)}`)
	thirdPartyRaw = changeInPattern.ReplaceAll(thirdPartyRaw, []byte("true"))
	mustWriteFile(thirdPartyFile, thirdPartyRaw)

	// Apply branch stanza replacement to all 3 files.
	for _, f := range []string{mainFile, scheduledFile, thirdPartyFile} {
		c := mustReadFile(f)
		c = bytes.ReplaceAll(c, []byte("${DEFAULT_BRANCH}"), []byte(branchStanza))
		mustWriteFile(f, c)
	}

	logrus.Info("Semaphore YAML generation complete")
}

func writeWithDisclaimer(path string, body []byte) {
	disclaimer := []byte("# !! WARNING, DO NOT EDIT !! This file is generated from semaphore.yml.d.\n# To update, modify the template and then run 'make gen-semaphore-yaml'.\n")
	content := append(disclaimer, body...)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		logrus.Fatalf("Failed to write %s: %v", path, err)
	}
}

func buildYAMLWithBlocks(preamble, globalCfg, promotions, blocks, afterPipeline []byte) []byte {
	var buf bytes.Buffer
	buf.Write(preamble)
	if len(globalCfg) > 0 {
		buf.Write(globalCfg)
	}
	if len(promotions) > 0 {
		buf.Write(promotions)
	}
	buf.WriteString("blocks:\n")
	buf.Write(blocks)
	if len(afterPipeline) > 0 {
		buf.Write(afterPipeline)
	}
	return buf.Bytes()
}

func loadAndIndentAllBlocks(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var buf bytes.Buffer
	for _, n := range names {
		raw := mustReadFile(filepath.Join(dir, n))
		buf.Write(indentTwoSpaces(raw))
	}
	return buf.Bytes(), nil
}

func loadAndIndentSelectedBlocks(dir string, files []string) ([]byte, error) {
	var buf bytes.Buffer
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		buf.Write(indentTwoSpaces(raw))
	}
	return buf.Bytes(), nil
}

func indentTwoSpaces(in []byte) []byte {
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(in))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			out.WriteString("\n")
			continue
		}
		out.WriteString("  ")
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.Bytes()
}

func mustReadFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		logrus.Fatalf("Failed to read %s: %v", path, err)
	}
	return b
}

func extractChangeInPlaceholders(content []byte) map[string]struct{} {
	pattern := regexp.MustCompile(`\$\{CHANGE_IN\(([^)]+)\)}`)
	matches := pattern.FindAllSubmatch(content, -1)
	out := map[string]struct{}{}
	for _, m := range matches {
		out[string(m[1])] = struct{}{}
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
		return fmt.Errorf("All change_in clauses must include pipeline_file: 'ignore' (or 'track'). Offending lines:\n%s", strings.Join(offending, "\n"))
	}
	return nil
}

func calculateBranchStanza(semaphoreDir string) string {
	// Determine current branch.
	current := os.Getenv("DEFAULT_BRANCH_OVERRIDE")
	if current == "" {
		current = os.Getenv("SEMAPHORE_GIT_BRANCH")
	}
	if current == "" {
		// Fallback to git.
		out, err := exec.Command("git", "branch", "--show-current").Output()
		if err == nil {
			current = strings.TrimSpace(string(out))
		}
	}
	if current == "" {
		current = "master"
	} // final fallback

	if strings.HasPrefix(current, "release-calient-v") {
		return fmt.Sprintf(", default_branch: '%s'", current)
	}
	if current == "master" {
		return ""
	}

	// Try to detect from existing semaphore.yml
	detected, err := detectExistingDefaultBranch(filepath.Join(semaphoreDir, "semaphore.yml"))
	if err != nil {
		logrus.Warnf("Failed to detect existing default branch: %v", err)
	}
	if detected != "" {
		logrus.Warnf("Currently on a non-master, non-release branch. This branch appears to be a branch of %s; using that as default branch.", detected)
		return fmt.Sprintf(", default_branch: '%s'", detected)
	}
	logrus.Warn("Currently on a non-master, non-release branch. Appears to be a branch of master; not specifying default branch.")
	return ""
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
		return "", fmt.Errorf("Detected more than one branch in the current semaphore.yml, bailing out: %v", branches.Slice())
	}

	return branch, nil
}

func mustWriteFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		logrus.Fatalf("Failed to write %s: %v", path, err)
	}
}
