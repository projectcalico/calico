package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func printUsageAndExit() {
	_, _ = fmt.Fprint(os.Stderr, `CI Dependency helper tool.

Usage: 

  deps modules <package>          # Print go modules that package depends on
  deps local-dirs <package>       # Print in-repo go package dirs that 
                                  # package depends on.
  deps test-exclusions <package>  # Print glob patterns to match *_test.go 
                                  # files in dependency dirs outside the 
                                  # package itself.
  deps sem-change-in <package>[,<secondary package>...] # Print a SemaphoreCI
                                  # conditions DSL change_in() clause for 
                                  # <package>, including non-test deps from
                                  # any <secondary package> clauses.

The test-exclusions and sem-change-in sub-commands are intended to be used with
packages at the top-level of the repo.  Test exclusions are based on whether
a dependency is within the package.

The change_in() clause always depends on the whole package directory itself. 
Some non-Go dependencies are hard-coded in the tool.  For example, it knows
that node depends on felix/bpf-*.
`)
	os.Exit(1)
}

func main() {
	// We use stdout for the parseable output of the tool so we _do_ want
	// logging to go to stderr.
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.WarnLevel)
	logutils.ConfigureFormatter("deps")

	if len(os.Args) != 3 {
		printUsageAndExit()
	}

	cmd := os.Args[1]
	pkg := os.Args[2]

	switch cmd {
	case "modules":
		printModules(pkg)
	case "local-dirs":
		printLocalDirs(pkg)
	case "test-exclusions":
		printTestExclusions(pkg)
	case "sem-change-in":
		printSemChangeIn(pkg)
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

func printSemChangeIn(pkg string) {
	parts := strings.Split(pkg, ",")
	pkg = parts[0]
	otherPkgs := parts[1:]
	if len(otherPkgs) == 0 {
		logrus.Infof("Calculating deps for %s package", pkg)
	} else {
		logrus.Infof("Calculating deps for %s package; including secondary deps: %v", pkg, otherPkgs)
	}

	localDirs, err := loadLocalDirs(pkg)
	if err != nil {
		logrus.Fatalln("Failed to load local dirs:", err)
		os.Exit(1)
	}

	inclusions := set.New[string]()
	inclusions.Add(pkg)
	inclusions.AddAll(defaultInclusions)
	inclusions.AddAll(nonGoDeps[pkg])
	for _, dir := range localDirs {
		if strings.HasPrefix(dir+"/", pkg) {
			continue // covered by the whole-package inclusion.
		}
		inclusions.Add(dir + "/*.go")
	}

	exclusions := set.From(calculateTestExclusionGlobs(pkg, localDirs)...)
	exclusions.AddAll(defaultExclusions)

	// Some jobs depend on secondary packages.  For example, the node tests
	// also run typha, api server, etc.  Add inclusions for those.
	for _, otherPkg := range otherPkgs {
		otherPkgDirs, err := loadLocalDirs(otherPkg)
		if err != nil {
			logrus.Fatalln("Failed to load local dirs:", err)
			os.Exit(1)
		}
		for _, dir := range otherPkgDirs {
			inclusions.Add(dir + "/*.go")
		}
		inclusions.Add(otherPkg + "/Makefile")
		inclusions.Add(otherPkg + "/deps.txt")
		inclusions.AddAll(nonGoDeps[otherPkg])
		exclusions.AddAll(calculateTestExclusionGlobs(pkg, otherPkgDirs))
	}

	_, _ = fmt.Printf("change_in(%s, {pipeline_file: 'ignore', exclude: %s})\n", formatSemList(inclusions), formatSemList(exclusions))
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

func printLocalDirs(pkg string) {
	localDirs, err := loadLocalDirs(pkg)
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
	localDirs, err := loadLocalDirs(pkg)
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
	prefix := pkg + "/"
	var exclusions []string
	for _, dir := range localDirs {
		if strings.HasPrefix(dir+"/", prefix) {
			continue
		}
		exclusions = append(exclusions, dir+"/*_test.go")
	}
	return exclusions
}

func loadLocalDirs(pkg string) (out []string, err error) {
	packageDeps, err := loadPackageDeps(pkg)
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
	packageDeps, err := loadPackageDeps(pkg)
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

func loadPackageDeps(pkg string) ([]string, error) {
	command := exec.Command("go", "list", "-deps", "./...")
	command.Dir = pkg
	raw, err := command.Output()
	if err != nil {
		return nil, err
	}
	var out []string
	for line := range bytes.Lines(raw) {
		dep := string(bytes.TrimSpace(line))
		if strings.HasPrefix(dep, "github.com/projectcalico/api/") {
			// HACK, handle the API go mod replace.
			dep = strings.Replace(dep, "github.com/projectcalico/api/", "github.com/projectcalico/calico/api/", 1)
		}
		out = append(out, dep)
		logrus.Debugf("Loaded package: %s", line)
	}
	return out, nil
}

type module struct {
	Path    string
	Version string
}

func loadGoMods() ([]module, error) {
	return loadGoToolJSON[module]("list", "-m", "-json", "all")
}

func loadGoToolJSON[Item any](args ...string) ([]Item, error) {
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		return nil, err
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
