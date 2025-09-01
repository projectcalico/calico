package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/logutils"
)

func main() {
	logutils.ConfigureEarlyLogging()
	// We use stdout for the parseable output of the tool so we _do_ want
	// logging to go to stderr.
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.InfoLevel)

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

var defaultExclusions = []string{
	"/**/.gitignore",
	"/**/README.md",
	"/**/LICENSE",
}

func printSemChangeIn(pkg string) {
	localDirs, err := loadLocalDirs(pkg)
	if err != nil {
		logrus.Fatalln("Failed to load local dirs:", err)
		os.Exit(1)
	}

	var inclusions []string
	inclusions = append(inclusions, pkg)
	inclusions = append(inclusions, defaultInclusions...)
	for _, dir := range localDirs {
		if strings.HasPrefix(dir+"/", pkg) {
			continue // already included
		}
		inclusions = append(inclusions, dir+"/*.go")
	}

	exclusions := calculateTestExclusionGlobs(pkg, localDirs)
	exclusions = append(exclusions, defaultExclusions...)

	_, _ = fmt.Printf("change_in(%s, {exclude: %s})\n", formatSemList(inclusions), formatSemList(exclusions))
}

func formatSemList(exclusions []string) string {
	var quoted []string
	for _, s := range exclusions {
		quoted = append(quoted, fmt.Sprintf("'%s'", s))
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func printUsageAndExit() {
	logrus.Fatalln("Usage: deps modules modules|local-dirs <package>")
	os.Exit(1)
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
	logrus.Infof("Found %d test exclusions.", len(exclusions))
	return exclusions
}

func loadLocalDirs(pkg string) (out []string, err error) {
	packageDeps, err := loadPackageDeps(pkg)
	if err != nil {
		logrus.Fatalln("Failed to load package deps:", err)
		os.Exit(1)
	}
	for _, pkg := range packageDeps {
		const ourPackage = "github.com/projectcalico/calico/"
		if strings.HasPrefix(pkg, ourPackage) {
			pkg = strings.TrimPrefix(pkg, ourPackage)
			out = append(out, pkg)
		}
	}
	return out, nil
}

func printModules(pkg string) {
	packageDeps, err := loadPackageDeps(pkg)
	if err != nil {
		logrus.Fatalln("Failed to load package deps:", err)
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
	for _, mod := range modules {
		for _, pkg := range packageDeps {
			if strings.HasPrefix(pkg, mod.Path) {
				if mod.Version != "" {
					_, _ = fmt.Println(mod.Path + " " + mod.Version)
				} else {
					_, _ = fmt.Println(mod.Path)
				}
				break
			}
		}
	}
	logrus.Info("Done.")
}

func loadPackageDeps(pkg string) ([]string, error) {
	raw, err := exec.Command("go", "list", "-deps", pkgToSearchQuery(pkg)).Output()
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

func pkgToSearchQuery(pkg string) string {
	if !strings.HasPrefix(pkg, "./") {
		pkg = "./" + pkg
	}
	if strings.HasSuffix(pkg, "/...") {
		return pkg
	}
	if strings.HasSuffix(pkg, "/") {
		return pkg + "..."
	}
	return pkg + "/..."
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
