// Package aptrepo contains functionality for creating and managing apt repositories
package aptrepo

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
)

// A brief note on Ubuntu/Debian/apt repo terminology:
//
// For Ubuntu and Debian, releases are numbered and codenamed; Ubuntu releases follow
// a fixed schedule and are numbered by release year and month, e.g. 24.04 was released
// in April 2024. Debian releases do not follow a fixed schedule and are numbered
// sequentially, e.g. 12.10, 12.11, etc.
//
// The 'codename' is the one-word name of the release, such as 'noble', 'trixie',
// etc. If you run `lsb_release -a` it will give you these names in the 'Codename'
// field.
//
// Here is some terminology and how it's used for these distros and how that relates to
// use in apt repositories.
//
// Suite
//   In Debian, the 'suite' refers to a category of release 'oldstable', 'stable', 'testing',
//   etc., and allows users to float their version to the current 'stable' or 'testing' release
//   for example; when a release is promoted to 'stable' then 'stable' refers to that new
//   release (whichever it is) and users will now start to get packages from that new release;
//   'oldstable' now refers to the former 'stable'.
//
//   In apt, however, this distinction is not made, and the 'suite' field can contain the codename
//   of the Debian or Ubuntu release, such as 'noble', 'bookworm', etc., or the Debian 'suite'
//   such as 'stable' or 'testing'.
//
//   Some third party repositories will create a separate suite for their own releases; for example,
//   LLVM has suites for 'llvm-toolchain-noble-18', 'llvm-toolchain-noble-19', etc. We may consider
//   doing something similar, e.g. 'calico-enterprise-v3.23-noble'.
//
// Component
//   Which 'part' of the release it is. Most common in Ubuntu are 'main', 'restricted',
//   'universe', and 'multiverse'; for Debian the equivalents are 'main', 'non-free-firmware',
//   'contrib', and 'non-free'.
//
//   While these terms have specific meaning for these releases, we can just use 'main'
//   for everything.
//
// Hopefully this explains why 'suite' and 'codename' are used mostly interchangeably in
// this code depending on what they're actually being used for!

type aptSourcesData struct {
	// RepoName is the name of the repository as might be shown by repolib (e.g. in a UI)
	RepoName string
	// RepoURL is the base URL of the repository (i.e. where pool/ and dists/ are)
	RepoURL string
	// Suite is the 'suite' field, e.g. noble, bookworm, etc.
	Suite string
	// GpgKey is the ascii-armored GPG public key
	GpgKey string
	// Architectures is the list of architectures this sources file will claim support for
	Architectures []string
}

//go:embed repo.sources.gotmpl
var aptSourcesTemplate string

// writeAptSourcesFile creates a deb822-style sources file for a given set
// of parameters, and writes it to <suite>.sources under <rootPath>
// For more info on the format: https://repolib.readthedocs.io/en/latest/deb822-format.html
func (asd *aptSourcesData) writeAptSourcesFile(rootPath string) error {
	logrus.WithField("suite", asd.Suite).Info("Generating apt .sources file")
	sourcesFilePath := filepath.Join(rootPath, fmt.Sprintf("%s.sources", asd.Suite))
	sourcesFile, err := os.OpenFile(sourcesFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", sourcesFilePath, err)
	}
	defer func() { _ = sourcesFile.Close() }()

	funcMap := template.FuncMap{
		"join": strings.Join,
	}

	tmpl, err := template.New("apt.sources").Funcs(funcMap).Parse(aptSourcesTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse apt sources template: %w", err)
	}

	if err := tmpl.Execute(sourcesFile, asd); err != nil {
		logrus.WithField("suite", asd.Suite).WithError(err).Error("failed to write apt sources file")
		return fmt.Errorf("failed to write apt sources file: %w", err)
	}

	logrus.WithField("file", sourcesFilePath).Info("Wrote apt .sources file")

	return nil
}

func getVersionFromDebfile(debfilePath string) (string, error) {
	logrus.WithField("debfile", debfilePath).Debug("Getting version information from debian package")
	cmd := exec.Command("dpkg-deb", "--show", "--showformat", "${Version}", debfilePath)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getting version for %s: %w", debfilePath, err)
	}
	return string(out), nil
}

func getComponentNameFromVersion(version string) (string, error) {
	if lastIdx := strings.LastIndex(version, "~"); lastIdx != -1 {
		return version[lastIdx+1:], nil
	}
	return "", fmt.Errorf("version %s does not contain a tilde separator", version)
}

func getSuiteNameFromDebFile(debfilePath string) (string, error) {
	version, err := getVersionFromDebfile(debfilePath)
	if err != nil {
		return "", fmt.Errorf("getting version for %s: %w", debfilePath, err)
	}

	suite, err := getComponentNameFromVersion(version)
	if err != nil {
		return "", fmt.Errorf("getting component name for %s: %w", debfilePath, err)
	}

	return suite, nil
}

// formatGPGKeyForSourcesFile formats a GPG public key into a format suitable to
// be appended into a sources file template (indented one space, blank
// lines replaced with '.')
func formatGPGKeyForSourcesFile(gpgKey string) string {
	// To make it easier to insert the GPG key into the sources file, we want to
	// 1. Replace every blank line (there should only be one) with a '.'
	// 2. Indent each line with a single space
	var processedKey bytes.Buffer
	lines := strings.Split(gpgKey, "\n")
	// The split might result in a trailing empty string if the output ends in newline, which is typical.
	// We should be careful not to add extra newlines if not present, but `gpg` output usually has a trailing newline.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	for _, line := range lines {
		if line == "" {
			line = "."
		}
		processedKey.WriteString(" " + line + "\n")
	}

	return processedKey.String()
}

func getRecursiveDebsBySuite(searchPaths []string) (map[string][]string, error) {
	debsBySuite := make(map[string][]string, 0)

	files, err := getRecursiveDebs(searchPaths)
	if err != nil {
		return map[string][]string{}, err
	}

	logrus.Debugf("Found %d debian package files to process", len(files))
	for _, debFile := range files {
		suite, err := getSuiteNameFromDebFile(debFile)
		if err != nil {
			return map[string][]string{}, fmt.Errorf("getting suite name for %s: %w", debFile, err)
		}
		debsBySuite[suite] = append(debsBySuite[suite], debFile)
	}

	return debsBySuite, nil
}

func getRecursiveDebs(searchPaths []string) ([]string, error) {
	// Find .deb and .ddeb files
	var files []string
	for _, searchPath := range searchPaths {
		logrus.Infof("Scanning for debian packages in %s", searchPath)
		err := filepath.WalkDir(searchPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Avoid walking into .git or .aptly to save time/confusion,
				// though bash script doesn't explicitly exclude them (it relies on glob).
				if d.Name() == ".git" || d.Name() == "pool" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".deb") || strings.HasSuffix(path, ".ddeb") {
				logrus.Debug(fmt.Sprintf("Found debian package %s", path))
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return []string{}, fmt.Errorf("walking directory: %w", err)
		}
	}
	return files, nil
}
