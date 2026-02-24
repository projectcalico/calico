package aptrepo

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/sirupsen/logrus"
)

// Reprepro is a terrible name but it's what we have

// RepoConfig is the information we'll use to generate Reprepro's 'distributions' configuration file
type RepoConfig struct {
	// Architectures is the list of architectures we'll publish
	Architectures []string
	// Origin is a freeform text field that admins can use to filter on; probably should be 'Tigera'
	Origin string
	// Label is another freeform text field to filter on; probably should be 'Calico Enterprise'
	Label string
	// Components is the list of 'components' (releases) we intend to publish, e.g. noble, jammy, bookworm
	Components []string
	// ProductName is the full name of our product that will show in the description field of the repo; e.g.
	// "Calico Enterprise v3.21", or maybe "Calico Enterprise v3.21 hashrelease"
	ProductName string
	// GPGKeyID is the GPG key ID that we'll sign the repository with
	GPGKeyID string
}

// Repo defines the core information about a local (on-disk) repo that we want to create/manipulate
type Repo struct {
	// TempDir is where we're going to store our files while we do our generation
	TempDir string
	// BaseDirectory is the absolute path to the repo base (where our configs and db are stored)
	BaseDirectory string
	// OutputDirectory is the absolute path to the output directory, where our pool and dists will be stored)
	OutputDirectory string
	// RepoConfig is the RepoConfig object representing the information about the repo we'll be publishing
	Config RepoConfig
	// PublishingURL is the full URL to the root of the published repository, e.g. https://host.com/ubuntu
	PublishingURL string
}

//go:embed reprepro-conf.gotmpl
var repoDistributionsTemplate string

// NewRepo creates a new Repo instance with the appropriate fields populated
func NewRepo(tempDir, outputDir string, repoConfig RepoConfig, url string) (*Repo, error) {
	repo := Repo{
		TempDir:         tempDir,
		BaseDirectory:   filepath.Join(tempDir, "_apt_repo_conf"),
		OutputDirectory: outputDir,
		Config:          repoConfig,
		PublishingURL:   url,
	}
	return &repo, nil
}

// RepositoryDBExists checks to see if the configured repository path already has
// a repo database; we need this to update existing remote repositories.
func (repo *Repo) RepositoryDBExists() (bool, error) {
	dbPath := filepath.Join(repo.BaseDirectory, "db")
	exist, err := utils.DirExists(dbPath)
	if err != nil || !exist {
		return exist, err
	}
	entries, err := os.ReadDir(dbPath)
	if err != nil || len(entries) == 0 {
		return false, err
	}
	return true, nil
}

// exec 'wrapper' commands that we can use for later

// exec runs a reprepro command but discards the output
func (repo *Repo) exec(args ...string) error {
	_, err := repo.execWithOutput(args...)
	return err
}

// execWithOutput executes a reprepro command using the existing configuration and returns the output
func (repo *Repo) execWithOutput(args ...string) (string, error) {
	cmdArgs := []string{
		"--basedir",
		repo.BaseDirectory,
		"--outdir",
		repo.OutputDirectory,
		"--ignore=extension",
	}
	cmdArgs = append(cmdArgs, args...)
	logrus.Debugf("running reprepro command %s", strings.Join(cmdArgs, " "))
	out, err := command.Run("reprepro", cmdArgs)
	if err != nil {
		logrus.Error(out)
		return "", fmt.Errorf("running 'reprepro %s': %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// Functions that handle configuration, setup, etc.

// configDirPath returns the path to the configuration directory; does not guarantee it exists
func (repo *Repo) configDirPath() string {
	return filepath.Join(repo.BaseDirectory, "conf")
}

// configFilePath returns the path to the configuration file; does not guarantee it exists
func (repo *Repo) configFilePath() string {
	return filepath.Join(repo.configDirPath(), "distributions")
}

// CleanBaseDir removes the repo's configured base directory
func (repo *Repo) cleanBaseDir() error {
	logrus.Debugf("removing repo base directory %s", repo.BaseDirectory)
	if err := os.RemoveAll(repo.BaseDirectory); err != nil {
		return fmt.Errorf("could not clean repo base directory %s: %w", repo.BaseDirectory, err)
	}
	return nil
}

// CleanOutputDir removes the repo's configured output directory
func (repo *Repo) cleanOutputDir() error {
	logrus.Debugf("removing repo output directory %s", repo.OutputDirectory)
	if err := os.RemoveAll(repo.OutputDirectory); err != nil {
		return fmt.Errorf("could not clean repo output directory %s: %w", repo.OutputDirectory, err)
	}
	return nil
}

// Clean removes the configured base and output directories. Must be run before creating
// the repository configuration with Repo.WriteRepoConfig()
func (repo *Repo) clean() error {
	return errors.Join(
		repo.cleanBaseDir(),
		repo.cleanOutputDir(),
	)
}

// PrepareForBuild sets up the configured paths to be ready to build an
// apt repo. If we're building a repository from packages, this should
// be run before we start touching the filesystem.
func (repo *Repo) PrepareForBuild() error {
	// We need to run clean() to ensure that we don't have leftover files
	// from a previous build, leftover repo configuration or database, etc.
	return repo.clean()
}

// WriteRepoConfig generates and writes the config file for the repo software to the appropriate path
func (repo *Repo) WriteRepoConfig() error {
	if err := os.MkdirAll(repo.configDirPath(), utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	repoConfigFile, err := os.OpenFile(repo.configFilePath(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer func() { repoConfigFile.Close() }()

	funcMap := template.FuncMap{
		"join": strings.Join,
	}
	tmpl, err := template.New("repo/config/distributions").Funcs(funcMap).Parse(repoDistributionsTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse repo's distributions template: %w", err)
	}

	if err := tmpl.Execute(repoConfigFile, repo.Config); err != nil {
		return fmt.Errorf("failed to write repo distributions file: %w", err)
	}

	return nil
}

// Functions that expose reprepro's functionality (e.g. adding debian packages)

// IncludeDeb adds a specified debian file to the specified component in the repo
func (repo *Repo) IncludeDeb(component, debFile string) error {
	if !slices.Contains(repo.Config.Components, component) {
		return fmt.Errorf("specified component %s not present in configured components list %s", component, strings.Join(repo.Config.Components, ", "))
	}

	err := repo.exec("includedeb", component, debFile)
	if err != nil {
		return fmt.Errorf("Could not add file %s to component %s: %w", debFile, component, err)
	}
	return nil
}

// RecursiveAddDebsFromDirectories takes a list of paths to search and finds all debian packages
// under those paths, gets their suite/component name, and adds them to the repo
func (repo *Repo) RecursiveAddDebsFromDirectories(searchPaths []string) error {
	debsBySuite, err := getRecursiveDebsBySuite(searchPaths)
	if err != nil {
		return fmt.Errorf("could not scan for debian packages: %w", err)
	}

	var publishingErrors []error

	for suite, filesList := range debsBySuite {
		for _, filename := range filesList {
			if err := repo.IncludeDeb(suite, filename); err != nil {
				publishingErrors = append(publishingErrors, err)
			}

		}
	}
	if err := errors.Join(publishingErrors...); err != nil {
		return fmt.Errorf("Encountered errors publishing Apt repository: %w", err)
	}
	return nil
}

// WriteSourcesFile writes out the <codename>.sources file for a given codename to the repo's output directory
func (repo *Repo) WriteSourcesFile(codename string) error {
	if !slices.Contains(repo.Config.Components, codename) {
		return fmt.Errorf("specified codename %s does not exist in defined codenames (%s)", codename, strings.Join(repo.Config.Components, ", "))
	}
	gpgPubKey, err := utils.GetGPGPubKey(repo.Config.GPGKeyID)
	if err != nil {
		return fmt.Errorf("could not fetch GPG key %s: %w", repo.Config.GPGKeyID, err)
	}
	gpgPubKeyFormatted := formatGPGKeyForSourcesFile(gpgPubKey)

	sourcesFields := aptSourcesData{
		RepoName:      repo.Config.ProductName,
		RepoURL:       repo.PublishingURL,
		Suite:         codename,
		GpgKey:        gpgPubKeyFormatted,
		Architectures: repo.Config.Architectures,
	}

	if err := sourcesFields.writeAptSourcesFile(repo.OutputDirectory); err != nil {
		return fmt.Errorf("Unable to write sources file for %s: %w", codename, err)
	}
	return nil
}

// WriteAllSourcesFiles creates a <codename>.sources in the repo's output directory for
// each configured codename/suite.
func (repo *Repo) WriteAllSourcesFiles() error {
	var errs []error
	for _, codename := range repo.Config.Components {
		errs = append(errs, repo.WriteSourcesFile(codename))
	}
	return errors.Join(errs...)
}
