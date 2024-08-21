package config

import (
	"path/filepath"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
)

type Config struct {
	// Organization is the name of the organization
	Organization string `envconfig:"ORGANIZATION" default:"projectcalico"`

	// RepoRootDir is the root directory for this repository
	RepoRootDir string `envconfig:"REPO_ROOT"`

	IsHashrelease bool `envconfig:"IS_HASHRELEASE" default:"true"`

	// DevTagSuffix is the suffix for the development tag
	DevTagSuffix string `envconfig:"DEV_TAG_SUFFIX" default:"0.dev"`

	// RepoReleaseBranchPrefix is the suffix for the release tag
	RepoReleaseBranchPrefix string `envconfig:"RELEASE_BRANCH_PREFIX" default:"release"`

	// OperatorRepo is the repository for the operator
	OperatorBranchName string `envconfig:"OPERATOR_BRANCH" default:"master"`

	// ValidArchs are the OS architectures supported for multi-arch build
	ValidArchs []string `envconfig:"VALID_ARCHES" default:"amd64,arm64,ppc64le,s390x"`

	// Registry is the registry to publish images.
	// This is only required if not on a release branch.
	Registry string `envconfig:"REGISTRY"`

	// DocsHost is the host for the hashrelease docs
	DocsHost string `envconfig:"DOCS_HOST"`

	// DocsPort is the port for the hashrelease docs
	DocsPort string `envconfig:"DOCS_PORT"`

	// DocsPath is the path for the hashrelease docs
	DocsUser string `envconfig:"DOCS_USER"`

	// DocsPath is the path for the hashrelease docs
	DocsKey string `envconfig:"DOCS_KEY"`

	// GithubToken is the token for the GitHub API
	GithubToken string `envconfig:"GITHUB_TOKEN"`

	// OutputDir is the directory for the output
	OutputDir string `envconfig:"OUTPUT_DIR"`

	// SlackConfig is the configuration for Slack integration
	SlackConfig slack.Config

	// ImageScannerConfig is the configuration for Image Scanning Service integration
	ImageScannerConfig imagescanner.Config
}

// ReleaseType returns the type of release.
// If IsHashrelease is true, it returns "hashrelease" (internal release).
// Otherwise, it returns "release" (public release).
func (c *Config) ReleaseType() string {
	relType := "release"
	if c.IsHashrelease {
		relType = "hash" + relType
	}
	return cases.Title(language.English).String(relType)
}

// HashreleaseDir returns the directory for the hashrelease
func (c *Config) HashreleaseDir() string {
	return filepath.Join(c.OutputDir, "hashrelease")
}

// TmpFolderPath returns the temporary folder path.
// This is used for temporary files during the release process
func (c *Config) TmpFolderPath() string {
	return filepath.Join(c.RepoRootDir, utils.ReleaseFolderName, "tmp")
}

// repoRootDir returns the root directory of this repository
func repoRootDir() string {
	dir, err := command.GitDir("")
	if err != nil {
		logrus.WithError(err).Fatal("failed to get repo root dir")
	}
	return dir
}

// LoadConfig loads the configuration from the environment
func LoadConfig() *Config {
	config := &Config{}
	envconfig.MustProcess("", config)
	if config.RepoRootDir == "" {
		config.RepoRootDir = repoRootDir()
	}
	if config.OutputDir == "" {
		config.OutputDir = filepath.Join(config.RepoRootDir, utils.ReleaseFolderName, "output")
	}
	return config
}
