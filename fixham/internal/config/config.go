package config

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

type Config struct {
	// Organization is the name of the organization
	Organization string `envconfig:"ORGANIZATION" default:"projectcalico"`

	// RepoRootDir is the root directory for the repository
	// it is used for git operations
	RepoRootDir string `envconfig:"REPO_ROOT"`

	// DevTagSuffix is the suffix for the development tag
	DevTagSuffix string `envconfig:"DEV_TAG_SUFFIX" default:"-0.dev"`

	// RepoReleaseBranchPrefix is the suffix for the release tag
	RepoReleaseBranchPrefix string `envconfig:"RELEASE_BRANCH_PREFIX" default:"release-"`

	// OperatorRepo is the repository for the operator
	OperatorBranchName string `envconfig:"OPERATOR_BRANCH" default:"master"`

	// ValidArchs are the OS architectures supported for multi-arch build
	ValidArchs []string `envconfig:"VALID_ARCHES" default:"amd64,arm64,ppc64le,s390x"`

	DocsHost string `envconfig:"DOCS_HOST"`
	DocsPort string `envconfig:"DOCS_PORT"`
	DocsUser string `envconfig:"DOCS_USER"`
	DocsKey  string `envconfig:"DOCS_KEY"`

	// GithubToken is the token for the GitHub API
	GithubToken string `envconfig:"GITHUB_TOKEN"`
}

// LoadConfig loads the configuration from the environment
func LoadConfig() *Config {
	config := &Config{}
	envconfig.MustProcess("", config)
	if config.RepoRootDir == "" {
		config.RepoRootDir = repoRootDir()
	}
	return config
}

func repoRootDir() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		logrus.WithError(err).Fatal("failed to get repo root dir")
	}
	return strings.TrimSpace(out.String())
}
