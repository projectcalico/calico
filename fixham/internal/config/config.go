package config

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

type Config struct {
	// Name is the name of the component/repository
	Name string `envconfig:"NAME"`

	// PackageName is the name of the package
	PackageName string `envconfig:"PACKAGE_NAME" default:"github.com/projectcalico/calico"`

	// Organization is the name of the organization
	Organization string `envconfig:"ORGANIZATION" default:"projectcalico"`

	// GoBuildImageName is the name of the go-build image
	// if wanting to override calico/go-build
	GoBuildImageName string `envconfig:"GO_BUILD_IMAGE" default:"calico/go-build"`

	// GoBuildVersion is the version of the go-build image
	GoBuildVersion string `envconfig:"GO_BUILD_VER" default:"v0.90"`

	// GitUseSSH is a flag to use SSH for git operations
	GitUseSSH bool `envconfig:"GIT_USE_SSH"`

	// RepoRootDir is the root directory for the repository
	// it is used for git operations
	RepoRootDir string `envconfig:"REPO_ROOT"`

	// RepoDefaultBranch is the default branch for repositories
	RepoDefaultBranch string `envconfig:"DEFAULT_BRANCH" default:"master"`

	// RepoBranchName is the branch name for the calico repository
	BranchName string `envconfig:"BRANCH_NAME"`

	// DevTagSuffix is the suffix for the development tag
	DevTagSuffix string `envconfig:"DEV_TAG_SUFFIX" default:"-0.dev"`

	// RepoReleaseBranchPrefix is the suffix for the release tag
	RepoReleaseBranchPrefix string `envconfig:"RELEASE_BRANCH_PREFIX" default:"release-"`

	// OperatorRepo is the repository for the operator
	OperatorBranchName string `envconfig:"OPERATOR_BRANCH" default:"master"`

	// LintArgs are the arguments to pass to the linter
	LintArgs string `envconfig:"LINT_ARGS" default:"--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"`

	// BinDir is the directory to store binaries
	BinDir string `envconfig:"BIN_DIR" default:"bin"`

	// ValidArchs are the OS architectures supported for multi-arch build
	ValidArchs []string `envconfig:"VALID_ARCHES" default:"amd64,arm64,ppc64le,s390x"`

	DocsHost string `envconfig:"DOCS_HOST"`
	DocsPort string `envconfig:"DOCS_PORT"`
	DocsUser string `envconfig:"DOCS_USER"`
	DocsKey  string `envconfig:"DOCS_KEY"`
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
