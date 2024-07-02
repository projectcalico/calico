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

	// LintArgs are the arguments to pass to the linter
	LintArgs string `envconfig:"LINT_ARGS" default:"--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"`

	// BinDir is the directory to store binaries
	BinDir string `envconfig:"BIN_DIR" default:"bin"`
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
