package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	Name         string `envconfig:"NAME"`
	PackageName  string `envconfig:"PACKAGE_NAME" required:"true"`
	Organization string `envconfig:"ORGANIZATION"`
	// GoBuildImageName is the name of the go-build image
	// if wanting to override calico/go-build
	GoBuildImageName string `envconfig:"GO_BUILD_IMAGE" default:"calico/go-build"`
	// GoBuildVersion is the version of the go-build image
	GoBuildVersion string `envconfig:"GO_BUILD_VER" required:"true"`
	// GitUseSSH is a flag to use SSH for git operations
	GitUseSSH bool `envconfig:"GIT_USE_SSH"`
	// RepoRootDir is the root directory for the repository
	// it is used for git operations
	RepoRootDir string `envconfig:"REPO_ROOT" required:"true"`
	// LintArgs are the arguments to pass to the linter
	LintArgs string `envconfig:"LINT_ARGS" default:"--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"`
	// BinDir is the directory to store binaries
	BinDir string `envconfig:"BIN_DIR"`
}

func LoadConfig() *Config {
	config := &Config{}
	envconfig.MustProcess("", config)
	return config
}
