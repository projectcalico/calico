package config

type Config struct {
	packageName string
	// GoBuildImageName is the name of the go-build image
	// if wanting to override calico/go-build
	GoBuildImageName string `envconfig:"GO_BUILD_IMAGE" default:""`
	// GoBuildVersion is the version of the go-build image
	GoBuildVersion string `envconfig:"GO_BUILD_VER" default:"v0.91"`
	// GitUseSSH is a flag to use SSH for git operations
	GitUseSSH bool `envconfig:"GIT_USE_SSH" default:"false"`
	// LintArgs are the arguments to pass to the linter
	LintArgs string `envconfig:"LINT_ARGS" default:"--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"`
	// BinDir is the directory to store binaries
	BinDir string `envconfig:"BIN_DIR" default:"bin"`
}

func NewConfig(packageName string) *Config {
	return &Config{
		packageName: packageName,
	}
}

func (c *Config) PackageName() string {
	return c.packageName
}
