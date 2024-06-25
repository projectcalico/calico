package config

type Config struct {
	packageName string
	// GoBuildImageName is the name of the go-build image
	// if wanting to override calico/go-build
	GoBuildImageName string `envconfig:"GO_BUILD_IMAGE" default:""`
	// GoBuildVersion is the version of the go-build image
	goBuildVersion string //`envconfig:"GO_BUILD_VER" default:"v0.91"`
	// GitUseSSH is a flag to use SSH for git operations
	GitUseSSH bool `envconfig:"GIT_USE_SSH" default:"false"`
	// RepoRootDir is the root directory for the repository
	// it is used for git operations
	RepoRootDir string
	// LintArgs are the arguments to pass to the linter
	LintArgs string `envconfig:"LINT_ARGS" default:"--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"`
	// BinDir is the directory to store binaries
	BinDir string `envconfig:"BIN_DIR" default:"bin"`
}

func NewConfig(packageName string) *Config {
	repoRootDir := MustReadGitRepoPath()
	// TODO: update to use envconfig for goBuildVersion
	goBuildVersion := MustReadMakefileValue(repoRootDir+"/"+makefileConfigFile, "GO_BUILD_VER")
	return &Config{
		packageName:    packageName,
		RepoRootDir:    repoRootDir,
		goBuildVersion: goBuildVersion,
	}
}

func (c *Config) PackageName() string {
	return c.packageName
}

func (c *Config) GoBuildVersion() string {
	return c.goBuildVersion
}
