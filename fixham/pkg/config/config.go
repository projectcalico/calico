package config

type Config struct {
	packageName    string
	GoBuildVersion string `envconfig:"GO_BUILD_VERSION" default:"v0.91"`
	GitUseSSH      bool   `envconfig:"GIT_USE_SSH" default:"false"`
	LintArgs       string `envconfig:"LINT_ARGS" default:"--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"`
}

func (c *Config) SetPackageName(packageName string) {
	c.packageName = packageName
}

func (c *Config) PackageName() string {
	return c.packageName
}
