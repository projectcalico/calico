package config

type Config struct {
	packageName    string
	GoBuildImage   string `envconfig:"GO_BUILD_IMAGE" default:"calico/go-build"`
	GoBuildVersion string `envconfig:"GO_BUILD_VER" default:"v0.91"`
	GitUseSSH      bool   `envconfig:"GIT_USE_SSH" default:"false"`
	LintArgs       string `envconfig:"LINT_ARGS" default:"--max-issues-per-linter 0 --max-same-issues 0 --timeout 8m"`
}

func NewConfig(packageName string) *Config {
	return &Config{
		packageName: packageName,
	}
}

func (c *Config) PackageName() string {
	return c.packageName
}
