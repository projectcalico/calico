package logrus

type Option func(*config)

func WithComponentName(name string) Option {
	return func(c *config) {
		c.componentName = name
	}
}

func WithOutput(name string) Option {
	return func(c *config) {
		c.componentName = name
	}
}
