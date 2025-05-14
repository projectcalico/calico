package logrus

import (
	"io"

	"github.com/projectcalico/calico/lib/std/log/types"
)

type Option func(*config)

func WithComponentName(name string) Option {
	return func(c *config) {
		c.componentName = name
	}
}

func WithOutput(output io.Writer) Option {
	return func(c *config) {
		c.output = output
	}
}

func WithFormatter(formatter types.Formatter) Option {
	return func(c *config) {
		c.formatter = formatter
	}
}

func WithLevel(level types.Level) Option {
	return func(c *config) {
		c.level = level
	}
}
