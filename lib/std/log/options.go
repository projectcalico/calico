package log

import (
	"io"
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

func WithFormatter(formatter Formatter) Option {
	return func(c *config) {
		c.formatter = formatter
	}
}

func WithLevel(level Level) Option {
	return func(c *config) {
		c.level = level
	}
}

func WithHooks(hooks ...Hook) Option {
	return func(c *config) {
		c.hooks = hooks
	}
}

func WithBackgroundHook(levels []Level,
	syslogLevel Level,
	destinations []*Destination,
	counter MetricsCounter,
	opts ...BackgroundHookOpt) Option {
	return func(c *config) {
		c.backgroundHook = NewBackgroundHook(levels, syslogLevel, destinations, counter, opts...)
	}
}
