package logrus

import (
	"io"

	"github.com/sirupsen/logrus"

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

func WithHooks(hooks ...types.Hook) Option {
	return func(c *config) {
		c.hooks = hooks
	}
}

func WithBackgroundHook(levels []types.Level,
	syslogLevel types.Level,
	destinations []*Destination,
	counter MetricsCounter,
	opts ...BackgroundHookOpt) Option {
	return func(c *config) {
		var convertedLevels []logrus.Level
		for _, level := range levels {
			convertedLevels = append(convertedLevels, logrus.Level(level))
		}
		c.backgroundHook = NewBackgroundHook(convertedLevels, logrus.Level(syslogLevel), destinations, counter, opts...)
	}
}
