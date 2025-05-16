// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
