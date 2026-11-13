// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

type Option interface {
	apply(*settings)
}

type setting func(*settings)

func (f setting) apply(s *settings) { f(s) }

type settings struct {
	dir     string
	env     []string
	logFile string
	stdin   string
	stream  bool
}

func newSettings(opts []Option) *settings {
	s := &settings{}
	for _, o := range opts {
		if o != nil {
			o.apply(s)
		}
	}
	return s
}

func WithDir(dir string) Option {
	return setting(func(s *settings) {
		s.dir = dir
	})
}

// WithEnv adds to the parent's environment.
func WithEnv(env ...string) Option {
	return setting(func(s *settings) {
		s.env = append(s.env, env...)
	})
}

func WithStdin(in string) Option {
	return setting(func(s *settings) {
		s.stdin = in
	})
}

// WithStream shows the command's output as it runs, at any log level.
func WithStream() Option {
	return setting(func(s *settings) {
		s.stream = true
	})
}

// WithLogFile also writes the command's stdout and stderr to path. An empty
// path writes no file.
func WithLogFile(path string) Option {
	return setting(func(s *settings) {
		s.logFile = path
	})
}
