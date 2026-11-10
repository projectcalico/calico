// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

import (
	"slices"
	"sync"
)

// Call is one command a Recorder received, with its options applied.
type Call struct {
	Name    string
	Args    []string
	Dir     string
	Env     []string
	LogFile string
	Stdin   string
	Stream  bool
}

// Recorder is a CommandRunner that records each command instead of running it.
type Recorder struct {
	// Reply, if set, gives each command's output. It runs outside the lock, so
	// commands can overlap and a Reply that keeps state locks it itself.
	Reply func(Call) (string, error)

	mu    sync.Mutex
	calls []Call
}

func (r *Recorder) Run(name string, args []string, opts ...Option) (string, error) {
	s := newSettings(opts)
	c := Call{Name: name, Args: slices.Clone(args), Dir: s.dir, Env: s.env, LogFile: s.logFile, Stdin: s.stdin, Stream: s.stream}
	r.mu.Lock()
	r.calls = append(r.calls, c)
	r.mu.Unlock()
	if r.Reply == nil {
		return "", nil
	}
	return r.Reply(c)
}

func (r *Recorder) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Call(nil), r.calls...)
}
