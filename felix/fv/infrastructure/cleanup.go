// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
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

package infrastructure

import "sync"

// cleanupStack is a reusable reverse-order cleanup registry.
// It is thread-safe and does not suppress panics from registered functions.
//
// Note: intentionally unexported to keep scope local to infrastructure
// while providing small wrapper methods on infra structs.
type cleanupStack struct {
	mu  sync.Mutex
	fns []func()
}

func (c *cleanupStack) Add(f func()) {
	if f == nil {
		return
	}
	c.mu.Lock()
	c.fns = append(c.fns, f)
	c.mu.Unlock()
}

// Run executes registered functions in reverse order and clears the stack.
// Panics from cleanup functions are allowed to propagate to the caller.
func (c *cleanupStack) Run() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.fns) - 1; i >= 0; i-- {
		c.fns[i]()
	}
	c.fns = nil
}
