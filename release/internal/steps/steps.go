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

// Package steps holds what every release step uses.
package steps

import (
	"errors"
	"sync"
)

type RefRecorder interface {
	Add(refs ...string) error
}

// Go runs fn over every item at once and waits for all of them, so fn must be
// safe to call concurrently. Results come back in the order the items were
// given, whatever order they finished in.
func Go[U, T any](items []U, fn func(U) (T, error)) ([]T, error) {
	return GoLimit(items, 0, fn)
}

// GoLimit runs fn over every item, at most limit in flight.
// A limit of zero or less runs everything at once.
func GoLimit[U, T any](items []U, limit int, fn func(U) (T, error)) ([]T, error) {
	var wg sync.WaitGroup
	out := make([]T, len(items))
	errs := make([]error, len(items))
	var tokens chan struct{}
	if limit > 0 {
		tokens = make(chan struct{}, limit)
	}
	for i, item := range items {
		if tokens != nil {
			tokens <- struct{}{}
		}
		wg.Go(func() {
			if tokens != nil {
				defer func() { <-tokens }()
			}
			out[i], errs[i] = fn(item)
		})
	}
	wg.Wait()
	return out, errors.Join(errs...)
}
