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
	"strings"
	"sync"
)

type RefRecorder interface {
	Add(refs ...string) error
}

// DigestResolver reports the manifest digest of a tag. exists is false with a
// nil error when the tag is absent; auth and network failures return an error.
type DigestResolver func(ref string) (digest string, exists bool, err error)

// A repo publishes several tags at different digests, so it maps to a set.
type RecordedDigests map[string]map[string]struct{}

func DigestsByRepo(refs []string) RecordedDigests {
	out := make(RecordedDigests, len(refs))
	for _, ref := range refs {
		repo, digest, ok := strings.Cut(ref, "@")
		if !ok {
			continue
		}
		if out[repo] == nil {
			out[repo] = map[string]struct{}{}
		}
		out[repo][digest] = struct{}{}
	}
	return out
}

// Go runs fn over every item at once and waits for all of them, so fn must be
// safe to call concurrently. Results come back in the order the items were
// given, whatever order they finished in.
func Go[U, T any](items []U, fn func(U) (T, error)) ([]T, error) {
	var wg sync.WaitGroup
	out := make([]T, len(items))
	errs := make([]error, len(items))
	for i, item := range items {
		wg.Go(func() { out[i], errs[i] = fn(item) })
	}
	wg.Wait()
	return out, errors.Join(errs...)
}
