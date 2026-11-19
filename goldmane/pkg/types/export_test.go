// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package types

import (
	"sync"
	"unique"

	"github.com/projectcalico/calico/goldmane/proto"
)

// PolicyTraceGenerationSize exposes the trace cache's generation size to the external test
// package.
const PolicyTraceGenerationSize = policyTraceGenerationSize

// PolicyTraceCache is a trace cache separate from the package-wide one, so a test can give it a
// small generation size and rotate it cheaply.
type PolicyTraceCache = policyTraceCache

// NewPolicyTraceCache returns an empty trace cache that rotates once its current generation
// holds generationSize traces.
func NewPolicyTraceCache(generationSize int64) *PolicyTraceCache {
	return newPolicyTraceCache(generationSize)
}

// Trace looks up h as CachedPolicyTrace does for the package-wide cache.
func (c *policyTraceCache) Trace(h unique.Handle[string]) *proto.PolicyTrace {
	return c.trace(h)
}

// Size returns the cache's own count of entries across both generations, which backs the size
// gauge.
func (c *policyTraceCache) Size() int64 {
	return c.size()
}

// Rotations returns how many times the cache has started a new generation.
func (c *policyTraceCache) Rotations() uint64 {
	return c.rotations.Load()
}

// Holds reports whether either generation holds a trace for h, without promoting it.
func (c *policyTraceCache) Holds(h unique.Handle[string]) bool {
	_, inCurrent := loadTrace(c.current.Load(), h)
	_, inPrevious := loadTrace(c.previous.Load(), h)
	return inCurrent || inPrevious
}

// DefaultPolicyTraceCacheHolds reports whether the package-wide cache holds a trace for h.
func DefaultPolicyTraceCacheHolds(h unique.Handle[string]) bool {
	return defaultPolicyTraceCache.Holds(h)
}

// Lens counts the entries actually in the current and previous generations' maps, in that order,
// independent of the cache's own counts.
func (c *policyTraceCache) Lens() (int64, int64) {
	return mapLen(c.current.Load()), mapLen(c.previous.Load())
}

func mapLen(m *sync.Map) int64 {
	var n int64
	m.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}
