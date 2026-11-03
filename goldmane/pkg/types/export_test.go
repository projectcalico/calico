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
	"unique"

	"github.com/projectcalico/calico/goldmane/proto"
)

// MaxCachedPolicyTraces exposes the trace cache bound to the external test package.
const MaxCachedPolicyTraces = maxCachedPolicyTraces

// PolicyTraceCache is a trace cache separate from the package-wide one, so a test can give it a
// small bound and cross it cheaply.
type PolicyTraceCache = policyTraceCache

// NewPolicyTraceCache returns an empty trace cache that clears once it holds limit traces.
func NewPolicyTraceCache(limit int64) *PolicyTraceCache {
	return newPolicyTraceCache(limit)
}

// Trace looks up h as CachedPolicyTrace does for the package-wide cache.
func (c *policyTraceCache) Trace(h unique.Handle[string]) *proto.PolicyTrace {
	return c.trace(h)
}

// Size returns the cache's own count of cached traces, which backs the size gauge.
func (c *policyTraceCache) Size() int64 {
	return c.count.Load()
}

// Resets returns how many times the cache has filled and been cleared.
func (c *policyTraceCache) Resets() uint64 {
	return c.resets.Load()
}

// Len counts the traces actually in the map, independent of the cache's own count.
func (c *policyTraceCache) Len() int64 {
	var n int64
	c.traces.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}
