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

package types

import (
	"sync"
	"sync/atomic"
	"unique"

	"github.com/projectcalico/calico/goldmane/proto"
)

// maxCachedPolicyTraces bounds the decoded trace cache. A cluster has one trace per distinct
// path through its policies, usually hundreds, and a decoded trace is a few hundred bytes.
const maxCachedPolicyTraces = 4096

var (
	policyTraceCache     sync.Map
	policyTraceCacheSize atomic.Int64
)

// CachedPolicyTrace returns the decoded, sorted policy trace for h, decoding it at most once
// while it stays cached. The result is shared between callers and goroutines, so callers must
// not modify it.
func CachedPolicyTrace(h unique.Handle[string]) *proto.PolicyTrace {
	if v, ok := policyTraceCache.Load(h); ok {
		if p, ok := v.(*proto.PolicyTrace); ok {
			return p
		}
	}

	p := FlowLogPolicyToProto(h)

	// Churn past the bound clears the whole cache rather than tracking recency. Refilling
	// costs one decode per trace, and the cache never grows past the bound.
	if policyTraceCacheSize.Add(1) > maxCachedPolicyTraces {
		policyTraceCache.Clear()
		policyTraceCacheSize.Store(1)
	}
	policyTraceCache.Store(h, p)
	return p
}
