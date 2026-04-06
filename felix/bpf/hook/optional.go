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

package hook

import "sync"

// OptionalSubProgInfo describes a BPF sub-program that may fail to load on
// older kernels. Each optional program has user-facing metadata used for
// health reporting when the program fails to load.
type OptionalSubProgInfo struct {
	SubProg      SubProg
	FeatureName  string                   // human-readable, e.g., "IP fragment reassembly"
	ProgName     string                   // BPF C function name, e.g., "calico_tc_skb_ipv4_frag"
	DisableMsg   string                   // message telling user how to disable the feature
	IsApplicable func(at AttachType) bool // structural applicability check
}

var optionalMu sync.Mutex

var optionalSubProgs = map[SubProg]OptionalSubProgInfo{
	SubProgIPFrag: {
		SubProg:      SubProgIPFrag,
		FeatureName:  "IP fragment reassembly",
		ProgName:     "calico_tc_skb_ipv4_frag",
		DisableMsg:   "Set bpfIPFragmentReassemblyEnabled to false in FelixConfiguration to disable this feature.",
		IsApplicable: func(at AttachType) bool { return at.hasIPDefrag() },
	},
}

// GetOptionalSubProgInfo returns the info for an optional sub-program, or nil
// if the sub-program is not in the optional registry (i.e., it is required).
func GetOptionalSubProgInfo(sp SubProg) *OptionalSubProgInfo {
	optionalMu.Lock()
	defer optionalMu.Unlock()
	info, ok := optionalSubProgs[sp]
	if !ok {
		return nil
	}
	return &info
}

// IsOptionalSubProg returns true if the sub-program is in the optional registry.
func IsOptionalSubProg(sp SubProg) bool {
	optionalMu.Lock()
	defer optionalMu.Unlock()
	_, ok := optionalSubProgs[sp]
	return ok
}

// isOptionalAndNotApplicable checks if a sub-program is optional and not
// applicable to the given AttachType. Returns (isOptional, shouldSkip).
func isOptionalAndNotApplicable(sp SubProg, at AttachType) (isOptional, shouldSkip bool) {
	optionalMu.Lock()
	defer optionalMu.Unlock()
	info, ok := optionalSubProgs[sp]
	if !ok {
		return false, false
	}
	return true, !info.IsApplicable(at)
}

// forEachOptionalSubProg iterates the optional registry under the lock.
func forEachOptionalSubProg(fn func(SubProg, OptionalSubProgInfo)) {
	optionalMu.Lock()
	defer optionalMu.Unlock()
	for sp, info := range optionalSubProgs {
		fn(sp, info)
	}
}

// RegisterOptionalSubProg registers an additional optional sub-program.
// Must be called during init, before any BPF operations.
func RegisterOptionalSubProg(info OptionalSubProgInfo) {
	optionalMu.Lock()
	defer optionalMu.Unlock()
	optionalSubProgs[info.SubProg] = info
}
