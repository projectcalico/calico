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

// OptionalSubProgInfo describes a BPF sub-program that may fail to load on
// older kernels. Each optional program has user-facing metadata used for
// health reporting when the program fails to load.
type OptionalSubProgInfo struct {
	SubProg     SubProg
	FeatureName string // human-readable, e.g., "IP fragment reassembly"
	DisableMsg  string // message telling user how to disable the feature
}

var optionalSubProgs = map[SubProg]OptionalSubProgInfo{
	SubProgIPFrag: {
		SubProg:     SubProgIPFrag,
		FeatureName: "IP fragment reassembly",
		DisableMsg:  "Set bpfIPFragmentReassemblyEnabled to false in FelixConfiguration to disable this feature.",
	},
}

// GetOptionalSubProgInfo returns the info for an optional sub-program, or nil
// if the sub-program is not in the optional registry (i.e., it is required).
func GetOptionalSubProgInfo(sp SubProg) *OptionalSubProgInfo {
	info, ok := optionalSubProgs[sp]
	if !ok {
		return nil
	}
	return &info
}

// IsOptionalSubProg returns true if the sub-program is in the optional registry.
func IsOptionalSubProg(sp SubProg) bool {
	_, ok := optionalSubProgs[sp]
	return ok
}

// RegisterOptionalSubProg registers an additional optional sub-program.
// This is intended for enterprise code to extend the registry at init time.
func RegisterOptionalSubProg(info OptionalSubProgInfo) {
	optionalSubProgs[info.SubProg] = info
}
