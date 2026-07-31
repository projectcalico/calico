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

// Package bpfpolprog contains FV helpers for inspecting Felix's BPF policy
// program jump maps. It is split out from felix/fv/infrastructure so importers
// of that package (e.g. kube-controllers FV tests) don't pull in the cgo
// libbpf chain via felix/bpf/jump and felix/bpf/polprog.
package bpfpolprog

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
)

func NumContiguousPolProgramsFn(f *infrastructure.Felix, iface, ingressOrEgress string, family int) func() int {
	return func() int {
		cont, _ := NumPolProgramsByName(f, iface, ingressOrEgress, family)
		return cont
	}
}

func NumPolProgramsByName(f *infrastructure.Felix, iface, ingressOrEgress string, family int) (contiguous, total int) {
	entryPointIdx := f.BPFPolEntryPointIdx(iface, ingressOrEgress, family)
	return NumPolProgramsByEntryPoint(f, entryPointIdx, ingressOrEgress)
}

func NumPolProgramsTotalByEntryPointFn(f *infrastructure.Felix, entryPointIdx int, ingressOrEgress string) func() int {
	return func() int {
		_, total := NumPolProgramsByEntryPoint(f, entryPointIdx, ingressOrEgress)
		return total
	}
}

func NumPolProgramsByEntryPoint(f *infrastructure.Felix, entryPointIdx int, ingressOrEgress string) (contiguous, total int) {
	gapSeen := false
	var jmpMapName string
	if infrastructure.NetkitMode() {
		jmpMapName = jump.NetkitEgressMapParameters.VersionedName()
		if ingressOrEgress == "egress" {
			jmpMapName = jump.NetkitIngressMapParameters.VersionedName()
		}
	} else {
		jmpMapName = jump.EgressMapParameters.VersionedName()
		if ingressOrEgress == "egress" {
			jmpMapName = jump.IngressMapParameters.VersionedName()
		}
	}
	pinnedMap := "/sys/fs/bpf/tc/globals/" + jmpMapName
	for i := range jump.MaxSubPrograms {
		k := polprog.SubProgramJumpIdx(entryPointIdx, i, jump.TCMaxEntryPoints)
		out, err := f.ExecOutput(
			"bpftool", "map", "lookup",
			"pinned", pinnedMap,
			"key",
			fmt.Sprintf("%d", k&0xff),
			fmt.Sprintf("%d", (k>>8)&0xff),
			fmt.Sprintf("%d", (k>>16)&0xff),
			fmt.Sprintf("%d", (k>>24)&0xff),
		)
		if err != nil {
			gapSeen = true
		}
		if strings.Contains(out, `value:`) || strings.Contains(out, `"value":`) {
			total++
			if !gapSeen {
				contiguous++
			}
		} else {
			gapSeen = true
		}
	}
	return
}
