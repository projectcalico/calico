// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package main

import (
	"fmt"
	"sort"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	intdataplane "github.com/projectcalico/felix/dataplane/linux"

	"github.com/projectcalico/felix/buildinfo"
)

const bpfUsage = `calico-bpf, tool for interrogating Calico BPF state.

Usage:
  calico-bpf dump ipsets

Options:
  --version                    Print the version and exit.
`

// main is the entry point to the calico-bpf binary.
func main() {
	// Parse command-line args.
	version := "Version:            " + buildinfo.GitVersion + "\n" +
		"Full git commit ID: " + buildinfo.GitRevision + "\n" +
		"Build date:         " + buildinfo.BuildDate + "\n"
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}

	_ = arguments

	ipsets := intdataplane.IPSetsMap()
	membersBySet := map[uint64][]string{}
	err = ipsets.Iter(func(k, v []byte) {
		var entry intdataplane.IPSetEntry
		copy(entry[:], k[:])
		var member string
		if entry.Protocol() == 0 {
			member = fmt.Sprintf("%s/%d", entry.Addr(), entry.PrefixLen()-64)
		} else {
			member = fmt.Sprintf("%s:%d (proto %d)", entry.Addr(), entry.Port(), entry.Protocol())
		}
		membersBySet[entry.SetID()] = append(membersBySet[entry.SetID()], member)
	})
	if err != nil {
		log.WithError(err).Error("Failed to dump IP sets map.")
	}
	var setIDs []uint64
	for k, v := range membersBySet {
		setIDs = append(setIDs, k)
		sort.Strings(v)
	}
	sort.Slice(setIDs, func(i, j int) bool {
		return setIDs[i] < setIDs[j]
	})

	for _, setID := range setIDs {
		fmt.Println("IP set ", setID)
		for _, member := range membersBySet[setID] {
			fmt.Println("  ", member)
		}
		fmt.Println()
	}
	if len(setIDs) == 0 {
		fmt.Println("No IP sets found.")
	}
}
