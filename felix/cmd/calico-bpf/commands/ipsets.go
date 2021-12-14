// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package commands

import (
	"fmt"
	"sort"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/ipsets"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	ipsetsCmd.AddCommand(ipsetsDumpCmd)
	rootCmd.AddCommand(ipsetsCmd)
}

var ipsetsDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps ipsets",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dumpIPSets(); err != nil {
			log.WithError(err).Error("Failed to dump IP sets map.")
		}
	},
}

// ipsetsCmd represents the ipsets command
var ipsetsCmd = &cobra.Command{
	Use:   "ipsets",
	Short: "Manipulates ipsets",
}

func dumpIPSets() error {
	ipsetMap := ipsets.Map(&bpf.MapContext{})

	if err := ipsetMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	membersBySet := map[uint64][]string{}
	err := ipsetMap.Iter(func(k, v []byte) bpf.IteratorAction {
		var entry ipsets.IPSetEntry
		copy(entry[:], k[:])
		var member string
		if entry.Protocol() == 0 {
			member = fmt.Sprintf("%s/%d", entry.Addr(), entry.PrefixLen()-64)
		} else {
			member = fmt.Sprintf("%s:%d (proto %d)", entry.Addr(), entry.Port(), entry.Protocol())
		}
		membersBySet[entry.SetID()] = append(membersBySet[entry.SetID()], member)
		return bpf.IterNone
	})
	if err != nil {
		return err
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
		fmt.Printf("IP set %#x\n", setID)
		for _, member := range membersBySet[setID] {
			fmt.Println("  ", member)
		}
		fmt.Println()
	}
	if len(setIDs) == 0 {
		fmt.Println("No IP sets found.")
	}

	return nil
}
