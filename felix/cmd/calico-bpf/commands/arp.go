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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

func init() {
	arpCmd.AddCommand(arpDumpCmd)
	arpCmd.AddCommand(arpCleanCmd)
	rootCmd.AddCommand(arpCmd)
}

var arpDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps arp",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dumpARP(); err != nil {
			log.WithError(err).Error("Failed to dump the arp table.")
		}
	},
}

var arpCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "removes all arp entries",
	Run: func(cmd *cobra.Command, args []string) {
		if err := cleanARP(); err != nil {
			log.WithError(err).Error("Failed to clean the arp table.")
		}
	},
}

// arpCmd represents the arp command
var arpCmd = &cobra.Command{
	Use:   "arp",
	Short: "Manipulates arp",
}

func dumpARP() error {
	var arpMap maps.Map

	v6 := false

	if ipv6 != nil && *ipv6 {
		v6 = true
		arpMap = arp.MapV6()
	} else {
		arpMap = arp.Map()
	}

	if err := arpMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	err := arpMap.Iter(func(k, v []byte) maps.IteratorAction {
		if v6 {
			var (
				key arp.KeyV6
				val arp.ValueV6
			)

			copy(key[:], k[:arp.KeyV6Size])
			copy(val[:], v[:arp.ValueV6Size])

			fmt.Printf("dev %4d: %15s : %s -> %s\n", key.IfIndex(), key.IP(), val.SrcMAC(), val.DstMAC())
		} else {
			var (
				key arp.Key
				val arp.Value
			)

			copy(key[:], k[:arp.KeySize])
			copy(val[:], v[:arp.ValueSize])

			fmt.Printf("dev %4d: %15s : %s -> %s\n", key.IfIndex(), key.IP(), val.SrcMAC(), val.DstMAC())
		}

		return maps.IterNone
	})

	return err
}

func cleanARP() error {
	arpMap := arp.Map()

	if err := arpMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	err := arpMap.Iter(func(k, v []byte) maps.IteratorAction {
		return maps.IterDelete
	})

	return err
}
