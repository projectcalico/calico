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

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/arp"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
	arpMap := arp.Map(&bpf.MapContext{})

	if err := arpMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	err := arpMap.Iter(func(k, v []byte) bpf.IteratorAction {
		var (
			key arp.Key
			val arp.Value
		)

		copy(key[:], k[:arp.KeySize])
		copy(val[:], v[:arp.ValueSize])

		fmt.Printf("dev %4d: %15s : %s -> %s\n", key.IfIndex(), key.IP(), val.SrcMAC(), val.DstMAC())

		return bpf.IterNone
	})

	return err
}

func cleanARP() error {
	arpMap := arp.Map(&bpf.MapContext{})

	if err := arpMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	err := arpMap.Iter(func(k, v []byte) bpf.IteratorAction {
		return bpf.IterDelete
	})

	return err
}
