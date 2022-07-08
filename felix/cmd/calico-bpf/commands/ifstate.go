// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/ifstate"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	ifstateCmd.AddCommand(ifstateDumpCmd)
	rootCmd.AddCommand(ifstateCmd)
}

var ifstateDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps interface states",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dumpIfState(cmd); err != nil {
			log.WithError(err).Error("Failed to dump interface states map.")
		}
	},
}

// ifstateCmd represents the ifstate command
var ifstateCmd = &cobra.Command{
	Use:   "ifstate",
	Short: "Manipulates ifstate",
}

func dumpIfState(cmd *cobra.Command) error {
	ifstateMap := ifstate.Map(&bpf.MapContext{})

	if err := ifstateMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	err := ifstateMap.Iter(func(k, v []byte) bpf.IteratorAction {
		var (
			key ifstate.Key
			val ifstate.Value
		)

		copy(key[:], k[:])
		copy(val[:], v[:])

		cmd.Printf("%5d : %s\n", key.IfIndex(), val)

		return bpf.IterNone
	})

	return err
}
