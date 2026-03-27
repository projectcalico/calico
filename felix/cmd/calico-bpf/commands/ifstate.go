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
	"encoding/json"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/maps"
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

type ifstateJSON struct {
	IfIndex         uint32   `json:"ifindex"`
	Name            string   `json:"name"`
	Flags           []string `json:"flags"`
	IngressPolicyV4 int      `json:"ingress_policy_v4"`
	EgressPolicyV4  int      `json:"egress_policy_v4"`
	XDPPolicyV4     int      `json:"xdp_policy_v4"`
	IngressPolicyV6 int      `json:"ingress_policy_v6"`
	EgressPolicyV6  int      `json:"egress_policy_v6"`
	XDPPolicyV6     int      `json:"xdp_policy_v6"`
	TcIngressFilter int      `json:"tc_ingress_filter"`
	TcEgressFilter  int      `json:"tc_egress_filter"`
}

func dumpIfState(cmd *cobra.Command) error {
	ifstateMap := ifstate.Map()

	if err := ifstateMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	var jsonEntries []ifstateJSON

	err := ifstateMap.Iter(func(k, v []byte) maps.IteratorAction {
		var (
			key ifstate.Key
			val ifstate.Value
		)

		copy(key[:], k[:])
		copy(val[:], v[:])

		if *jsonOutput {
			jsonEntries = append(jsonEntries, ifstateJSON{
				IfIndex:         key.IfIndex(),
				Name:            val.IfName(),
				Flags:           ifstate.FlagNames(val.Flags()),
				IngressPolicyV4: val.IngressPolicyV4(),
				EgressPolicyV4:  val.EgressPolicyV4(),
				XDPPolicyV4:     val.XDPPolicyV4(),
				IngressPolicyV6: val.IngressPolicyV6(),
				EgressPolicyV6:  val.EgressPolicyV6(),
				XDPPolicyV6:     val.XDPPolicyV6(),
				TcIngressFilter: val.TcIngressFilter(),
				TcEgressFilter:  val.TcEgressFilter(),
			})
		} else {
			cmd.Printf("%5d : %s\n", key.IfIndex(), val)
		}

		return maps.IterNone
	})
	if err != nil {
		return err
	}

	if *jsonOutput {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(jsonEntries)
	}

	return err
}
