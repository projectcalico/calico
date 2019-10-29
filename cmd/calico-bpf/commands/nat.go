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

package commands

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/felix/bpf/proxy/maps"
)

func init() {
	natCmd.AddCommand(natDumpCmd)
	rootCmd.AddCommand(natCmd)
}

// conntrackCmd represents the conntrack command
var natCmd = &cobra.Command{
	Use:   "nat",
	Short: "Nanipulates network address translation (nat)",
	Long: "nat manipulates network address translation (nat), " +
		"which implements the bpf-based replacement for kube-proxy",
}

var natDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps the nat tables",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dump(cmd); err != nil {
			log.WithError(err).Error("Failed to dump NAT maps")
		}
	},
}

func dump(cmd *cobra.Command) error {
	nat, err := maps.LoadNATMap(maps.NATMap())
	if err != nil {
		return err
	}

	back, err := maps.LoadNATBackendMap(maps.BackendMap())
	if err != nil {
		return err
	}

	dumpNice(cmd.Printf, nat, back)
	return nil
}

type printfFn func(format string, i ...interface{})

func dumpNice(printf printfFn, nat maps.NATMapMem, back maps.NATBackendMapMem) {
	for nk, nv := range nat {
		count := nv.Count()
		id := nv.ID()
		printf("%s port %d proto %d id %d count %d\n", nk.Addr(), nk.Port(), nk.Proto(), id, count)
		for i := uint32(0); i < count; i++ {
			bk := maps.NewNATBackendKey(id, i)
			bv, ok := back[bk]
			printf("\t%d:%d\t ", id, i)
			if !ok {
				printf("is missing\n")
			} else {
				printf("%s:%d\n", bv.Addr(), bv.Port())
			}
		}
	}
}
