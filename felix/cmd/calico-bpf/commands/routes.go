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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
)

func init() {
	routesCmd.AddCommand(routesDumpCmd)
	rootCmd.AddCommand(routesCmd)
}

var routesDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "dumps routes",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dumpRoutes(); err != nil {
			log.WithError(err).Error("Failed to dump routes map.")
		}
	},
}

// routesCmd represents the routes command
var routesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Manipulates routes",
}

func dumpRoutes() error {
	var routesMap maps.Map

	if ipv6 != nil && *ipv6 {
		routesMap = routes.MapV6()
	} else {
		routesMap = routes.Map()
	}

	if err := routesMap.Open(); err != nil {
		return errors.WithMessage(err, "failed to open map")
	}

	var dests []ip.CIDR
	valueByDest := map[ip.CIDR]routes.ValueInterface{}

	err := routesMap.Iter(func(k, v []byte) maps.IteratorAction {
		var key routes.KeyInterface
		var value routes.ValueInterface

		if ipv6 != nil && *ipv6 {
			var kk routes.KeyV6
			var vv routes.ValueV6
			copy(kk[:], k)
			copy(vv[:], v)

			key = kk
			value = vv
		} else {
			var kk routes.Key
			var vv routes.Value
			copy(kk[:], k)
			copy(vv[:], v)

			key = kk
			value = vv
		}

		dest := key.Dest()
		valueByDest[dest] = value
		dests = append(dests, dest)
		return maps.IterNone
	})
	if err != nil {
		return err
	}

	if ipv6 != nil && *ipv6 {
		sortCIDRsV6(dests)
	} else {
		sortCIDRs(dests)
	}

	for _, dest := range dests {
		v := valueByDest[dest]
		fmt.Printf("%15v: %s\n", dest, v)
	}

	return nil
}

func sortCIDRs(cidrs []ip.CIDR) {
	sort.Slice(cidrs, func(i, j int) bool {
		addrA := cidrs[i].Addr().(ip.V4Addr)
		addrB := cidrs[j].Addr().(ip.V4Addr)
		for byteIdx := 0; byteIdx < 4; byteIdx++ {
			if addrA[byteIdx] < addrB[byteIdx] {
				return true
			}
			if addrA[byteIdx] > addrB[byteIdx] {
				return false
			}
		}
		return cidrs[i].Prefix() < cidrs[j].Prefix()
	})
}

func sortCIDRsV6(cidrs []ip.CIDR) {
	sort.Slice(cidrs, func(i, j int) bool {
		addrA := cidrs[i].Addr().(ip.V6Addr)
		addrB := cidrs[j].Addr().(ip.V6Addr)
		for byteIdx := 0; byteIdx < 16; byteIdx++ {
			if addrA[byteIdx] < addrB[byteIdx] {
				return true
			}
			if addrA[byteIdx] > addrB[byteIdx] {
				return false
			}
		}
		return cidrs[i].Prefix() < cidrs[j].Prefix()
	})
}
