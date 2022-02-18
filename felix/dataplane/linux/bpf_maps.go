//go:build !windows

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

package intdataplane

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
)

func CreateBPFMaps(mc *bpf.MapContext, config *Config) {
	maps := []bpf.Map{}

	mc.IpsetsMap = ipsets.Map(mc)
	mc.IpsetsMap.SetMaxEntries(config.BPFMapSizeIPSets)
	maps = append(maps, mc.IpsetsMap)

	mc.StateMap = state.Map(mc)
	maps = append(maps, mc.StateMap)

	mc.ArpMap = arp.Map(mc)
	maps = append(maps, mc.ArpMap)

	mc.FailsafesMap = failsafes.Map(mc)
	maps = append(maps, mc.FailsafesMap)

	mc.FrontendMap = nat.FrontendMap(mc)
	mc.FrontendMap.SetMaxEntries(config.BPFMapSizeNATFrontend)
	maps = append(maps, mc.FrontendMap)

	mc.BackendMap = nat.BackendMap(mc)
	mc.BackendMap.SetMaxEntries(config.BPFMapSizeNATBackend)
	maps = append(maps, mc.BackendMap)

	mc.AffinityMap = nat.AffinityMap(mc)
	mc.AffinityMap.SetMaxEntries(config.BPFMapSizeNATAffinity)
	maps = append(maps, mc.AffinityMap)

	mc.RouteMap = routes.Map(mc)
	mc.RouteMap.SetMaxEntries(config.BPFMapSizeRoute)
	maps = append(maps, mc.RouteMap)

	mc.CtMap = conntrack.Map(mc)
	mc.CtMap.SetMaxEntries(config.BPFMapSizeConntrack)
	maps = append(maps, mc.CtMap)

	mc.SrMsgMap = nat.SendRecvMsgMap(mc)
	maps = append(maps, mc.SrMsgMap)

	mc.CtNatsMap = nat.AllNATsMsgMap(mc)
	maps = append(maps, mc.CtNatsMap)

	for _, bpfMap := range maps {
		err := bpfMap.EnsureExists()
		if err != nil {
			log.WithError(err).Panicf("Failed to create %s map %s", bpfMap.GetName(), err)
		}
		mc.MapSizes[bpfMap.GetName()] = uint32((bpfMap.(*bpf.PinnedMap)).MaxEntries)
	}
}
