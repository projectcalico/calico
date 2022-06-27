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

package bpfmap

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
)

func CreateBPFMapContext(
	ipsetsMapSize,
	natFEMapSize,
	natBEMapSize,
	natAffMapSize,
	routeMapSize,
	ifstateSize,
	ctMapSize int,
	repinEnabled bool,
) *bpf.MapContext {
	bpfMapContext := &bpf.MapContext{
		RepinningEnabled: repinEnabled,
		MapSizes:         map[string]uint32{},
	}
	bpfMapContext.MapSizes[ipsets.MapParameters.VersionedName()] = uint32(ipsetsMapSize)
	bpfMapContext.MapSizes[nat.FrontendMapParameters.VersionedName()] = uint32(natFEMapSize)
	bpfMapContext.MapSizes[nat.BackendMapParameters.VersionedName()] = uint32(natBEMapSize)
	bpfMapContext.MapSizes[nat.AffinityMapParameters.VersionedName()] = uint32(natAffMapSize)
	bpfMapContext.MapSizes[routes.MapParameters.VersionedName()] = uint32(routeMapSize)
	bpfMapContext.MapSizes[conntrack.MapParams.VersionedName()] = uint32(ctMapSize)

	bpfMapContext.MapSizes[state.MapParameters.VersionedName()] = uint32(state.MapParameters.MaxEntries)
	bpfMapContext.MapSizes[arp.MapParams.VersionedName()] = uint32(arp.MapParams.MaxEntries)
	bpfMapContext.MapSizes[failsafes.MapParams.VersionedName()] = uint32(failsafes.MapParams.MaxEntries)
	bpfMapContext.MapSizes[nat.SendRecvMsgMapParameters.VersionedName()] = uint32(nat.SendRecvMsgMapParameters.MaxEntries)
	bpfMapContext.MapSizes[nat.CTNATsMapParameters.VersionedName()] = uint32(nat.CTNATsMapParameters.MaxEntries)
	bpfMapContext.MapSizes[ifstate.MapParams.VersionedName()] = uint32(ifstateSize)

	return bpfMapContext
}

func MigrateDataFromOldMap(mc *bpf.MapContext) {
	ctMap := mc.CtMap
	err := ctMap.CopyDeltaFromOldMap()
	if err != nil {
		log.WithError(err).Debugf("Failed to copy data from old conntrack map %s", err)
	}
}

func DestroyBPFMaps(mc *bpf.MapContext) {
	maps := []bpf.Map{mc.IpsetsMap, mc.StateMap, mc.ArpMap, mc.FailsafesMap, mc.FrontendMap,
		mc.BackendMap, mc.AffinityMap, mc.RouteMap, mc.CtMap, mc.SrMsgMap, mc.CtNatsMap}
	for _, m := range maps {
		os.Remove(m.(*bpf.PinnedMap).Path())
		m.(*bpf.PinnedMap).Close()
	}
}

func CreateBPFMaps(mc *bpf.MapContext) error {
	maps := []bpf.Map{}

	mc.IpsetsMap = ipsets.Map(mc)
	maps = append(maps, mc.IpsetsMap)

	mc.StateMap = state.Map(mc)
	maps = append(maps, mc.StateMap)

	mc.ArpMap = arp.Map(mc)
	maps = append(maps, mc.ArpMap)

	mc.FailsafesMap = failsafes.Map(mc)
	maps = append(maps, mc.FailsafesMap)

	mc.FrontendMap = nat.FrontendMap(mc)
	maps = append(maps, mc.FrontendMap)

	mc.BackendMap = nat.BackendMap(mc)
	maps = append(maps, mc.BackendMap)

	mc.AffinityMap = nat.AffinityMap(mc)
	maps = append(maps, mc.AffinityMap)

	mc.RouteMap = routes.Map(mc)
	maps = append(maps, mc.RouteMap)

	mc.CtMap = conntrack.Map(mc)
	maps = append(maps, mc.CtMap)

	mc.SrMsgMap = nat.SendRecvMsgMap(mc)
	maps = append(maps, mc.SrMsgMap)

	mc.CtNatsMap = nat.AllNATsMsgMap(mc)
	maps = append(maps, mc.CtNatsMap)

	mc.IfStateMap = ifstate.Map(mc)
	maps = append(maps, mc.IfStateMap)

	for _, bpfMap := range maps {
		err := bpfMap.EnsureExists()
		if err != nil {
			return fmt.Errorf("Failed to create %s map, err=%w", bpfMap.GetName(), err)
		}
	}
	return nil
}
