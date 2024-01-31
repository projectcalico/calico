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

	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
)

const (
	V4MapIndex = iota
	V6MapIndex
	CommonMapIndex
)

type Maps struct {
	IpsetsMap    maps.Map
	ArpMap       maps.Map
	FailsafesMap maps.Map
	FrontendMap  maps.Map
	BackendMap   maps.Map
	AffinityMap  maps.Map
	RouteMap     maps.Map
	CtMap        maps.Map
	SrMsgMap     maps.Map
	CtNatsMap    maps.Map

	StateMap        maps.Map
	IfStateMap      maps.Map
	RuleCountersMap maps.Map
	CountersMap     maps.Map
	ProgramsMap     maps.Map
	JumpMap         maps.MapWithDeleteIfExists
	XDPProgramsMap  maps.Map
	XDPJumpMap      maps.MapWithDeleteIfExists
}

func (m *Maps) Destroy() {
	mps := []maps.Map{
		m.IpsetsMap,
		m.StateMap,
		m.ArpMap,
		m.FailsafesMap,
		m.FrontendMap,
		m.BackendMap,
		m.AffinityMap,
		m.RouteMap,
		m.CtMap,
		m.SrMsgMap,
		m.CtNatsMap,
		m.ProgramsMap,
		m.JumpMap,
		m.XDPProgramsMap,
		m.XDPJumpMap,
	}

	for _, m := range mps {
		if m == nil {
			continue
		}
		os.Remove(m.(pinnedMap).Path())
		m.(pinnedMap).Close()
	}
}

func getCommonBPFMaps(mapsPtr *Maps) []maps.Map {
	mps := []maps.Map{}

	// Create the common maps
	mapsPtr.StateMap = state.Map()
	mps = append(mps, mapsPtr.StateMap)

	mapsPtr.IfStateMap = ifstate.Map()
	mps = append(mps, mapsPtr.IfStateMap)

	mapsPtr.RuleCountersMap = counters.PolicyMap()
	mps = append(mps, mapsPtr.RuleCountersMap)

	mapsPtr.CountersMap = counters.Map()
	mps = append(mps, mapsPtr.CountersMap)

	mapsPtr.ProgramsMap = hook.NewProgramsMap()
	mps = append(mps, mapsPtr.ProgramsMap)

	mapsPtr.JumpMap = jump.Map().(maps.MapWithDeleteIfExists)
	mps = append(mps, mapsPtr.JumpMap)

	mapsPtr.XDPProgramsMap = hook.NewXDPProgramsMap()
	mps = append(mps, mapsPtr.XDPProgramsMap)

	mapsPtr.XDPJumpMap = jump.XDPMap().(maps.MapWithDeleteIfExists)
	mps = append(mps, mapsPtr.XDPJumpMap)

	return mps
}

func getBPFMapsPerIPFamily(mapsPtr *Maps, ipFamily int) []maps.Map {
	mps := []maps.Map{}

	getmap := func(v4, v6 func() maps.Map, ipFamily int) maps.Map {
		if ipFamily == 4 {
			return v4()
		}
		return v6()
	}

	getmapWithExistsCheck := func(v4, v6 func() maps.MapWithExistsCheck, ipFamily int) maps.MapWithExistsCheck {
		if ipFamily == 4 {
			return v4()
		}
		return v6()
	}
	mapsPtr.IpsetsMap = getmap(ipsets.Map, ipsets.MapV6, ipFamily)
	mps = append(mps, mapsPtr.IpsetsMap)

	mapsPtr.ArpMap = getmap(arp.Map, arp.MapV6, ipFamily)
	mps = append(mps, mapsPtr.ArpMap)

	mapsPtr.FailsafesMap = getmap(failsafes.Map, failsafes.MapV6, ipFamily)
	mps = append(mps, mapsPtr.FailsafesMap)

	mapsPtr.FrontendMap = getmapWithExistsCheck(nat.FrontendMap, nat.FrontendMapV6, ipFamily)
	mps = append(mps, mapsPtr.FrontendMap)

	mapsPtr.BackendMap = getmapWithExistsCheck(nat.BackendMap, nat.BackendMapV6, ipFamily)
	mps = append(mps, mapsPtr.BackendMap)

	mapsPtr.AffinityMap = getmap(nat.AffinityMap, nat.AffinityMapV6, ipFamily)
	mps = append(mps, mapsPtr.AffinityMap)

	mapsPtr.RouteMap = getmap(routes.Map, routes.MapV6, ipFamily)
	mps = append(mps, mapsPtr.RouteMap)

	mapsPtr.CtMap = getmap(conntrack.Map, conntrack.MapV6, ipFamily)
	mps = append(mps, mapsPtr.CtMap)

	mapsPtr.SrMsgMap = getmap(nat.SendRecvMsgMap, nat.SendRecvMsgMapV6, ipFamily)
	mps = append(mps, mapsPtr.SrMsgMap)

	mapsPtr.CtNatsMap = getmap(nat.AllNATsMsgMap, nat.AllNATsMsgMapV6, ipFamily)
	mps = append(mps, mapsPtr.CtNatsMap)

	return mps
}

func CreateBPFMaps(ipv6Enabled bool) ([]Maps, error) {
	mps := []maps.Map{}
	ret := make([]Maps, 3)

	mps = append(mps, getBPFMapsPerIPFamily(&ret[V4MapIndex], 4)...)
	if ipv6Enabled {
		mps = append(mps, getBPFMapsPerIPFamily(&ret[V6MapIndex], 6)...)
	}
	mps = append(mps, getCommonBPFMaps(&ret[CommonMapIndex])...)

	for i, bpfMap := range mps {
		err := bpfMap.EnsureExists()
		if err != nil {

			for j := 0; j < i; j++ {
				m := mps[j]
				os.Remove(m.(pinnedMap).Path())
				m.(pinnedMap).Close()
			}

			return nil, fmt.Errorf("failed to create %s map, err=%w", bpfMap.GetName(), err)
		}
	}

	return ret, nil
}

type pinnedMap interface {
	Path() string
	Close() error
}
