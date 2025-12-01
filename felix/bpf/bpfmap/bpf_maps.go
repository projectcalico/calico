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
	"github.com/projectcalico/calico/felix/bpf/profiling"
	"github.com/projectcalico/calico/felix/bpf/qos"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
)

type IPMaps struct {
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
	CtCleanupMap maps.Map
	MaglevMap    maps.Map
}

type CommonMaps struct {
	StateMap         maps.Map
	IfStateMap       maps.Map
	RuleCountersMap  maps.Map
	CountersMap      maps.Map
	ProgramsMaps     []maps.Map
	JumpMap          maps.MapWithDeleteIfExists
	XDPProgramsMap   maps.Map
	XDPJumpMap       maps.MapWithDeleteIfExists
	ProfilingMap     maps.Map
	CTLBProgramsMaps []maps.Map
	QoSMap           maps.MapWithUpdateWithFlags
}

type Maps struct {
	CommonMaps *CommonMaps
	V4         *IPMaps
	V6         *IPMaps
}

func (m *Maps) Destroy() {
	mps := []maps.Map{}
	mps = append(mps, m.CommonMaps.slice()...)
	mps = append(mps, m.V4.slice()...)
	if m.V6 != nil {
		mps = append(mps, m.V6.slice()...)
	}
	for _, m := range mps {
		os.Remove(m.(pinnedMap).Path())
		m.(pinnedMap).Close()
	}
}

func getCommonMaps() *CommonMaps {
	return &CommonMaps{
		StateMap:         state.Map(),
		IfStateMap:       ifstate.Map(),
		RuleCountersMap:  counters.PolicyMap(),
		CountersMap:      counters.Map(),
		ProgramsMaps:     hook.NewProgramsMaps(),
		JumpMap:          jump.Map().(maps.MapWithDeleteIfExists),
		XDPProgramsMap:   hook.NewXDPProgramsMap(),
		XDPJumpMap:       jump.XDPMap().(maps.MapWithDeleteIfExists),
		ProfilingMap:     profiling.Map(),
		CTLBProgramsMaps: nat.ProgramsMaps(),
		QoSMap:           qos.Map().(maps.MapWithUpdateWithFlags),
	}
}

func getIPMaps(ipFamily int) *IPMaps {
	getmap := func(v4, v6 func() maps.Map) maps.Map {
		if ipFamily == 4 {
			return v4()
		}
		return v6()
	}

	getmapWithExistsCheck := func(v4, v6 func() maps.MapWithExistsCheck) maps.MapWithExistsCheck {
		if ipFamily == 4 {
			return v4()
		}
		return v6()
	}

	return &IPMaps{
		IpsetsMap:    getmap(ipsets.Map, ipsets.MapV6),
		ArpMap:       getmap(arp.Map, arp.MapV6),
		FailsafesMap: getmap(failsafes.Map, failsafes.MapV6),
		FrontendMap:  getmapWithExistsCheck(nat.FrontendMap, nat.FrontendMapV6),
		BackendMap:   getmapWithExistsCheck(nat.BackendMap, nat.BackendMapV6),
		AffinityMap:  getmap(nat.AffinityMap, nat.AffinityMapV6),
		RouteMap:     getmap(routes.Map, routes.MapV6),
		CtMap:        getmap(conntrack.Map, conntrack.MapV6),
		CtCleanupMap: getmapWithExistsCheck(conntrack.CleanupMap, conntrack.CleanupMapV6),
		SrMsgMap:     getmap(nat.SendRecvMsgMap, nat.SendRecvMsgMapV6),
		CtNatsMap:    getmap(nat.AllNATsMsgMap, nat.AllNATsMsgMapV6),
		MaglevMap:    getmapWithExistsCheck(nat.MaglevMap, nat.MaglevMapV6)}
}

func CreateBPFMaps(ipV6Enabled bool) (*Maps, error) {
	ret := new(Maps)

	ret.CommonMaps = getCommonMaps()
	ret.V4 = getIPMaps(4)
	if ipV6Enabled {
		ret.V6 = getIPMaps(6)
	}

	mps := ret.slice()
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

func (m *Maps) slice() []maps.Map {
	mps := []maps.Map{}
	mps = append(mps, m.CommonMaps.slice()...)
	if m.V4 != nil {
		mps = append(mps, m.V4.slice()...)
	}
	if m.V6 != nil {
		mps = append(mps, m.V6.slice()...)
	}
	return mps
}

func (c *CommonMaps) slice() []maps.Map {
	mapslice := []maps.Map{
		c.StateMap,
		c.IfStateMap,
		c.RuleCountersMap,
		c.CountersMap,
		c.JumpMap,
		c.XDPProgramsMap,
		c.XDPJumpMap,
		c.ProfilingMap,
		c.QoSMap,
	}
	mapslice = append(mapslice, c.ProgramsMaps...)
	mapslice = append(mapslice, c.CTLBProgramsMaps...)
	return mapslice
}

func (i *IPMaps) slice() []maps.Map {
	return []maps.Map{
		i.IpsetsMap,
		i.ArpMap,
		i.FailsafesMap,
		i.FrontendMap,
		i.BackendMap,
		i.AffinityMap,
		i.RouteMap,
		i.CtMap,
		i.CtCleanupMap,
		i.SrMsgMap,
		i.CtNatsMap,
		i.MaglevMap,
	}
}

type pinnedMap interface {
	Path() string
	Close() error
}
