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

type Maps struct {
	IpsetsMap       maps.Map
	StateMap        maps.Map
	ArpMap          maps.Map
	FailsafesMap    maps.Map
	FrontendMap     maps.Map
	BackendMap      maps.Map
	AffinityMap     maps.Map
	RouteMap        maps.Map
	CtMap           maps.Map
	SrMsgMap        maps.Map
	CtNatsMap       maps.Map
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
		os.Remove(m.(pinnedMap).Path())
		m.(pinnedMap).Close()
	}
}

func CreateBPFMaps(ipFamily int) (*Maps, error) {
	mps := []maps.Map{}
	ret := new(Maps)

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

	ret.IpsetsMap = ipsets.Map()
	mps = append(mps, ret.IpsetsMap)

	ret.StateMap = state.Map()
	mps = append(mps, ret.StateMap)

	ret.ArpMap = getmap(arp.Map, arp.MapV6)
	mps = append(mps, ret.ArpMap)

	ret.FailsafesMap = failsafes.Map()
	mps = append(mps, ret.FailsafesMap)

	ret.FrontendMap = getmapWithExistsCheck(nat.FrontendMap, nat.FrontendMapV6)
	mps = append(mps, ret.FrontendMap)

	ret.BackendMap = getmapWithExistsCheck(nat.BackendMap, nat.BackendMapV6)
	mps = append(mps, ret.BackendMap)

	ret.AffinityMap = getmap(nat.AffinityMap, nat.AffinityMapV6)
	mps = append(mps, ret.AffinityMap)

	ret.RouteMap = getmap(routes.Map, routes.MapV6)
	mps = append(mps, ret.RouteMap)

	ret.CtMap = getmap(conntrack.Map, conntrack.MapV6)
	mps = append(mps, ret.CtMap)

	ret.SrMsgMap = getmap(nat.SendRecvMsgMap, nat.SendRecvMsgMapV6)
	mps = append(mps, ret.SrMsgMap)

	ret.CtNatsMap = getmap(nat.AllNATsMsgMap, nat.AllNATsMsgMapV6)
	mps = append(mps, ret.CtNatsMap)

	ret.IfStateMap = ifstate.Map()
	mps = append(mps, ret.IfStateMap)

	ret.RuleCountersMap = counters.PolicyMap()
	mps = append(mps, ret.RuleCountersMap)

	ret.CountersMap = counters.Map()
	mps = append(mps, ret.CountersMap)

	ret.ProgramsMap = hook.NewProgramsMap()
	mps = append(mps, ret.ProgramsMap)

	ret.JumpMap = jump.Map().(maps.MapWithDeleteIfExists)
	mps = append(mps, ret.JumpMap)

	ret.XDPProgramsMap = hook.NewXDPProgramsMap()
	mps = append(mps, ret.XDPProgramsMap)

	ret.XDPJumpMap = jump.XDPMap().(maps.MapWithDeleteIfExists)
	mps = append(mps, ret.XDPJumpMap)

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
