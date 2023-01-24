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

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
)

type Maps struct {
	IpsetsMap       bpf.Map
	StateMap        bpf.Map
	ArpMap          bpf.Map
	FailsafesMap    bpf.Map
	FrontendMap     bpf.Map
	BackendMap      bpf.Map
	AffinityMap     bpf.Map
	RouteMap        bpf.Map
	CtMap           bpf.Map
	SrMsgMap        bpf.Map
	CtNatsMap       bpf.Map
	IfStateMap      bpf.Map
	RuleCountersMap bpf.Map
	CountersMap     bpf.Map
}

func (m *Maps) Destroy() {
	maps := []bpf.Map{
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
	}

	for _, m := range maps {
		os.Remove(m.(*bpf.PinnedMap).Path())
		m.(*bpf.PinnedMap).Close()
	}
}

func CreateBPFMaps() (*Maps, error) {
	maps := []bpf.Map{}
	ret := new(Maps)

	ret.IpsetsMap = ipsets.Map()
	maps = append(maps, ret.IpsetsMap)

	ret.StateMap = state.Map()
	maps = append(maps, ret.StateMap)

	ret.ArpMap = arp.Map()
	maps = append(maps, ret.ArpMap)

	ret.FailsafesMap = failsafes.Map()
	maps = append(maps, ret.FailsafesMap)

	ret.FrontendMap = nat.FrontendMap()
	maps = append(maps, ret.FrontendMap)

	ret.BackendMap = nat.BackendMap()
	maps = append(maps, ret.BackendMap)

	ret.AffinityMap = nat.AffinityMap()
	maps = append(maps, ret.AffinityMap)

	ret.RouteMap = routes.Map()
	maps = append(maps, ret.RouteMap)

	ret.CtMap = conntrack.Map()
	maps = append(maps, ret.CtMap)

	ret.SrMsgMap = nat.SendRecvMsgMap()
	maps = append(maps, ret.SrMsgMap)

	ret.CtNatsMap = nat.AllNATsMsgMap()
	maps = append(maps, ret.CtNatsMap)

	ret.IfStateMap = ifstate.Map()
	maps = append(maps, ret.IfStateMap)

	ret.RuleCountersMap = counters.PolicyMap()
	maps = append(maps, ret.RuleCountersMap)

	ret.CountersMap = counters.Map()
	maps = append(maps, ret.CountersMap)

	for i, bpfMap := range maps {
		err := bpfMap.EnsureExists()
		if err != nil {

			for j := 0; j < i; j++ {
				m := maps[j]
				os.Remove(m.(*bpf.PinnedMap).Path())
				m.(*bpf.PinnedMap).Close()
			}

			return nil, fmt.Errorf("failed to create %s map, err=%w", bpfMap.GetName(), err)
		}
	}

	return ret, nil
}
