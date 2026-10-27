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
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/allowsources"
	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/ipfrags"
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
	IpsetsMap       maps.Map
	ArpMap          maps.Map
	FailsafesMap    maps.Map
	FrontendMap     maps.Map
	BackendMap      maps.Map
	AffinityMap     maps.Map
	RouteMap        maps.Map
	CtMap           maps.Map
	SrMsgMap        maps.Map
	CtNatsMap       maps.Map
	CtCleanupMap    maps.Map
	MaglevMap       maps.Map
	IPFragMap       maps.Map
	IPFragFwdMap    maps.Map
	AllowSourcesMap maps.Map
}

type CommonMaps struct {
	StateMap         maps.Map
	IfStateMap       maps.Map
	RuleCountersMap  maps.Map
	CountersMap      maps.Map
	ProgramsMaps     []maps.Map
	JumpMaps         []maps.MapWithDeleteIfExists
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
	for _, m := range m.pinned() {
		os.Remove(m.Path())
		m.Close()
	}
}

// Close closes every map and keeps the pins.
func (m *Maps) Close() {
	for _, m := range m.pinned() {
		m.Close()
	}
}

func (m *Maps) pinned() []pinnedMap {
	mps := []maps.Map{}
	mps = append(mps, m.CommonMaps.slice()...)
	mps = append(mps, m.V4.slice()...)
	if m.V6 != nil {
		mps = append(mps, m.V6.slice()...)
	}
	ret := make([]pinnedMap, 0, len(mps))
	for _, m := range mps {
		ret = append(ret, m.(pinnedMap))
	}
	return ret
}

func getCommonMaps() *CommonMaps {
	commonMaps := &CommonMaps{
		StateMap:         state.Map(),
		IfStateMap:       ifstate.Map(),
		RuleCountersMap:  counters.PolicyMap(),
		CountersMap:      counters.Map(),
		ProgramsMaps:     hook.NewProgramsMaps(),
		XDPProgramsMap:   hook.NewXDPProgramsMap(),
		XDPJumpMap:       jump.XDPMap().(maps.MapWithDeleteIfExists),
		ProfilingMap:     profiling.Map(),
		CTLBProgramsMaps: nat.ProgramsMaps(),
		QoSMap:           qos.Map().(maps.MapWithUpdateWithFlags),
	}
	jumpMaps := jump.Maps()
	for _, jm := range jumpMaps {
		commonMaps.JumpMaps = append(commonMaps.JumpMaps, jm.(maps.MapWithDeleteIfExists))
	}
	return commonMaps
}

func getIPMaps(ipFamily int) *IPMaps {
	getmap := func(v4, v6 func() maps.Map) maps.Map {
		if ipFamily == 4 {
			return v4()
		}
		if v6 == nil {
			return nil
		}
		return v6()
	}

	getmapWithExistsCheck := func(v4, v6 func() maps.MapWithExistsCheck) maps.MapWithExistsCheck {
		if ipFamily == 4 {
			return v4()
		}
		if v6 == nil {
			return nil
		}
		return v6()
	}

	return &IPMaps{
		IpsetsMap:       getmap(ipsets.Map, ipsets.MapV6),
		ArpMap:          getmap(arp.Map, arp.MapV6),
		FailsafesMap:    getmap(failsafes.Map, failsafes.MapV6),
		FrontendMap:     getmapWithExistsCheck(nat.FrontendMap, nat.FrontendMapV6),
		BackendMap:      getmapWithExistsCheck(nat.BackendMap, nat.BackendMapV6),
		AffinityMap:     getmap(nat.AffinityMap, nat.AffinityMapV6),
		RouteMap:        getmap(routes.Map, routes.MapV6),
		CtMap:           getmap(conntrack.Map, conntrack.MapV6),
		CtCleanupMap:    getmapWithExistsCheck(conntrack.CleanupMap, conntrack.CleanupMapV6),
		SrMsgMap:        getmap(nat.SendRecvMsgMap, nat.SendRecvMsgMapV6),
		CtNatsMap:       getmap(nat.AllNATsMsgMap, nat.AllNATsMsgMapV6),
		MaglevMap:       getmapWithExistsCheck(nat.MaglevMap, nat.MaglevMapV6),
		IPFragMap:       getmap(ipfrags.Map, nil),
		IPFragFwdMap:    getmap(ipfrags.FwdMap, nil),
		AllowSourcesMap: getmap(allowsources.Map, allowsources.MapV6),
	}
}

func newMaps(ipV6Enabled bool) *Maps {
	ret := new(Maps)

	ret.CommonMaps = getCommonMaps()
	ret.V4 = getIPMaps(4)
	if ipV6Enabled {
		ret.V6 = getIPMaps(6)
	}
	return ret
}

// CreateBPFMapsKeepingPinnedSizes is CreateBPFMaps for processes other than Felix, which owns the map sizes.
func CreateBPFMapsKeepingPinnedSizes(ipV6Enabled bool) (*Maps, error) {
	keepPinnedSizes(ipV6Enabled)
	return CreateBPFMaps(ipV6Enabled)
}

// keepPinnedSizes registers the size of each pinned map, which NewPinnedMap then uses.
func keepPinnedSizes(ipV6Enabled bool) {
	for _, m := range newMaps(ipV6Enabled).slice() {
		pm, ok := m.(*maps.PinnedMap)
		if !ok {
			continue
		}
		// EnsureExists restores an interrupted migration's _old map, so that is the map to size.
		path := pm.Path()
		if _, err := os.Stat(path + "_old"); err == nil {
			path += "_old"
		}
		logCtx := log.WithField("name", pm.GetName())
		fd, err := maps.GetMapFDByPin(path)
		if errors.Is(err, os.ErrNotExist) {
			logCtx.Debug("No pinned map, creating it at the default size.")
			continue
		} else if err != nil {
			logCtx.WithError(err).Warn("Failed to open the pinned map, its size may be reset to the default.")
			continue
		}
		info, err := maps.GetMapInfo(fd)
		_ = fd.Close()
		if err != nil {
			logCtx.WithError(err).Warn("Failed to read the pinned map's size, its size may be reset to the default.")
			continue
		}
		if info.KeySize != pm.KeySize || info.ValueSize != pm.ValueSize {
			logCtx.Debug("Pinned map has a different key or value size, it will be recreated.")
			continue
		}
		maps.SetSize(pm.GetName(), info.MaxEntries)
	}
}

func CreateBPFMaps(ipV6Enabled bool) (*Maps, error) {
	ret := newMaps(ipV6Enabled)

	mps := ret.slice()
	for i, bpfMap := range mps {
		if bpfMap == nil {
			continue
		}
		err := bpfMap.EnsureExists()
		if err != nil {
			for j := range i {
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
		c.XDPProgramsMap,
		c.XDPJumpMap,
		c.ProfilingMap,
		c.QoSMap,
	}
	mapslice = append(mapslice, c.ProgramsMaps...)
	mapslice = append(mapslice, c.CTLBProgramsMaps...)
	for _, m := range c.JumpMaps {
		mapslice = append(mapslice, m)
	}
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
		i.IPFragMap,
		i.IPFragFwdMap,
		i.AllowSourcesMap,
	}
}

type pinnedMap interface {
	Path() string
	Close() error
}
