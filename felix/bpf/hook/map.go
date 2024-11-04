// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package hook

import (
	"fmt"
	"path"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

const maxPrograms = 400

type SubProg int

const (
	SubProgTCMain SubProg = iota
	SubProgTCPolicy
	SubProgTCAllowed
	SubProgTCIcmp
	SubProgTCDrop
	SubProgTCHostCtConflict
	SubProgIcmpInnerNat
	SubProgNewFlow
	SubProgTCMainDebug

	SubProgXDPMain    = SubProgTCMain
	SubProgXDPPolicy  = SubProgTCPolicy
	SubProgXDPAllowed = SubProgTCAllowed
	SubProgXDPDrop    = SubProgTCDrop
)

var tcSubProgNames = []string{
	"calico_tc_main",
	"", // index reserved for policy program
	"calico_tc_skb_accepted_entrypoint",
	"calico_tc_skb_send_icmp_replies",
	"calico_tc_skb_drop",
	"calico_tc_host_ct_conflict",
	"calico_tc_skb_icmp_inner_nat",
	"calico_tc_skb_new_flow_entrypoint",
}

var xdpSubProgNames = []string{
	"calico_xdp_main",
	"", // index reserved for policy program
	"calico_xdp_accepted_entrypoint",
	"", // reserved / nothing
	"calico_xdp_drop",
}

// Layout maps sub-programs of an object to their location in the ProgramsMap
type Layout map[SubProg]int

func MergeLayouts(layouts ...Layout) Layout {
	ret := make(Layout)

	for _, l := range layouts {
		for k, v := range l {
			ret[k] = v
		}
	}

	return ret
}

type ProgramsMap struct {
	lock sync.Mutex
	*maps.PinnedMap
	nextIdx  int
	programs map[AttachType]Layout
}

var ProgramsMapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: maxPrograms,
	Name:       "cali_progs",
	Version:    3,
}

func NewProgramsMap() maps.Map {
	return &ProgramsMap{
		PinnedMap: maps.NewPinnedMap(ProgramsMapParameters),
		programs:  make(map[AttachType]Layout),
	}
}

func NewXDPProgramsMap() maps.Map {
	return &ProgramsMap{
		PinnedMap: maps.NewPinnedMap(maps.MapParameters{
			Type:       "prog_array",
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: maxPrograms,
			Name:       "xdp_cali_progs",
			Version:    3,
		}),
		programs: make(map[AttachType]Layout),
	}
}

func (pm *ProgramsMap) LoadObj(at AttachType) (Layout, error) {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	file, ok := objectFiles[at]
	if !ok {
		return nil, fmt.Errorf("no object for attach type %+v", at)
	}
	log.WithField("AttachType", at).Debugf("needs generic object file %s", file)

	if l, ok := pm.programs[at]; ok {
		log.WithField("layout", l).Debugf("generic object file already loaded %s", file)
		return MergeLayouts(l), nil // MergeLayouts triggers a copy
	}

	return pm.loadObj(at, path.Join(bpfdefs.ObjectDir, file))
}

func (pm *ProgramsMap) loadObj(at AttachType, file string) (Layout, error) {
	obj, err := libbpf.OpenObject(file)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", file, err)
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		mapName := m.Name()
		if strings.Contains(mapName, ".rodata") {
			continue
		}

		if err := pm.setMapSize(m); err != nil {
			return nil, fmt.Errorf("error setting map size %s : %w", mapName, err)
		}
		if err := m.SetPinPath(path.Join(bpfdefs.GlobalPinDir, mapName)); err != nil {
			return nil, fmt.Errorf("error pinning map %s: %w", mapName, err)
		}
		log.Debugf("map %s k %d v %d pinned to %s for generic object file %s",
			mapName, m.KeySize(), m.ValueSize(), path.Join(bpfdefs.GlobalPinDir, mapName), file)
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("error loading program: %w", err)
	}

	layout, err := pm.newLayout(at, obj)
	log.WithError(err).WithField("layout", layout).Debugf("load generic object file %s", file)

	return MergeLayouts(layout), err // MergeLayouts triggers a copy
}

func (pm *ProgramsMap) setMapSize(m *libbpf.Map) error {
	if size := maps.Size(m.Name()); size != 0 {
		return m.SetSize(size)
	}
	return nil
}

func (pm *ProgramsMap) newLayout(at AttachType, obj *libbpf.Obj) (Layout, error) {
	mapName := pm.GetName()

	l := make(Layout)

	offset := 0
	subs := tcSubProgNames
	if at.Hook == XDP {
		subs = xdpSubProgNames
	} else if at.LogLevel == "debug" {
		offset = int(SubProgTCMainDebug)
	}

	for idx, subprog := range subs {
		if subprog == "" {
			continue
		}

		if SubProg(idx) == SubProgTCHostCtConflict && !at.hasHostConflictProg() {
			continue
		}

		err := obj.UpdateJumpMap(mapName, subprog, pm.nextIdx)
		if err != nil {
			return nil, fmt.Errorf("error updating programs map with %s/%s at %d: %w",
				objectFiles[at], subprog, pm.nextIdx, err)
		}
		log.Debugf("generic file %s prog %s loaded at %d", objectFiles[at], subprog, pm.nextIdx)

		i := idx + offset
		if SubProg(idx) == SubProgTCPolicy {
			i = idx // Debug programs share the same policy
		}
		l[SubProg(i)] = pm.nextIdx
		pm.nextIdx++
	}

	pm.programs[at] = l

	return l, nil
}

// Count returns how many slots are allocated.
func (pm *ProgramsMap) Count() int {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	return pm.nextIdx
}

// ResetCount for unittesting only.
func (pm *ProgramsMap) ResetCount() {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	// We keep the same pinned map but reset the accounting as the map is
	// replaced by repinning by the user.
	pm.nextIdx = 0
	pm.programs = make(map[AttachType]Layout)
}

func (pm *ProgramsMap) Programs() map[AttachType]Layout {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	return pm.programs
}
