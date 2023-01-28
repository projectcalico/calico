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

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

const maxPrograms = 200

type SubProg int

const (
	SubProgTCMain SubProg = iota
	SubProgTCPolicy
	SubProgTCAllowed
	SubProgTCIcmp
	SubProgTCDrop
	SubProgTCHostCtConflict
)

var tcSubProgNames = []string{
	"calico_tc_main",
	"", // index reserved for policy program
	"calico_tc_skb_accepted_entrypoint",
	"calico_tc_skb_send_icmp_replies",
	"calico_tc_skb_drop",
	"calico_tc_host_ct_conflict",
}

// Layout maps sub-programs of an object to their location in the ProgramsMap
type Layout map[SubProg]int

type ProgramsMap struct {
	*maps.PinnedMap
	nextIdx  int
	programs map[AttachType]Layout
}

func NewProgramsMap() maps.Map {
	return &ProgramsMap{
		PinnedMap: maps.NewPinnedMap(maps.MapParameters{
			Type:       "prog_array",
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: maxPrograms,
			Name:       "cali_progs",
			Version:    2,
		}),
	}
}

func (pm *ProgramsMap) LoadObj(at AttachType) (Layout, error) {
	file, ok := objectFiles[at]
	if !ok {
		return nil, fmt.Errorf("no object for attach type %+v", at)
	}

	if l, ok := pm.programs[at]; ok {
		return l, nil
	}

	return pm.loadObj(at, path.Join(bpfdefs.ObjectDir, file))
}

func (pm *ProgramsMap) loadObj(at AttachType, file string) (Layout, error) {
	obj, err := libbpf.OpenObject(file)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", file, err)
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		if err := pm.setMapSize(m); err != nil {
			return nil, fmt.Errorf("error setting map size %s : %w", m.Name(), err)
		}
		if err := m.SetPinPath(path.Join(bpfdefs.GlobalPinDir, m.Name())); err != nil {
			return nil, fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("error loading program: %w", err)
	}

	return pm.newLayout(at, obj)
}

func (pm *ProgramsMap) setMapSize(m *libbpf.Map) error {
	if size := maps.Size(m.Name()); size != 0 {
		return m.SetSize(size)
	}
	return nil
}

func (pm *ProgramsMap) newLayout(at AttachType, obj *libbpf.Obj) (Layout, error) {
	if at.Family == 6 {
		return nil, fmt.Errorf("IPv6 is not supported")
	}

	mapName := pm.GetName()

	l := make(Layout)

	for idx, subprog := range tcSubProgNames {
		if SubProg(idx) == SubProgTCPolicy {
			// normal policies are also loaded into the policy map
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

		l[SubProg(idx)] = pm.nextIdx
		pm.nextIdx++
	}

	return l, nil
}
