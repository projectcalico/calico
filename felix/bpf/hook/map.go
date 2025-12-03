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
	"maps"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	bpfmaps "github.com/projectcalico/calico/felix/bpf/maps"
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
	SubProgIPFrag
	SubProgMaglev
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
	"calico_tc_skb_ipv4_frag",
	"calico_tc_maglev",
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
	*bpfmaps.PinnedMap

	programsLock sync.Mutex
	programs     map[AttachType]*program

	expectedAttachType string
	nextIdx            atomic.Int64
}

type program struct {
	lock   sync.Mutex
	layout Layout
}

var IngressProgramsMapParameters = bpfmaps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: maxPrograms,
	Name:       "cali_progs_ing",
	Version:    2,
}

var EgressProgramsMapParameters = bpfmaps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: maxPrograms,
	Name:       "cali_progs_egr",
	Version:    2,
}

func NewProgramsMaps() []bpfmaps.Map {
	return []bpfmaps.Map{
		NewIngressProgramsMap(),
		NewEgressProgramsMap(),
	}
}

func NewIngressProgramsMap() bpfmaps.Map {
	return newProgramsMap(IngressProgramsMapParameters, "ingress")
}

func NewEgressProgramsMap() bpfmaps.Map {
	return newProgramsMap(EgressProgramsMapParameters, "egress")
}

func newProgramsMap(ProgramsMapParameters bpfmaps.MapParameters, expectedAttachType string) bpfmaps.Map {
	return &ProgramsMap{
		PinnedMap:          bpfmaps.NewPinnedMap(ProgramsMapParameters),
		programs:           make(map[AttachType]*program),
		expectedAttachType: expectedAttachType,
	}
}

func NewXDPProgramsMap() bpfmaps.Map {
	return &ProgramsMap{
		PinnedMap: bpfmaps.NewPinnedMap(bpfmaps.MapParameters{
			Type:       "prog_array",
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: maxPrograms,
			Name:       "xdp_cali_progs",
			Version:    3,
		}),
		programs: make(map[AttachType]*program),
	}
}

func (pm *ProgramsMap) LoadObj(at AttachType, progType string) (Layout, error) {
	file := ObjectFile(at)
	if file == "" {
		return nil, fmt.Errorf("no object for attach type %+v", at)
	}
	log.WithField("AttachType", at).Debugf("Looked up file for attach type: %s", file)

	pi := pm.getOrCreateProgramInfo(at)

	// Loading is protected by the program lock to ensure that we do not
	// load the same object multiple times in parallel.  Two goroutines may
	// reach here before the program is loaded.  We check pi.layout to see if
	// we're first.
	pi.lock.Lock()
	defer pi.lock.Unlock()

	var err error
	if pi.layout == nil {
		la, err := pm.loadObj(at, path.Join(bpfdefs.ObjectDir, file), progType)
		if err != nil && strings.Contains(file, "_co-re") {
			log.WithError(err).Warn("Failed to load CO-RE object, kernel too old? Falling back to non-CO-RE.")
			file := strings.ReplaceAll(file, "_co-re", "")
			// Skip trying the same file again, as it will fail with the same error.
			SetObjectFile(at, file)
			la, err = pm.loadObj(at, path.Join(bpfdefs.ObjectDir, file), progType)
		}
		if err == nil {
			log.WithField("layout", la).Debugf("Loaded generic object file %s", file)
			pi.layout = la
		}
	} else {
		log.WithField("layout", pi.layout).Debugf("Using cached layout for %s", file)
	}

	// Return a clone of the layout to avoid accidental modifications.
	return maps.Clone(pi.layout), err
}

func (pm *ProgramsMap) getOrCreateProgramInfo(at AttachType) *program {
	pm.programsLock.Lock()
	defer pm.programsLock.Unlock()
	pi, ok := pm.programs[at]
	if !ok {
		pi = &program{}
		pm.programs[at] = pi
	}
	return pi
}

func (pm *ProgramsMap) loadObj(at AttachType, file, progAttachType string) (Layout, error) {
	obj, err := libbpf.OpenObject(file)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", file, err)
	}

	if err := pm.configureMapsAndPrograms(obj, file, progAttachType); err != nil {
		return nil, err
	}

	if !at.hasIPDefrag() {
		// Disable autoload for the IP defrag program
		obj.SetProgramAutoload("calico_tc_skb_ipv4_frag", false)
	}
	skipIPDefrag := false
	if err := obj.Load(); err != nil {
		// If load fails and this attach type has IP defrag, try loading without the IP defrag program
		if at.hasIPDefrag() {
			log.WithError(err).Warn("Failed to load object with IP defrag program, retrying without it")
			// Close the failed object and reopen
			obj.Close()
			obj, err = libbpf.OpenObject(file)
			if err != nil {
				return nil, fmt.Errorf("file %s: %w", file, err)
			}

			// Re-configure maps
			if err := pm.configureMapsAndPrograms(obj, file, progAttachType); err != nil {
				return nil, err
			}

			// Disable autoload for the IP defrag program
			obj.SetProgramAutoload("calico_tc_skb_ipv4_frag", false)
			skipIPDefrag = true

			// Try loading again
			if err := obj.Load(); err != nil {
				return nil, fmt.Errorf("error loading program: %w", err)
			}
			log.WithField("attach type", at).
				Warn("Object loaded without IP defrag - processing of fragmented packets will not be supported")
		} else {
			return nil, fmt.Errorf("error loading program: %w", err)
		}
	}

	layout, err := pm.allocateLayout(at, obj, skipIPDefrag)
	log.WithError(err).WithField("layout", layout).Debugf("load generic object file %s", file)

	return layout, err
}

func (pm *ProgramsMap) configureMapsAndPrograms(obj *libbpf.Obj, file, progAttachType string) error {
	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		mapName := m.Name()
		if strings.Contains(mapName, ".rodata") {
			continue
		}

		if err := pm.setMapSize(m); err != nil {
			return fmt.Errorf("error setting map size %s : %w", mapName, err)
		}
		if err := m.SetPinPath(path.Join(bpfdefs.GlobalPinDir, mapName)); err != nil {
			return fmt.Errorf("error pinning map %s: %w", mapName, err)
		}
		log.Debugf("map %s k %d v %d pinned to %s for generic object file %s",
			mapName, m.KeySize(), m.ValueSize(), path.Join(bpfdefs.GlobalPinDir, mapName), file)
	}

	if progAttachType == "TCX" {
		for prog, err := obj.FirstProgram(); prog != nil && err == nil; prog, err = prog.NextProgram() {
			attachType := libbpf.AttachTypeTcxEgress
			if pm.expectedAttachType == "ingress" {
				attachType = libbpf.AttachTypeTcxIngress
			}
			if err := obj.SetAttachType(prog.Name(), attachType); err != nil {
				return fmt.Errorf("error setting attach type for program %s: %w", prog.Name(), err)
			}
		}
	}

	return nil
}

func (pm *ProgramsMap) setMapSize(m *libbpf.Map) error {
	if size := bpfmaps.Size(m.Name()); size != 0 {
		return m.SetSize(size)
	}
	return nil
}

func (pm *ProgramsMap) allocateLayout(at AttachType, obj *libbpf.Obj, skipIPDefrag bool) (Layout, error) {
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

		if SubProg(idx) == SubProgIPFrag && (!at.hasIPDefrag() || skipIPDefrag) {
			continue
		}

		if SubProg(idx) == SubProgMaglev && !at.hasMaglev() {
			continue
		}

		pmIdx := pm.allocIdx()
		err := obj.UpdateJumpMap(mapName, subprog, pmIdx)
		if err != nil {
			return nil, fmt.Errorf("error updating programs map with %s/%s at %d: %w",
				ObjectFile(at), subprog, pmIdx, err)
		}
		log.Debugf("generic file %s prog %s loaded at %d", ObjectFile(at), subprog, pmIdx)

		i := idx + offset
		if SubProg(idx) == SubProgTCPolicy {
			i = idx // Debug programs share the same policy
		}
		l[SubProg(i)] = pmIdx
	}

	return l, nil
}

func (pm *ProgramsMap) allocIdx() int {
	for {
		idx := pm.nextIdx.Load()
		if pm.nextIdx.CompareAndSwap(idx, idx+1) {
			return int(idx)
		}
	}
}

// Count returns how many slots are allocated.
func (pm *ProgramsMap) Count() int {
	pm.programsLock.Lock()
	defer pm.programsLock.Unlock()

	return int(pm.nextIdx.Load())
}

// ResetForTesting for unit testing only.
func (pm *ProgramsMap) ResetForTesting() {
	pm.programsLock.Lock()
	defer pm.programsLock.Unlock()

	// We keep the same pinned map but reset the accounting as the map is
	// replaced by repinning by the user.
	pm.nextIdx.Store(0)
	pm.programs = make(map[AttachType]*program)
}

func (pm *ProgramsMap) Programs() map[AttachType]Layout {
	pm.programsLock.Lock()
	defer pm.programsLock.Unlock()

	progs := make(map[AttachType]Layout, len(pm.programs))
	for at, prog := range pm.programs {
		progs[at] = prog.layout
	}

	return progs
}
