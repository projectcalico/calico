// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

package libbpf

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/bpfutils"
)

// #include "libbpf_api.h"
import "C"

type Obj struct {
	obj *C.struct_bpf_object
}

type Map struct {
	bpfMap *C.struct_bpf_map
	bpfObj *C.struct_bpf_object
}

type QdiskHook string

const (
	QdiskIngress QdiskHook = "ingress"
	QdiskEgress  QdiskHook = "egress"
)

func (m *Map) Name() string {
	name := C.bpf_map__name(m.bpfMap)
	if name == nil {
		return ""
	}
	return C.GoString(name)
}

func (m *Map) Type() int {
	mapType := C.bpf_map__type(m.bpfMap)
	return int(mapType)
}

func (m *Map) SetPinPath(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	errno := C.bpf_map__set_pin_path(m.bpfMap, cPath)
	if errno != 0 {
		err := syscall.Errno(errno)
		return fmt.Errorf("pinning map failed %w", err)
	}
	return nil
}

func (m *Map) SetMapSize(size uint32) error {
	_, err := C.bpf_map_set_max_entries(m.bpfMap, C.uint(size))
	if err != nil {
		return fmt.Errorf("setting %s map size failed %w", m.Name(), err)
	}
	return nil
}

func (m *Map) IsMapInternal() bool {
	return bool(C.bpf_map__is_internal(m.bpfMap))
}

func OpenObject(filename string) (*Obj, error) {
	bpfutils.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	obj, err := C.bpf_obj_open(cFilename)
	if obj == nil || err != nil {
		return nil, fmt.Errorf("error opening libbpf object %w", err)
	}
	return &Obj{obj: obj}, nil
}

func (o *Obj) Load() error {
	_, err := C.bpf_obj_load(o.obj)
	if err != nil {
		return fmt.Errorf("error loading object %w", err)
	}
	return nil
}

// FirstMap returns first bpf map of the object.
// Returns error if the map is nil.
func (o *Obj) FirstMap() (*Map, error) {
	bpfMap, err := C.bpf_map__next(nil, o.obj)
	if bpfMap == nil || err != nil {
		return nil, fmt.Errorf("error getting first map %w", err)
	}
	return &Map{bpfMap: bpfMap, bpfObj: o.obj}, nil
}

// NextMap returns the successive maps given the first map.
// Returns nil, no error at the end of the list.
func (m *Map) NextMap() (*Map, error) {
	bpfMap, err := C.bpf_map__next(m.bpfMap, m.bpfObj)
	if err != nil {
		return nil, fmt.Errorf("error getting next map %w", err)
	}
	if bpfMap == nil {
		return nil, nil
	}
	return &Map{bpfMap: bpfMap, bpfObj: m.bpfObj}, nil
}

func (o *Obj) AttachClassifier(secName, ifName, hook string) (int, error) {
	isIngress := 0
	cSecName := C.CString(secName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cSecName))
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return -1, err
	}

	if hook == string(QdiskIngress) {
		isIngress = 1
	}

	opts, err := C.bpf_tc_program_attach(o.obj, cSecName, C.int(ifIndex), C.int(isIngress))
	if err != nil {
		return -1, fmt.Errorf("Error attaching tc program %w", err)
	}

	progId, err := C.bpf_tc_query_iface(C.int(ifIndex), opts, C.int(isIngress))
	if err != nil {
		return -1, fmt.Errorf("Error querying interface %s: %w", ifName, err)
	}
	return int(progId), nil
}

func (o *Obj) AttachXDP(secName, ifName string) (int, error) {
	cSecName := C.CString(secName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cSecName))
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return -1, err
	}

	ret, err := C.bpf_program_attach_xdp(o.obj, cSecName, C.int(ifIndex), unix.XDP_FLAGS_UPDATE_IF_NOEXIST|unix.XDP_FLAGS_SKB_MODE)
	if err != nil {
		return -1, fmt.Errorf("Error attaching xdp program %w - ret: %v", err, ret)
	}

	progId, err := C.bpf_xdp_program_id(C.int(ifIndex))
	if err != nil {
		return -1, fmt.Errorf("Error querying xdp information. interface: %s err: %w", ifName, err)
	}
	return int(progId), nil
}

func DetachXDP(ifName string, progID int, mode uint) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return err
	}

	_, err = C.bpf_set_link_xdp_fd(C.int(ifIndex), -1, C.uint(mode))
	if err != nil {
		return fmt.Errorf("Failed to detach XDP program. interface: %s err: %w", ifName, err)
	}

	return nil
}

func GetXDPProgramID(ifName string) (int, error) {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return -1, err
	}
	progId, err := C.bpf_xdp_program_id(C.int(ifIndex))
	if err != nil {
		return -1, fmt.Errorf("Error querying xdp information. interface: %s err: %w", ifName, err)
	}
	return int(progId), nil
}

type Link struct {
	link *C.struct_bpf_link
}

func (l *Link) Close() error {
	if l.link != nil {
		err := C.bpf_link_destroy(l.link)
		if err != 0 {
			return fmt.Errorf("error destroying link: %v", err)
		}
		l.link = nil
		return nil
	}
	return fmt.Errorf("link nil")
}

func CreateQDisc(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return err
	}
	_, err = C.bpf_tc_create_qdisc(C.int(ifIndex))
	if err != nil {
		return fmt.Errorf("Error creating qdisc %w", err)
	}
	return nil
}

func RemoveQDisc(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return err
	}
	_, err = C.bpf_tc_remove_qdisc(C.int(ifIndex))
	if err != nil {
		return fmt.Errorf("Error removing qdisc %w", err)
	}
	return nil
}

func (o *Obj) UpdateJumpMap(mapName, progName string, mapIndex int) error {
	cMapName := C.CString(mapName)
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cMapName))
	defer C.free(unsafe.Pointer(cProgName))
	_, err := C.bpf_update_jump_map(o.obj, cMapName, cProgName, C.int(mapIndex))
	if err != nil {
		return fmt.Errorf("Error updating %s at index %d: %w", mapName, mapIndex, err)
	}
	return nil
}

func (o *Obj) Close() error {
	if o.obj != nil {
		C.bpf_object__close(o.obj)
		o.obj = nil
		return nil
	}
	return fmt.Errorf("error: libbpf obj nil")
}

func (o *Obj) AttachCGroup(cgroup, progName string) (*Link, error) {
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cProgName))

	f, err := os.OpenFile(cgroup, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to join cgroup %s: %w", cgroup, err)
	}
	defer f.Close()
	fd := int(f.Fd())

	link, err := C.bpf_program_attach_cgroup(o.obj, C.int(fd), cProgName)
	if err != nil {
		link = nil
		_, err2 := C.bpf_program_attach_cgroup_legacy(o.obj, C.int(fd), cProgName)
		if err2 != nil {
			return nil, fmt.Errorf("failed to attach %s to cgroup %s (legacy try %s): %w",
				progName, cgroup, err2, err)
		}
	}

	return &Link{link: link}, nil
}

const (
	// Set when IPv6 is enabled to configure bpf dataplane accordingly
	GlobalsIPv6Enabled      uint32 = C.CALI_GLOBALS_IPV6_ENABLED
	GlobalsRPFStrictEnabled uint32 = C.CALI_GLOBALS_RPF_STRICT_ENABLED
)

func TcSetGlobals(
	m *Map,
	hostIP uint32,
	intfIP uint32,
	extToSvcMark uint32,
	tmtu uint16,
	vxlanPort uint16,
	psNatStart uint16,
	psNatLen uint16,
	hostTunnelIP uint32,
	flags uint32,
	wgPort uint16,
) error {
	_, err := C.bpf_tc_set_globals(m.bpfMap,
		C.uint(hostIP),
		C.uint(intfIP),
		C.uint(extToSvcMark),
		C.ushort(tmtu),
		C.ushort(vxlanPort),
		C.ushort(psNatStart),
		C.ushort(psNatLen),
		C.uint(hostTunnelIP),
		C.uint(flags),
		C.ushort(wgPort),
	)

	return err
}

func CTLBSetGlobals(m *Map, udpNotSeen time.Duration) error {
	udpNotSeen /= time.Second // Convert to seconds
	_, err := C.bpf_ctlb_set_globals(m.bpfMap, C.uint(udpNotSeen))

	return err
}

func NumPossibleCPUs() (int, error) {
	ncpus := int(C.num_possible_cpu())
	if ncpus < 0 {
		return ncpus, fmt.Errorf("Invalid number of CPUs: %d", ncpus)
	}
	return ncpus, nil
}
