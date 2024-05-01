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

// #cgo CFLAGS: -I${SRCDIR}/../../bpf-gpl/include/libbpf/src -I${SRCDIR}/../../bpf-gpl/include/libbpf/include/uapi -I${SRCDIR}/../../bpf-gpl -Werror
// #cgo amd64 LDFLAGS: -L${SRCDIR}/../../bpf-gpl/include/libbpf/src/amd64 -lbpf -lelf -lz
// #cgo arm64 LDFLAGS: -L${SRCDIR}/../../bpf-gpl/include/libbpf/src/arm64 -lbpf -lelf -lz
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

func (m *Map) ValueSize() int {
	return int(C.bpf_map__value_size(m.bpfMap))
}

func (m *Map) KeySize() int {
	return int(C.bpf_map__key_size(m.bpfMap))
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

func (m *Map) MaxEntries() int {
	return int(C.bpf_map__max_entries(m.bpfMap))
}

func (m *Map) SetSize(size int) error {
	_, err := C.bpf_map_set_max_entries(m.bpfMap, C.uint(size))
	if err != nil {
		return fmt.Errorf("setting %s map size failed %w", m.Name(), err)
	}
	return nil
}

func (m *Map) IsMapInternal() bool {
	return bool(C.bpf_map__is_internal(m.bpfMap))
}

func (m *Map) IsJumpMap() bool {
	return m.Type() == int(C.BPF_MAP_TYPE_PROG_ARRAY)
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
	bpfMap, err := C.bpf_object__next_map(o.obj, nil)
	if bpfMap == nil || err != nil {
		return nil, fmt.Errorf("error getting first map %w", err)
	}
	return &Map{bpfMap: bpfMap, bpfObj: o.obj}, nil
}

// NextMap returns the successive maps given the first map.
// Returns nil, no error at the end of the list.
func (m *Map) NextMap() (*Map, error) {
	bpfMap, err := C.bpf_object__next_map(m.bpfObj, m.bpfMap)
	if err != nil {
		return nil, fmt.Errorf("error getting next map %w", err)
	}
	if bpfMap == nil {
		return nil, nil
	}
	return &Map{bpfMap: bpfMap, bpfObj: m.bpfObj}, nil
}

func (o *Obj) ProgramFD(secname string) (int, error) {
	cSecName := C.CString(secname)
	defer C.free(unsafe.Pointer(cSecName))

	ret, err := C.bpf_program_fd(o.obj, cSecName)
	if err != nil {
		return -1, fmt.Errorf("error finding program %s: %w", secname, err)
	}

	return int(ret), nil
}

func QueryClassifier(ifindex, handle, pref int, ingress bool) (int, error) {
	opts, err := C.bpf_tc_program_query(C.int(ifindex), C.int(handle), C.int(pref), C.bool(ingress))

	return int(opts.prog_id), err
}

func DetachClassifier(ifindex, handle, pref int, ingress bool) error {
	_, err := C.bpf_tc_program_detach(C.int(ifindex), C.int(handle), C.int(pref), C.bool(ingress))

	return err
}

// AttachClassifier return the program id and pref and handle of the qdisc
func (o *Obj) AttachClassifier(secName, ifName string, ingress bool) (int, int, int, error) {
	cSecName := C.CString(secName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cSecName))
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return -1, -1, -1, err
	}

	ret, err := C.bpf_tc_program_attach(o.obj, cSecName, C.int(ifIndex), C.bool(ingress))
	if err != nil {
		return -1, -1, -1, fmt.Errorf("error attaching tc program %w", err)
	}

	return int(ret.prog_id), int(ret.priority), int(ret.handle), nil
}

func (o *Obj) AttachXDP(ifName, progName string, oldID int, mode uint) (int, error) {
	cProgName := C.CString(progName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cProgName))
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return -1, err
	}

	_, err = C.bpf_program_attach_xdp(o.obj, cProgName, C.int(ifIndex), C.int(oldID), C.uint(mode))
	if err != nil {
		return -1, fmt.Errorf("error attaching xdp program: %w", err)
	}

	progId, err := C.bpf_xdp_program_id(C.int(ifIndex))
	if err != nil {
		return -1, fmt.Errorf("error querying xdp information. interface %s: %w", ifName, err)
	}
	return int(progId), nil
}

func (o *Obj) Pin(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	errno := C.bpf_object__pin(o.obj, cPath)
	if errno != 0 {
		err := syscall.Errno(errno)
		return fmt.Errorf("pinning programs failed %w", err)
	}
	return nil
}

func (o *Obj) Unpin(path string) error {
	return unix.Unlink(path)
}

func (o *Obj) PinPrograms(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	errno := C.bpf_object__pin_programs(o.obj, cPath)
	if errno != 0 {
		err := syscall.Errno(errno)
		return fmt.Errorf("pinning programs failed %w", err)
	}
	return nil
}

func (o *Obj) UnpinPrograms(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	errno := C.bpf_object__unpin_programs(o.obj, cPath)
	if errno != 0 {
		err := syscall.Errno(errno)
		return fmt.Errorf("pinning programs failed %w", err)
	}
	return nil
}

func (o *Obj) PinMaps(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	errno := C.bpf_object__pin_maps(o.obj, cPath)
	if errno != 0 {
		err := syscall.Errno(errno)
		return fmt.Errorf("pinning maps failed %w", err)
	}
	return nil
}

func DetachXDP(ifName string, mode uint) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return err
	}

	errno := C.bpf_xdp_detach(C.int(ifIndex), C.uint(mode), nil)
	if errno != 0 {
		err := syscall.Errno(errno)
		return fmt.Errorf("failed to detach xdp program. interface %s: %w", ifName, err)
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
		return -1, fmt.Errorf("error querying xdp information. interface %s: %w", ifName, err)
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
		return fmt.Errorf("creating qdisc %w", err)
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
		return fmt.Errorf("removing qdisc %w", err)
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
		return fmt.Errorf("updating %s at index %d: %w", mapName, mapIndex, err)
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
	GlobalsRPFOptionEnabled uint32 = C.CALI_GLOBALS_RPF_OPTION_ENABLED
	GlobalsRPFOptionStrict  uint32 = C.CALI_GLOBALS_RPF_OPTION_STRICT
	GlobalsNoDSRCidrs       uint32 = C.CALI_GLOBALS_NO_DSR_CIDRS
	GlobalsLoUDPOnly        uint32 = C.CALI_GLOBALS_LO_UDP_ONLY
)

func TcSetGlobals(
	m *Map,
	globalData *TcGlobalData,
) error {

	cName := C.CString(globalData.IfaceName)
	defer C.free(unsafe.Pointer(cName))

	cJumps := make([]C.uint, len(globalData.Jumps))

	for i, v := range globalData.Jumps {
		cJumps[i] = C.uint(v)
	}

	cJumpsV6 := make([]C.uint, len(globalData.JumpsV6))

	for i, v := range globalData.JumpsV6 {
		cJumpsV6[i] = C.uint(v)
	}

	_, err := C.bpf_tc_set_globals(m.bpfMap,
		cName,
		(*C.char)(unsafe.Pointer(&globalData.HostIPv4[0])),
		(*C.char)(unsafe.Pointer(&globalData.IntfIPv4[0])),
		(*C.char)(unsafe.Pointer(&globalData.HostIPv6[0])),
		(*C.char)(unsafe.Pointer(&globalData.IntfIPv6[0])),
		C.uint(globalData.ExtToSvcMark),
		C.ushort(globalData.Tmtu),
		C.ushort(globalData.VxlanPort),
		C.ushort(globalData.PSNatStart),
		C.ushort(globalData.PSNatLen),
		(*C.char)(unsafe.Pointer(&globalData.HostTunnelIPv4[0])),
		(*C.char)(unsafe.Pointer(&globalData.HostTunnelIPv6[0])),
		C.uint(globalData.Flags),
		C.ushort(globalData.WgPort),
		C.ushort(globalData.Wg6Port),
		C.uint(globalData.NatIn),
		C.uint(globalData.NatOut),
		C.uint(globalData.LogFilterJmp),
		&cJumps[0], // it is safe because we hold the reference here until we return.
		&cJumpsV6[0],
	)

	return err
}

func CTLBSetGlobals(m *Map, udpNotSeen time.Duration, excludeUDP bool) error {
	udpNotSeen /= time.Second // Convert to seconds
	_, err := C.bpf_ctlb_set_globals(m.bpfMap, C.uint(udpNotSeen), C.bool(excludeUDP))

	return err
}

func XDPSetGlobals(
	m *Map,
	globalData *XDPGlobalData,
) error {

	cName := C.CString(globalData.IfaceName)
	defer C.free(unsafe.Pointer(cName))

	cJumps := make([]C.uint, len(globalData.Jumps))
	cJumpsV6 := make([]C.uint, len(globalData.Jumps))

	for i, v := range globalData.Jumps {
		cJumps[i] = C.uint(v)
	}

	for i, v := range globalData.JumpsV6 {
		cJumpsV6[i] = C.uint(v)
	}
	_, err := C.bpf_xdp_set_globals(m.bpfMap,
		cName,
		&cJumps[0],
		&cJumpsV6[0],
	)

	return err
}

func NumPossibleCPUs() (int, error) {
	ncpus := int(C.num_possible_cpu())
	if ncpus < 0 {
		return ncpus, fmt.Errorf("Invalid number of CPUs: %d", ncpus)
	}
	return ncpus, nil
}

func ObjPin(fd int, path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	_, err := C.bpf_obj_pin(C.int(fd), cPath)

	return err
}

func ObjGet(path string) (int, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	fd, err := C.bpf_obj_get(cPath)

	return int(fd), err
}
