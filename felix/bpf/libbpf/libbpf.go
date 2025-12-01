// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/utils"
)

// #cgo CFLAGS: -I${SRCDIR}/../../bpf-gpl/libbpf/src -I${SRCDIR}/../../bpf-gpl/libbpf/include/uapi -I${SRCDIR}/../../bpf-gpl -Werror
// #cgo amd64 LDFLAGS: -L${SRCDIR}/../../bpf-gpl/libbpf/src/amd64 -lbpf -lelf -lz
// #cgo arm64 LDFLAGS: -L${SRCDIR}/../../bpf-gpl/libbpf/src/arm64 -lbpf -lelf -lz
// #include "libbpf_api.h"
import "C"

type Obj struct {
	filename string
	obj      *C.struct_bpf_object
}

func (o *Obj) Filename() string {
	return o.filename
}

type Map struct {
	bpfMap *C.struct_bpf_map
	bpfObj *C.struct_bpf_object
}

type Program struct {
	bpfProg *C.struct_bpf_program
	bpfObj  *C.struct_bpf_object
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
	utils.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	obj, err := C.bpf_obj_open(cFilename)
	if obj == nil || err != nil {
		return nil, fmt.Errorf("error opening libbpf object %w", err)
	}

	return &Obj{
		filename: filename,
		obj:      obj,
	}, nil
}

func OpenObjectWithLogBuffer(filename string, buf []byte) (*Obj, error) {
	if len(buf) == 0 {
		return OpenObject(filename)
	}

	utils.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)

	cBuf := (*C.char)(unsafe.Pointer(&buf[0]))

	defer C.free(unsafe.Pointer(cFilename))
	obj, err := C.bpf_obj_open_log_buf(cFilename, cBuf, C.size_t(len(buf)))
	if obj == nil || err != nil {
		return nil, fmt.Errorf("error opening libbpf object %w", err)
	}

	return &Obj{
		filename: filename,
		obj:      obj,
	}, nil
}

func (o *Obj) Load() error {
	_, err := C.bpf_obj_load(o.obj)
	if err != nil {
		return fmt.Errorf("error loading object %w", err)
	}
	return nil
}

// SetProgramAutoload sets whether a program should be automatically loaded.
// When set to false, the program will not be loaded when Load() is called.
func (o *Obj) SetProgramAutoload(progName string, autoload bool) {
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cProgName))
	C.bpf_set_program_autoload(o.obj, cProgName, C.bool(autoload))
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

func (o *Obj) FirstProgram() (*Program, error) {
	bpfProg, err := C.bpf_object__next_program(o.obj, nil)
	if bpfProg == nil || err != nil {
		return nil, fmt.Errorf("error getting first program %w", err)
	}
	return &Program{bpfProg: bpfProg, bpfObj: o.obj}, nil
}

func (p *Program) NextProgram() (*Program, error) {
	{
		bpfProg, err := C.bpf_object__next_program(p.bpfObj, p.bpfProg)
		if err != nil {
			return nil, fmt.Errorf("error getting next program %w", err)
		}
		if bpfProg == nil {
			return nil, nil
		}
		return &Program{bpfProg: bpfProg, bpfObj: p.bpfObj}, nil
	}
}

func (p *Program) Name() string {
	name := C.bpf_program__name(p.bpfProg)
	if name == nil {
		return ""
	}
	return C.GoString(name)
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

func (o *Obj) SetAttachType(progName string, attachType uint32) error {
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cProgName))
	_, err := C.bpf_set_attach_type(o.obj, cProgName, C.uint(attachType))
	return err
}

func ProgQueryTcx(ifindex int, ingress bool) ([64]uint32, [64]uint32, uint32, error) {
	attachType := C.BPF_TCX_EGRESS
	if ingress {
		attachType = C.BPF_TCX_INGRESS
	}
	return progQuery(ifindex, attachType)
}

func progQuery(ifindex, attachType int) ([64]uint32, [64]uint32, uint32, error) {
	var progIds, attachFlags [64]uint32
	progCnt := uint32(64)
	_, err := C.bpf_program_query(C.int(ifindex), C.int(attachType), 0,
		(*C.uint)(unsafe.Pointer(&attachFlags[0])),
		(*C.uint)(unsafe.Pointer(&progIds[0])),
		(*C.uint)(unsafe.Pointer(&progCnt)))
	return progIds, attachFlags, progCnt, err
}

func ProgName(id uint32) (string, error) {
	buf := make([]byte, C.BPF_OBJ_NAME_LEN)
	_, err := C.bpf_get_prog_name(C.uint(id), (*C.char)(unsafe.Pointer(&buf[0])))
	return string(buf), err
}

func DetachCTLBProgramsLegacy(ipv4Enabled bool, cgroup string) error {
	attachTypes := []int{C.BPF_CGROUP_INET6_CONNECT,
		C.BPF_CGROUP_UDP6_SENDMSG,
		C.BPF_CGROUP_UDP6_RECVMSG,
	}
	v4AttachTypes := []int{C.BPF_CGROUP_INET4_CONNECT,
		C.BPF_CGROUP_UDP4_SENDMSG,
		C.BPF_CGROUP_UDP4_RECVMSG,
	}
	if ipv4Enabled {
		attachTypes = append(attachTypes, v4AttachTypes...)
	}
	var err error
	for _, attachType := range attachTypes {
		perr := detachCTLBProgramLegacy(cgroup, attachType)
		if perr != nil {
			err = errors.Join(err, perr)
		}
	}
	return err
}

func detachCTLBProgramLegacy(cgroup string, attachType int) error {
	f, err := os.OpenFile(cgroup, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to join cgroup %s: %w", cgroup, err)
	}
	defer f.Close()
	fd := int(f.Fd())
	progFd, err := C.bpf_ctlb_get_prog_fd(C.int(fd), C.int(attachType))
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error querying cgroup %d : %w", attachType, err)
	}
	defer unix.Close(int(progFd))
	_, err = C.bpf_ctlb_detach_legacy(C.int(progFd), C.int(fd), C.int(attachType))
	return err
}

// AttachClassifier return the program id and pref and handle of the qdisc
func (o *Obj) AttachClassifier(secName, ifName string, ingress bool, prio int, handle uint32) error {
	cSecName := C.CString(secName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cSecName))
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return err
	}

	_, err = C.bpf_tc_program_attach(o.obj, cSecName, C.int(ifIndex), C.bool(ingress), C.int(prio), C.uint(handle))
	if err != nil {
		return fmt.Errorf("error attaching tc program %w", err)
	}

	return nil
}

func (o *Obj) AttachTCX(secName, ifName string) (*Link, error) {
	cSecName := C.CString(secName)
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cSecName))
	defer C.free(unsafe.Pointer(cIfName))
	ifIndex, err := C.if_nametoindex(cIfName)
	if err != nil {
		return nil, fmt.Errorf("error get ifindex for %s:%w", ifName, err)
	}
	link, err := C.bpf_tcx_program_attach(o.obj, cSecName, C.int(ifIndex))
	if err != nil {
		return nil, fmt.Errorf("error attaching tcx program %w", err)
	}
	return &Link{link: link}, nil
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

func (l *Link) Pin(path string) error {
	if l.link == nil {
		return fmt.Errorf("link nil")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	errno := C.bpf_link__pin(l.link, cPath)
	if errno != 0 {
		return fmt.Errorf("failed to pin link to %s: %w", path, syscall.Errno(errno))
	}
	return nil
}

func OpenLink(path string) (*Link, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	link, err := C.bpf_link_open(cPath)
	if err != nil {
		return nil, err
	}
	return &Link{link: link}, nil
}

func (l *Link) Detach() error {
	errno := C.bpf_link__detach(l.link)
	if errno != 0 {
		return fmt.Errorf("failed to detach link %w", syscall.Errno(errno))
	}
	return nil
}

func (l *Link) Update(obj *Obj, progName string) error {
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cProgName))

	_, err := C.bpf_update_link(l.link, obj.obj, cProgName)
	if err != nil {
		return fmt.Errorf("error updating link %w", err)
	}
	return nil
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
		return nil, fmt.Errorf("failed to attach %s to cgroup %s : %w",
			progName, cgroup, err)
	}
	return &Link{link: link}, nil
}

func (o *Obj) AttachCGroupLegacy(cgroup, progName string) error {
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cProgName))

	f, err := os.OpenFile(cgroup, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to join cgroup %s: %w", cgroup, err)
	}
	defer f.Close()
	fd := int(f.Fd())
	_, err = C.bpf_program_attach_cgroup_legacy(o.obj, C.int(fd), cProgName)
	if err != nil {
		return fmt.Errorf("failed to attach %s to cgroup %s (legacy try): %w",
			progName, cgroup, err)
	}
	return nil
}

const (
	// Set when IPv6 is enabled to configure bpf dataplane accordingly
	GlobalsRPFOptionEnabled            uint32 = C.CALI_GLOBALS_RPF_OPTION_ENABLED
	GlobalsRPFOptionStrict             uint32 = C.CALI_GLOBALS_RPF_OPTION_STRICT
	GlobalsNoDSRCidrs                  uint32 = C.CALI_GLOBALS_NO_DSR_CIDRS
	GlobalsLoUDPOnly                   uint32 = C.CALI_GLOBALS_LO_UDP_ONLY
	GlobalsRedirectPeer                uint32 = C.CALI_GLOBALS_REDIRECT_PEER
	GlobalsFlowLogsEnabled             uint32 = C.CALI_GLOBALS_FLOWLOGS_ENABLED
	GlobalsNATOutgoingExcludeHosts     uint32 = C.CALI_GLOBALS_NATOUTGOING_EXCLUDE_HOSTS
	GlobalsSkipEgressRedirect          uint32 = C.CALI_GLOBALS_SKIP_EGRESS_REDIRECT
	GlobalsIngressPacketRateConfigured uint32 = C.CALI_GLOBALS_INGRESS_PACKET_RATE_CONFIGURED
	GlobalsEgressPacketRateConfigured  uint32 = C.CALI_GLOBALS_EGRESS_PACKET_RATE_CONFIGURED

	AttachTypeTcxIngress uint32 = C.BPF_TCX_INGRESS
	AttachTypeTcxEgress  uint32 = C.BPF_TCX_EGRESS
)

func (t *TcGlobalData) Set(m *Map) error {
	cName := C.CString(t.IfaceName)
	defer C.free(unsafe.Pointer(cName))

	cJumps := make([]C.uint, len(t.Jumps))

	for i, v := range t.Jumps {
		cJumps[i] = C.uint(v)
	}

	cJumpsV6 := make([]C.uint, len(t.JumpsV6))

	for i, v := range t.JumpsV6 {
		cJumpsV6[i] = C.uint(v)
	}

	_, err := C.bpf_tc_set_globals(m.bpfMap,
		cName,
		(*C.char)(unsafe.Pointer(&t.HostIPv4[0])),
		(*C.char)(unsafe.Pointer(&t.IntfIPv4[0])),
		(*C.char)(unsafe.Pointer(&t.HostIPv6[0])),
		(*C.char)(unsafe.Pointer(&t.IntfIPv6[0])),
		C.uint(t.ExtToSvcMark),
		C.ushort(t.Tmtu),
		C.ushort(t.VxlanPort),
		C.ushort(t.PSNatStart),
		C.ushort(t.PSNatLen),
		(*C.char)(unsafe.Pointer(&t.HostTunnelIPv4[0])),
		(*C.char)(unsafe.Pointer(&t.HostTunnelIPv6[0])),
		C.uint(t.Flags),
		C.ushort(t.WgPort),
		C.ushort(t.Wg6Port),
		C.ushort(t.Profiling),
		C.uint(t.NatIn),
		C.uint(t.NatOut),
		C.uint(t.OverlayTunnelID),
		C.uint(t.LogFilterJmp),
		&cJumps[0], // it is safe because we hold the reference here until we return.
		&cJumpsV6[0],
		C.short(t.DSCP),
		C.uint(t.MaglevLUTSize),
	)

	return err
}

func (c *CTCleanupGlobalData) Set(m *Map) error {
	_, err := C.bpf_ct_cleanup_set_globals(
		m.bpfMap,
		C.uint64_t(c.CreationGracePeriod.Nanoseconds()),

		C.uint64_t(c.TCPSynSent.Nanoseconds()),
		C.uint64_t(c.TCPEstablished.Nanoseconds()),
		C.uint64_t(c.TCPFinsSeen.Nanoseconds()),
		C.uint64_t(c.TCPResetSeen.Nanoseconds()),

		C.uint64_t(c.UDPTimeout.Nanoseconds()),
		C.uint64_t(c.GenericTimeout.Nanoseconds()),
		C.uint64_t(c.ICMPTimeout.Nanoseconds()),
	)
	return err
}

func (c *CTLBGlobalData) Set(m *Map) error {
	udpNotSeen := c.UDPNotSeen / time.Second // Convert to seconds
	_, err := C.bpf_ctlb_set_globals(m.bpfMap, C.uint(udpNotSeen), C.bool(c.ExcludeUDP))

	return err
}

func (x *XDPGlobalData) Set(m *Map) error {
	cName := C.CString(x.IfaceName)
	defer C.free(unsafe.Pointer(cName))

	cJumps := make([]C.uint, len(x.Jumps))
	cJumpsV6 := make([]C.uint, len(x.Jumps))

	for i, v := range x.Jumps {
		cJumps[i] = C.uint(v)
	}

	for i, v := range x.JumpsV6 {
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
		return ncpus, fmt.Errorf("invalid number of CPUs: %d", ncpus)
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

// MapUpdateBatch expects all keys, values in a single slice, bytes of a one
// key/value appended back to back to the previous value.
func MapUpdateBatch(fd int, k, v []byte, count int, flags uint64) (int, error) {
	cK := C.CBytes(k)
	defer C.free(cK)
	cV := C.CBytes(v)
	defer C.free(cV)

	_, err := C.bpf_map_batch_update(C.int(fd), cK, cV, (*C.__u32)(unsafe.Pointer(&count)), C.__u64(flags))

	if err != nil {
		return 0, err
	}

	return count, nil
}

var bpfMapTypeMap = map[string]int{
	"unspec":           0,
	"hash":             1,
	"array":            2,
	"prog_array":       3,
	"perf_event_array": 4,
	"percpu_hash":      5,
	"percpu_array":     6,
	"lru_hash":         9,
	"lpm_trie":         11,
}

func CreateBPFMap(mapType string, keySize int, valueSize int, maxEntries int, flags int, name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	fd := C.create_bpf_map(
		C.enum_bpf_map_type(bpfMapTypeMap[mapType]),
		C.uint(keySize),
		C.uint(valueSize),
		C.uint(maxEntries),
		C.uint(flags),
		cname,
	)
	if fd < 0 {
		return int(fd), fmt.Errorf("failed to create bpf map")
	}
	return int(fd), nil
}

// MapDeleteBatch expects all key is in a single slice, bytes of a one
// key appended back to back to the previous value.
func MapDeleteBatch(fd int, k []byte, count int, flags uint64) (int, error) {
	cK := C.CBytes(k)
	defer C.free(cK)

	_, err := C.bpf_map_batch_delete(C.int(fd), cK, (*C.__u32)(unsafe.Pointer(&count)), C.__u64(flags))

	if err != nil {
		return 0, err
	}

	return count, nil
}
