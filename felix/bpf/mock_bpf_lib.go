// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package bpf

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/labelindex"
)

var id = 0

type CommonMapInfo struct {
	Id        int
	Type      string
	KeySize   int
	ValueSize int
}

type CIDRMapsKey struct {
	IfName string
	Family IPFamily
}

type CIDRMapInfo struct {
	CommonMapInfo

	Family IPFamily
}

type FailsafeMapInfo struct {
	CommonMapInfo
}

type IPv4Mask struct {
	Ip   [4]byte
	Mask int
}

type CIDRMap struct {
	Info CIDRMapInfo
	M    map[IPv4Mask]uint32
}

type FailsafeMap struct {
	Info FailsafeMapInfo
	M    map[ProtoPort]struct{} // (protocol, port) set
}

type XDPInfo struct {
	Id    int
	Maps  []int
	Bytes []byte
	Mode  XDPMode
}

type SockMapInfo struct {
	CommonMapInfo

	SkMsg *SkMsgInfo
}

type SockMap struct {
	Info SockMapInfo
	M    map[IPv4Mask]uint32
}

type SockopsInfo struct {
	CgroupPath string
}

type SkMsgInfo struct {
}

type MockBPFLib struct {
	binDir              string
	XDPProgs            map[string]XDPInfo      // iface -> []maps
	CIDRMaps            map[CIDRMapsKey]CIDRMap // iface -> map[ip]refCount
	SockopsProg         *SockopsInfo
	SockMap             *SockMap
	SkMsgProg           *SkMsgInfo
	SockmapEndpointsMap *CIDRMap
	FailsafeMap         FailsafeMap
	CgroupV2Dir         string
}

func NewMockBPFLib(binDir string) *MockBPFLib {
	return &MockBPFLib{
		binDir:      binDir,
		XDPProgs:    make(map[string]XDPInfo),
		CIDRMaps:    make(map[CIDRMapsKey]CIDRMap),
		CgroupV2Dir: "/sys/fs/cgroup/unified",
	}
}

func (b *MockBPFLib) GetBPFCalicoDir() string {
	return "/sys/fs/bpf/calico"
}

func (b *MockBPFLib) NewCIDRMap(ifName string, family IPFamily) (string, error) {
	if family != IPFamilyV4 {
		return "", errors.New("only IPv4 is supported")
	}

	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	b.CIDRMaps[key] = NewMockCIDRMap(id)

	id += 1

	return fmt.Sprintf("/sys/fs/bpf/calico/xdp/%s_ipv4_v1_blacklist", ifName), nil
}

func (b *MockBPFLib) NewFailsafeMap() (string, error) {
	b.FailsafeMap = NewMockFailsafeMap(id)

	id += 1

	return "/sys/fs/bpf/calico/xdp/calico_failsafe_ports_v1", nil
}

func (b *MockBPFLib) DumpCIDRMap(ifName string, family IPFamily) (map[CIDRMapKey]uint32, error) {
	ret := make(map[CIDRMapKey]uint32)

	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	m, ok := b.CIDRMaps[key]
	if !ok {
		return nil, fmt.Errorf("map %q not found", ifName)
	}

	for k, v := range m.M {
		ip := net.IPv4(k.Ip[0], k.Ip[1], k.Ip[2], k.Ip[3])
		ipnet := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(k.Mask, 32),
		}
		ret[NewCIDRMapKey(&ipnet)] = v
	}

	return ret, nil
}

func (b *MockBPFLib) DumpFailsafeMap() ([]ProtoPort, error) {
	var ret []ProtoPort

	if b.FailsafeMap.M == nil {
		return nil, fmt.Errorf("failsafe map not found")
	}

	for k := range b.FailsafeMap.M {
		ret = append(ret, k)
	}

	return ret, nil
}

func (b *MockBPFLib) GetCIDRMapID(ifName string, family IPFamily) (int, error) {
	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	m, ok := b.CIDRMaps[key]
	if !ok {
		return -1, fmt.Errorf("map %q not found", ifName)
	}
	return m.Info.Id, nil
}

func (b *MockBPFLib) GetFailsafeMapID() (int, error) {
	if b.FailsafeMap.M == nil {
		return -1, fmt.Errorf("failsafe map not found")
	}

	return b.FailsafeMap.Info.Id, nil
}

func (b *MockBPFLib) GetMapsFromXDP(ifName string) ([]int, error) {
	info, ok := b.XDPProgs[ifName]
	if !ok {
		return nil, errors.New("XDP program not found")
	}

	return info.Maps, nil
}

func (b *MockBPFLib) GetXDPID(ifName string) (int, error) {
	info, ok := b.XDPProgs[ifName]
	if !ok {
		return -1, errors.New("XDP program not found")
	}
	return info.Id, nil
}

func (b *MockBPFLib) GetXDPMode(ifName string) (XDPMode, error) {
	info, ok := b.XDPProgs[ifName]
	if !ok {
		return XDPGeneric, errors.New("XDP program not found")
	}
	return info.Mode, nil
}

func (b *MockBPFLib) GetXDPIfaces() ([]string, error) {
	var ret []string
	for ifName := range b.XDPProgs {
		ret = append(ret, ifName)
	}
	return ret, nil
}

func (b *MockBPFLib) GetXDPObjTag(objPath string) (tag string, err error) {
	tmpIf := "temp"
	if err := b.loadXDPRaw(objPath, tmpIf, XDPGeneric, nil); err != nil {
		return "", err
	}
	defer func() {
		e := b.RemoveXDP(tmpIf, XDPGeneric)
		if err == nil {
			err = e
		}
	}()

	return b.GetXDPTag(tmpIf)
}

func (b *MockBPFLib) GetXDPObjTagAuto() (string, error) {
	return b.GetXDPObjTag(xdpFilename)
}

func (b *MockBPFLib) GetXDPTag(ifName string) (string, error) {
	info, ok := b.XDPProgs[ifName]
	if !ok {
		return "", errors.New("xdp program not found")
	}

	return GetMockXDPTag(info.Bytes), nil
}

func (b *MockBPFLib) IsValidMap(ifName string, family IPFamily) (bool, error) {
	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	m, ok := b.CIDRMaps[key]
	if !ok {
		return false, fmt.Errorf("map %q not found", ifName)
	}

	valid := m.Info.Type == "lpm_trie" &&
		m.Info.KeySize == 8 &&
		m.Info.ValueSize == 4
	return valid, nil
}

func (b *MockBPFLib) ListCIDRMaps(family IPFamily) ([]string, error) {
	var ret []string

	for k := range b.CIDRMaps {
		ret = append(ret, k.IfName)
	}

	return ret, nil
}

func (b *MockBPFLib) LoadXDP(objPath, ifName string, mode XDPMode) error {
	if b.FailsafeMap.M == nil {
		return errors.New("failsafe map needs to be loaded first")
	}

	mapArgs := []string{strconv.Itoa(b.FailsafeMap.Info.Id)}

	key := CIDRMapsKey{
		IfName: ifName,
		// TODO change this when we support ipv6
		Family: IPFamilyV4,
	}

	cmap, ok := b.CIDRMaps[key]
	if !ok {
		return errors.New("failsafe map needs to be loaded first")
	}

	mapArgs = append(mapArgs, strconv.Itoa(cmap.Info.Id))

	return b.loadXDPRaw(objPath, ifName, mode, mapArgs)
}

func (b *MockBPFLib) LoadXDPAuto(ifName string, mode XDPMode) error {
	return b.LoadXDP(xdpFilename, ifName, mode)
}

func (b *MockBPFLib) LookupCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) (uint32, error) {
	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	m, ok := b.CIDRMaps[key]
	if !ok {
		return 0, fmt.Errorf("map %q not found", ifName)
	}

	l := len(ip)
	ipm := IPv4Mask{
		Ip:   [4]byte{ip[l-4], ip[l-3], ip[l-2], ip[l-1]},
		Mask: mask,
	}

	refCount, ok := m.M[ipm]
	if !ok {
		return 0, errors.New("CIDR not found")
	}

	return refCount, nil
}

func (b *MockBPFLib) LookupFailsafeMap(proto uint8, port uint16) (bool, error) {
	pp := ProtoPort{
		Proto: labelindex.IPSetPortProtocol(proto),
		Port:  port,
	}

	if b.FailsafeMap.M == nil {
		return false, fmt.Errorf("failsafe map not found")
	}

	_, ok := b.FailsafeMap.M[pp]

	return ok, nil
}

func (b *MockBPFLib) RemoveCIDRMap(ifName string, family IPFamily) error {
	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	if _, ok := b.CIDRMaps[key]; !ok {
		return fmt.Errorf("map %q not found", ifName)
	}

	delete(b.CIDRMaps, CIDRMapsKey{ifName, family})
	return nil
}

func (b *MockBPFLib) RemoveFailsafeMap() error {
	if b.FailsafeMap.M == nil {
		return fmt.Errorf("failsafe map not found")
	}

	b.FailsafeMap.M = nil
	return nil
}

func (b *MockBPFLib) RemoveItemCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) error {
	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	info, ok := b.CIDRMaps[key]
	if !ok {
		return fmt.Errorf("map %q not found", ifName)
	}

	l := len(ip)
	ipm := IPv4Mask{
		Ip:   [4]byte{ip[l-4], ip[l-3], ip[l-2], ip[l-1]},
		Mask: mask,
	}

	if _, ok := info.M[ipm]; !ok {
		return errors.New("CIDR not found")
	}

	delete(info.M, ipm)

	return nil
}

func (b *MockBPFLib) RemoveItemFailsafeMap(proto uint8, port uint16) error {
	if b.FailsafeMap.M == nil {
		return fmt.Errorf("failsafe map not found")
	}

	pp := ProtoPort{
		Proto: labelindex.IPSetPortProtocol(proto),
		Port:  port,
	}

	if _, ok := b.FailsafeMap.M[pp]; !ok {
		return errors.New("port not found")
	}

	delete(b.FailsafeMap.M, pp)

	return nil
}

func (b *MockBPFLib) RemoveXDP(ifName string, mode XDPMode) error {
	if info, ok := b.XDPProgs[ifName]; !ok {
		return errors.New("xdp program not found")
	} else if info.Mode != mode {
		return fmt.Errorf("xdp program has mode %s, not %s", info.Mode.String(), mode.String())
	}

	delete(b.XDPProgs, ifName)
	return nil
}

func (b *MockBPFLib) UpdateCIDRMap(ifName string, family IPFamily, ip net.IP, mask int, refCount uint32) error {
	key := CIDRMapsKey{
		IfName: ifName,
		Family: family,
	}

	m, ok := b.CIDRMaps[key]
	if !ok {
		return fmt.Errorf("map %q not found", ifName)
	}

	l := len(ip)
	ipm := IPv4Mask{
		Ip:   [4]byte{ip[l-4], ip[l-3], ip[l-2], ip[l-1]},
		Mask: mask,
	}
	m.M[ipm] = refCount
	return nil
}

func (b *MockBPFLib) UpdateFailsafeMap(proto uint8, port uint16) error {
	if b.FailsafeMap.M == nil {
		return fmt.Errorf("failsafe map not found")
	}

	pp := ProtoPort{
		Proto: labelindex.IPSetPortProtocol(proto),
		Port:  port,
	}

	b.FailsafeMap.M[pp] = struct{}{}

	return nil
}

func (b *MockBPFLib) loadXDPRaw(objPath, ifName string, mode XDPMode, mapArgs []string) error {
	objPath = path.Join(b.binDir, objPath)

	f, err := os.Open(objPath)
	if err != nil {
		return err
	}

	bytez, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	var mapIds []int

	if mapArgs == nil {
		mapIds = append(mapIds, id)
		id += 1
		mapIds = append(mapIds, id)
		id += 1
	} else {
		for _, id := range mapArgs {
			idInt, err := strconv.Atoi(id)
			if err != nil {
				return err
			}

			mapIds = append(mapIds, idInt)
		}
	}

	b.XDPProgs[ifName] = XDPInfo{
		Id:    id,
		Maps:  mapIds,
		Bytes: bytez,
		Mode:  mode,
	}

	id += 1

	return nil
}

func NewMockFailsafeMap(mapID int) FailsafeMap {
	return FailsafeMap{
		Info: FailsafeMapInfo{
			CommonMapInfo: CommonMapInfo{
				Id:        mapID,
				Type:      "hash",
				KeySize:   4,
				ValueSize: 1,
			},
		},
		M: make(map[ProtoPort]struct{}),
	}
}

func NewMockCIDRMap(mapID int) CIDRMap {
	return CIDRMap{
		Info: CIDRMapInfo{
			CommonMapInfo: CommonMapInfo{
				Id:        mapID,
				Type:      "lpm_trie",
				KeySize:   8,
				ValueSize: 4,
			},
		},
		M: make(map[IPv4Mask]uint32),
	}
}

func NewMockSockMap(mapID int) SockMap {
	return SockMap{
		Info: SockMapInfo{
			CommonMapInfo: CommonMapInfo{
				Id:        mapID,
				Type:      "sock_hash",
				KeySize:   8,
				ValueSize: 4,
			},
		},
		M: make(map[IPv4Mask]uint32),
	}
}

func GetMockXDPTag(bytes []byte) string {
	h := sha1.New()
	_, err := h.Write(bytes)
	if err != nil {
		log.WithError(err).Panic("failed to write rule hash")
	}
	checksum := hex.EncodeToString(h.Sum(nil))

	return string(checksum[:16])
}

func (b *MockBPFLib) AttachToSockmap() error {
	if b.SockMap == nil {
		return errors.New("no sockmap found")
	}

	if b.SkMsgProg == nil {
		return errors.New("no sk_msg program found")
	}

	b.SockMap.Info.SkMsg = b.SkMsgProg

	return nil
}

func (b *MockBPFLib) DetachFromSockmap(mode FindObjectMode) error {
	b.SockMap.Info.SkMsg = nil

	return nil
}

func (b *MockBPFLib) RemoveSockmap(mode FindObjectMode) error {
	if b.SockMap == nil {
		return errors.New("can't find sockmap")
	}

	b.SockMap = nil
	return nil
}

func (b *MockBPFLib) LoadSockops(objPath string) error {
	// we don't do anything with the sockops program so just succeed
	return nil
}

func (b *MockBPFLib) loadBPF(objPath, progPath, progType string, mapArgs []string) error {
	// this is just a refactoring with no real functionality for the mock BPF
	// library, just succeed
	return nil
}

func (b *MockBPFLib) LoadSockopsAuto() error {
	return b.LoadSockops(sockopsFilename)
}

func (b *MockBPFLib) RemoveSockops() error {
	if b.SockopsProg == nil {
		return errors.New("can't find sockops program")
	}

	b.SockopsProg = nil

	return nil

}
func (b *MockBPFLib) LoadSkMsg(objPath string) error {
	// we don't do anything with the sk_msg program so just succeed
	return nil
}

func (b *MockBPFLib) LoadSkMsgAuto() error {
	return b.LoadSkMsg(redirFilename)
}

func (b *MockBPFLib) RemoveSkMsg() error {
	if b.SkMsgProg == nil {
		return errors.New("can't find sk_msg program")
	}

	b.SkMsgProg = nil

	return nil
}

func (b *MockBPFLib) AttachToCgroup() error {
	if b.SockopsProg == nil {
		return errors.New("can't find sockops prog")
	}

	b.SockopsProg.CgroupPath = b.CgroupV2Dir

	return nil
}

func (b *MockBPFLib) DetachFromCgroup(mode FindObjectMode) error {
	if b.SockopsProg == nil {
		return errors.New("can't find sockops prog")
	}

	b.SockopsProg.CgroupPath = ""

	return nil
}

func (b *MockBPFLib) NewSockmapEndpointsMap() (string, error) {
	cidrMap := NewMockCIDRMap(id)

	b.SockmapEndpointsMap = &cidrMap

	id += 1

	return "/sys/fs/bpf/calico/sockmap/calico_sockmap_endpoints", nil
}

func (b *MockBPFLib) NewSockmap() (string, error) {
	sockMap := NewMockSockMap(id)
	b.SockMap = &sockMap

	id += 1

	return "/sys/fs/bpf/calico/sockmap/calico_sock_map", nil
}

func (b *MockBPFLib) UpdateSockmapEndpoints(ip net.IP, mask int) error {
	if b.SockmapEndpointsMap == nil {
		return errors.New("sockmap endpooints not found")
	}

	l := len(ip)
	ipm := IPv4Mask{
		Ip:   [4]byte{ip[l-4], ip[l-3], ip[l-2], ip[l-1]},
		Mask: mask,
	}
	b.SockmapEndpointsMap.M[ipm] = 1

	return nil
}

func (b *MockBPFLib) DumpSockmapEndpointsMap(family IPFamily) ([]CIDRMapKey, error) {
	if b.SockmapEndpointsMap == nil {
		return nil, errors.New("sockmap endpooints not found")
	}

	var ret []CIDRMapKey

	for k := range b.SockmapEndpointsMap.M {
		ip := net.IPv4(k.Ip[0], k.Ip[1], k.Ip[2], k.Ip[3])
		ipnet := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(k.Mask, 32),
		}
		ret = append(ret, NewCIDRMapKey(&ipnet))
	}

	return ret, nil
}

func (b *MockBPFLib) LookupSockmapEndpointsMap(ip net.IP, mask int) (bool, error) {
	if b.SockmapEndpointsMap == nil {
		return false, errors.New("sockmap endpooints not found")
	}

	l := len(ip)
	ipm := IPv4Mask{
		Ip:   [4]byte{ip[l-4], ip[l-3], ip[l-2], ip[l-1]},
		Mask: mask,
	}

	_, ok := b.SockmapEndpointsMap.M[ipm]
	if !ok {
		return false, errors.New("CIDR not found")
	}

	return true, nil
}

func (b *MockBPFLib) RemoveItemSockmapEndpointsMap(ip net.IP, mask int) error {
	if b.SockmapEndpointsMap == nil {
		return errors.New("sockmap endpooints not found")
	}

	l := len(ip)
	delete(b.SockmapEndpointsMap.M, IPv4Mask{
		Ip:   [4]byte{ip[l-4], ip[l-3], ip[l-2], ip[l-1]},
		Mask: mask,
	})

	return nil
}

func (b *MockBPFLib) RemoveSockmapEndpointsMap() error {
	if b.SockmapEndpointsMap == nil {
		return errors.New("sockmap endpooints not found")
	}

	b.SockmapEndpointsMap = nil

	return nil
}
