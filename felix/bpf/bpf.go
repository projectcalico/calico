// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

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

// Package bpf provides primitives to manage Calico-specific XDP programs
// attached to network interfaces, along with the blacklist LPM map and the
// failsafe map.
//
// It does not call the bpf() syscall itself but executes external programs
// like bpftool and ip.
package bpf

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/labelindex"
)

type XDPMode int

const (
	XDPDriver XDPMode = iota
	XDPOffload
	XDPGeneric
)

type FindObjectMode uint32

const (
	FindInBPFFSOnly FindObjectMode = 1 << iota
	FindByID
)

const (
	// XDP
	cidrMapVersion        = "v1"
	failsafeMapVersion    = "v1"
	xdpProgVersion        = "v1"
	failsafeMapName       = "calico_failsafe_ports_" + failsafeMapVersion
	failsafeSymbolMapName = "calico_failsafe_ports" // no need to version the symbol name

	// sockmap
	sockopsProgVersion         = "v1"
	sockopsProgName            = "calico_sockops_" + sockopsProgVersion
	skMsgProgVersion           = "v1"
	skMsgProgName              = "calico_sk_msg_" + skMsgProgVersion
	sockMapVersion             = "v1"
	sockMapName                = "calico_sock_map_" + sockMapVersion
	sockmapEndpointsMapVersion = "v1"
	sockmapEndpointsMapName    = "calico_sk_endpoints_" + sockmapEndpointsMapVersion

	defaultBPFfsPath = "/sys/fs/bpf"
)

var (
	xdpFilename     = "filter.o"
	sockopsFilename = "sockops.o"
	redirFilename   = "redir.o"

	bpfCalicoSubdir = "calico"
	ifaceRegexp     = regexp.MustCompile(`(?m)^[0-9]+:\s+(?P<name>.+):`)
	// v4Dot16Dot0 is the first kernel version that has all the
	// required features we use for XDP filtering
	v4Dot16Dot0 = environment.MustParseVersion("4.16.0")
	// v4Dot18Dot0 is the kernel version in RHEL that has all the
	// required features for BPF dataplane, sidecar acceleration
	v4Dot18Dot0 = environment.MustParseVersion("4.18.0-193")
	// v4Dot20Dot0 is the first kernel version that has all the
	// required features we use for sidecar acceleration
	v4Dot20Dot0 = environment.MustParseVersion("4.20.0")
	// v5Dot3Dot0 is the first kernel version that has all the
	// required features we use for BPF dataplane mode
	v5Dot3Dot0 = environment.MustParseVersion("5.3.0")
)

var distToVersionMap = map[string]*environment.Version{
	environment.Ubuntu:        v5Dot3Dot0,
	environment.RedHat:        v4Dot18Dot0,
	environment.DefaultDistro: v5Dot3Dot0,
}

func (m XDPMode) String() string {
	switch m {
	case XDPDriver:
		return "xdpdrv"
	case XDPOffload:
		return "xdpoffload"
	case XDPGeneric:
		return "xdpgeneric"
	default:
		return "unknown"
	}
}

// XXX maybe use ipsets.IPFamily
type IPFamily int

const (
	IPFamilyUnknown IPFamily = iota
	IPFamilyV4
	IPFamilyV6
)

func (m IPFamily) String() string {
	switch m {
	case IPFamilyV4:
		return "ipv4"
	case IPFamilyV6:
		return "ipv6"
	default:
		return "unknown"
	}
}

func (m IPFamily) Size() int {
	switch m {
	case IPFamilyV4:
		return 4
	case IPFamilyV6:
		return 16
	}
	return -1
}

func printCommand(name string, arg ...string) {
	log.Debugf("running: %s %s", name, strings.Join(arg, " "))
}

type BPFLib struct {
	binDir      string
	bpffsDir    string
	calicoDir   string
	sockmapDir  string
	cgroupV2Dir string
	xdpDir      string
}

func NewBPFLib(binDir string) (*BPFLib, error) {
	_, err := exec.LookPath("bpftool")
	if err != nil {
		return nil, errors.New("bpftool not found in $PATH")
	}

	bpfDir, err := MaybeMountBPFfs()
	if err != nil {
		return nil, err
	}

	cgroupV2Dir, err := MaybeMountCgroupV2()
	if err != nil {
		return nil, err
	}

	calicoDir := filepath.Join(bpfDir, bpfCalicoSubdir)
	xdpDir := filepath.Join(calicoDir, "xdp")
	sockmapDir := filepath.Join(calicoDir, "sockmap")

	return &BPFLib{
		binDir:      binDir,
		bpffsDir:    bpfDir,
		calicoDir:   calicoDir,
		sockmapDir:  sockmapDir,
		cgroupV2Dir: cgroupV2Dir,
		xdpDir:      xdpDir,
	}, nil
}

func MaybeMountBPFfs() (string, error) {
	var err error
	bpffsPath := defaultBPFfsPath

	mnt, err := isMount(defaultBPFfsPath)
	if err != nil {
		return "", err
	}

	fsBPF, err := isBPF(defaultBPFfsPath)
	if err != nil {
		return "", err
	}

	if !mnt {
		err = mountBPFfs(defaultBPFfsPath)
	} else if !fsBPF {
		var runfsBPF bool

		bpffsPath = "/var/run/calico/bpffs"

		if err := os.MkdirAll(bpffsPath, 0700); err != nil {
			return "", err
		}

		runfsBPF, err = isBPF(bpffsPath)
		if err != nil {
			return "", err
		}

		if !runfsBPF {
			err = mountBPFfs(bpffsPath)
		}
	}

	return bpffsPath, err
}

func MaybeMountCgroupV2() (string, error) {
	var err error
	cgroupV2Path := "/run/calico/cgroup"

	if err := os.MkdirAll(cgroupV2Path, 0700); err != nil {
		return "", err
	}

	mnt, err := isMount(cgroupV2Path)
	if err != nil {
		return "", fmt.Errorf("error checking if %s is a mount: %v", cgroupV2Path, err)
	}

	fsCgroup, err := isCgroupV2(cgroupV2Path)
	if err != nil {
		return "", fmt.Errorf("error checking if %s is CgroupV2: %v", cgroupV2Path, err)
	}

	if !mnt {
		err = mountCgroupV2(cgroupV2Path)
	} else if !fsCgroup {
		err = fmt.Errorf("something that's not cgroup v2 is already mounted in %s", cgroupV2Path)
	}

	return cgroupV2Path, err
}

func mountCgroupV2(path string) error {
	return syscall.Mount(path, path, "cgroup2", 0, "")
}

func isMount(path string) (bool, error) {
	procPath := "/proc/self/mountinfo"

	mi, err := os.Open(procPath)
	if err != nil {
		return false, err
	}
	defer mi.Close()

	sc := bufio.NewScanner(mi)

	for sc.Scan() {
		line := sc.Text()
		columns := strings.Split(line, " ")
		if len(columns) < 7 {
			return false, fmt.Errorf("not enough fields from line %q: %+v", line, columns)
		}

		mountPoint := columns[4]
		if filepath.Clean(mountPoint) == filepath.Clean(path) {
			return true, nil
		}
	}

	return false, nil
}

func isBPF(path string) (bool, error) {
	bpffsMagicNumber := uint32(0xCAFE4A11)

	var fsdata unix.Statfs_t
	if err := unix.Statfs(path, &fsdata); err != nil {
		return false, fmt.Errorf("%s is not mounted", path)
	}

	return uint32(fsdata.Type) == bpffsMagicNumber, nil
}

func isCgroupV2(path string) (bool, error) {
	cgroup2MagicNumber := uint32(0x63677270)

	var fsdata unix.Statfs_t
	if err := unix.Statfs(path, &fsdata); err != nil {
		return false, fmt.Errorf("%s is not mounted", path)
	}

	return uint32(fsdata.Type) == cgroup2MagicNumber, nil
}

func mountBPFfs(path string) error {
	return syscall.Mount(path, path, "bpf", 0, "")
}

type BPFDataplane interface {
	DumpCIDRMap(ifName string, family IPFamily) (map[CIDRMapKey]uint32, error)
	DumpFailsafeMap() ([]ProtoPort, error)
	GetCIDRMapID(ifName string, family IPFamily) (int, error)
	GetFailsafeMapID() (int, error)
	GetMapsFromXDP(ifName string) ([]int, error)
	GetXDPID(ifName string) (int, error)
	GetXDPMode(ifName string) (XDPMode, error)
	GetXDPIfaces() ([]string, error)
	GetXDPObjTag(objPath string) (string, error)
	GetXDPObjTagAuto() (string, error)
	GetXDPTag(ifName string) (string, error)
	IsValidMap(ifName string, family IPFamily) (bool, error)
	ListCIDRMaps(family IPFamily) ([]string, error)
	LoadXDP(objPath, ifName string, mode XDPMode) error
	LoadXDPAuto(ifName string, mode XDPMode) error
	LookupCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) (uint32, error)
	LookupFailsafeMap(proto uint8, port uint16) (bool, error)
	NewCIDRMap(ifName string, family IPFamily) (string, error)
	NewFailsafeMap() (string, error)
	RemoveCIDRMap(ifName string, family IPFamily) error
	RemoveFailsafeMap() error
	RemoveItemCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) error
	RemoveItemFailsafeMap(proto uint8, port uint16) error
	RemoveXDP(ifName string, mode XDPMode) error
	UpdateCIDRMap(ifName string, family IPFamily, ip net.IP, mask int, refCount uint32) error
	UpdateFailsafeMap(proto uint8, port uint16) error
	loadXDPRaw(objPath, ifName string, mode XDPMode, mapArgs []string) error
	GetBPFCalicoDir() string
	AttachToSockmap() error
	DetachFromSockmap(mode FindObjectMode) error
	RemoveSockmap(mode FindObjectMode) error
	loadBPF(objPath, progPath, progType string, mapArgs []string) error
	LoadSockops(objPath string) error
	LoadSockopsAuto() error
	RemoveSockops() error
	LoadSkMsg(objPath string) error
	LoadSkMsgAuto() error
	RemoveSkMsg() error
	AttachToCgroup() error
	DetachFromCgroup(mode FindObjectMode) error
	NewSockmapEndpointsMap() (string, error)
	NewSockmap() (string, error)
	UpdateSockmapEndpoints(ip net.IP, mask int) error
	DumpSockmapEndpointsMap(family IPFamily) ([]CIDRMapKey, error)
	LookupSockmapEndpointsMap(ip net.IP, mask int) (bool, error)
	RemoveItemSockmapEndpointsMap(ip net.IP, mask int) error
	RemoveSockmapEndpointsMap() error
}

func getCIDRMapName(ifName string, family IPFamily) string {
	return fmt.Sprintf("%s_%s_%s_blacklist", ifName, family, cidrMapVersion)
}

func getProgName(ifName string) string {
	return fmt.Sprintf("prefilter_%s_%s", xdpProgVersion, ifName)
}

func newMap(name, path, kind string, entries, keySize, valueSize, flags int) (string, error) {
	// FIXME: for some reason this function was called several times for a
	// particular map, just assume it's created if the pinned file is there for
	// now
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"create",
		path,
		"type",
		kind,
		"key",
		fmt.Sprintf("%d", keySize),
		"value",
		fmt.Sprintf("%d", valueSize),
		"entries",
		fmt.Sprintf("%d", entries),
		"name",
		name,
		"flags",
		fmt.Sprintf("%d", flags),
	}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create map (%s): %s\n%s", name, err, output)
	}

	return path, nil
}

func (b *BPFLib) NewFailsafeMap() (string, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	keySize := 4
	valueSize := 1

	return newMap(mapName,
		mapPath,
		"hash",
		65535,
		keySize,
		valueSize,
		1, // BPF_F_NO_PREALLOC
	)
}

func (b *BPFLib) GetBPFCalicoDir() string {
	return b.calicoDir
}

func (b *BPFLib) NewCIDRMap(ifName string, family IPFamily) (string, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if family == IPFamilyV6 {
		return "", errors.New("IPv6 not supported")
	}

	keySize := 8
	valueSize := 4

	return newMap(mapName,
		mapPath,
		"lpm_trie",
		10240,
		keySize,
		valueSize,
		1, // BPF_F_NO_PREALLOC
	)
}

func (b *BPFLib) ListCIDRMaps(family IPFamily) ([]string, error) {
	var ifNames []string
	maps, err := ioutil.ReadDir(b.xdpDir)
	if err != nil {
		return nil, err
	}

	suffix := fmt.Sprintf("_%s_%s_blacklist", family, cidrMapVersion)
	for _, m := range maps {
		name := m.Name()
		if strings.HasSuffix(name, suffix) {
			ifName := strings.TrimSuffix(name, suffix)
			ifNames = append(ifNames, ifName)
		}
	}

	return ifNames, nil
}

func (b *BPFLib) RemoveFailsafeMap() error {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	return os.Remove(mapPath)
}

func (b *BPFLib) RemoveCIDRMap(ifName string, family IPFamily) error {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	return os.Remove(mapPath)
}

type mapInfo struct {
	Id        int    `json:"id"`
	Type      string `json:"type"`
	KeySize   int    `json:"bytes_key"`
	ValueSize int    `json:"bytes_value"`
	Err       string `json:"error"`
}

type getnextEntry struct {
	Key     []string `json:"key"`
	NextKey []string `json:"next_key"`
	Err     string   `json:"error"`
}

type mapEntry struct {
	Key   []string `json:"key"`
	Value []string `json:"value"`
	Err   string   `json:"error"`
}

type progInfo struct {
	Id     int    `json:"id"`
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	MapIds []int  `json:"map_ids"`
	Err    string `json:"error"`
}

type cgroupProgEntry struct {
	ID          int    `json:"id"`
	AttachType  string `json:"attach_type"`
	AttachFlags string `json:"attach_flags"`
	Name        string `json:"name"`
	Err         string `json:"error"`
}

type ProtoPort struct {
	Proto labelindex.IPSetPortProtocol
	Port  uint16
}

func getMapStructGeneral(mapDesc []string) (*mapInfo, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"show"}
	args = append(args, mapDesc...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show map (%v): %s\n%s", mapDesc, err, output)
	}

	m := mapInfo{}
	err = json.Unmarshal(output, &m)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if m.Err != "" {
		return nil, fmt.Errorf("%s", m.Err)
	}
	return &m, nil
}

func getMapStruct(mapPath string) (*mapInfo, error) {
	return getMapStructGeneral([]string{"pinned", mapPath})
}

func (b *BPFLib) GetFailsafeMapID() (int, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	m, err := getMapStruct(mapPath)
	if err != nil {
		return -1, err
	}
	return m.Id, nil
}

func (b *BPFLib) DumpFailsafeMap() ([]ProtoPort, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"dump",
		"pinned",
		mapPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to dump map (%s): %s\n%s", mapPath, err, output)
	}

	l := []mapEntry{}
	err = json.Unmarshal(output, &l)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	pp := []ProtoPort{}
	for _, entry := range l {
		proto, port, err := hexToFailsafe(entry.Key)
		if err != nil {
			return nil, err
		}
		pp = append(pp, ProtoPort{labelindex.IPSetPortProtocol(proto), port})
	}

	return pp, nil
}

func (b *BPFLib) GetCIDRMapID(ifName string, family IPFamily) (int, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	m, err := getMapStruct(mapPath)
	if err != nil {
		return -1, err
	}
	return m.Id, nil
}

func (b *BPFLib) IsValidMap(ifName string, family IPFamily) (bool, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	m, err := getMapStruct(mapPath)
	if err != nil {
		return false, err
	}
	switch family {
	case IPFamilyV4:
		if m.Type != "lpm_trie" || m.KeySize != 8 || m.ValueSize != 4 {
			return false, nil
		}
	case IPFamilyV6:
		return false, fmt.Errorf("IPv6 not implemented yet")
	default:
		return false, fmt.Errorf("unknown IP family %d", family)
	}
	return true, nil
}

func (b *BPFLib) LookupFailsafeMap(proto uint8, port uint16) (bool, error) {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return false, err
	}

	hexKey, err := failsafeToHex(proto, port)
	if err != nil {
		return false, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"lookup",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to lookup in map (%s): %s\n%s", mapName, err, output)
	}

	l := mapEntry{}
	err = json.Unmarshal(output, &l)
	if err != nil {
		return false, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if l.Err != "" {
		return false, fmt.Errorf("%s", l.Err)
	}

	return true, err
}

func (b *BPFLib) LookupCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) (uint32, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return 0, err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return 0, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"lookup",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to lookup in map (%s): %s\n%s", mapName, err, output)
	}

	l := mapEntry{}
	err = json.Unmarshal(output, &l)
	if err != nil {
		return 0, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if l.Err != "" {
		return 0, fmt.Errorf("%s", l.Err)
	}

	val, err := hexToCIDRMapValue(l.Value)
	if err != nil {
		return 0, err
	}

	return val, err
}

type CIDRMapKey struct {
	rawIP   [16]byte
	rawMask [16]byte
}

func (k *CIDRMapKey) ToIPNet() *net.IPNet {
	ip := net.IP(k.rawIP[:]).To16()
	mask := func() net.IPMask {
		if ip.To4() != nil {
			// it's an IPV4 address
			return k.rawMask[12:16]
		} else {
			return k.rawMask[:]
		}
	}()
	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

func NewCIDRMapKey(n *net.IPNet) CIDRMapKey {
	k := CIDRMapKey{
		rawMask: [16]byte{
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,
		},
	}
	rawIPSlice := k.rawIP[:]
	copy(rawIPSlice, n.IP.To16())
	rawMaskSlice := k.rawMask[len(k.rawMask)-len(n.Mask):]
	copy(rawMaskSlice, n.Mask)
	return k
}

func (b *BPFLib) DumpCIDRMap(ifName string, family IPFamily) (map[CIDRMapKey]uint32, error) {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return nil, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"dump",
		"pinned",
		mapPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to dump in map (%s): %s\n%s", mapName, err, output)
	}

	var al []mapEntry
	err = json.Unmarshal(output, &al)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	m := make(map[CIDRMapKey]uint32, len(al))
	for _, l := range al {
		ipnet, err := hexToIPNet(l.Key, family)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bpf map key (%v) to ip and mask: %v", l.Key, err)
		}
		value, err := hexToCIDRMapValue(l.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bpf map value (%v): %v", l.Value, err)
		}
		m[NewCIDRMapKey(ipnet)] = value
	}

	return m, nil
}

func (b *BPFLib) RemoveItemFailsafeMap(proto uint8, port uint16) error {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	hexKey, err := failsafeToHex(proto, port)
	if err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"delete",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete item (%d) from map (%s): %s\n%s", port, mapName, err, output)
	}

	return nil
}

func (b *BPFLib) RemoveItemCIDRMap(ifName string, family IPFamily, ip net.IP, mask int) error {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"delete",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete item (%v/%d) from map (%s): %s\n%s", ip, mask, mapName, err, output)
	}

	return nil
}

func (b *BPFLib) UpdateFailsafeMap(proto uint8, port uint16) error {
	mapName := failsafeMapName
	mapPath := filepath.Join(b.calicoDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	hexKey, err := failsafeToHex(proto, port)
	if err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"map",
		"update",
		"pinned",
		mapPath,
		"key",
		"hex"}
	args = append(args, hexKey...)
	args = append(args, []string{
		"value",
		fmt.Sprintf("%d", 1), // it's just a set, so use 1 as value
	}...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update map (%s) with (%d): %s\n%s", mapName, port, err, output)
	}

	return nil
}

func (b *BPFLib) UpdateCIDRMap(ifName string, family IPFamily, ip net.IP, mask int, refCount uint32) error {
	mapName := getCIDRMapName(ifName, family)
	mapPath := filepath.Join(b.xdpDir, mapName)

	if err := os.MkdirAll(b.xdpDir, 0700); err != nil {
		return err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return err
	}
	hexValue := cidrMapValueToHex(refCount)

	prog := "bpftool"
	args := []string{
		"map",
		"update",
		"pinned",
		mapPath,
		"key",
		"hex"}
	args = append(args, hexKey...)
	args = append(args, "value", "hex")
	args = append(args, hexValue...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update map (%s) with (%v/%d): %s\n%s", mapName, ip, mask, err, output)
	}

	return nil
}

func (b *BPFLib) loadXDPRaw(objPath, ifName string, mode XDPMode, mapArgs []string) error {
	objPath = path.Join(b.binDir, objPath)

	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		return fmt.Errorf("cannot find XDP object %q", objPath)
	}

	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	if err := b.loadBPF(objPath, progPath, "xdp", mapArgs); err != nil {
		return err
	}

	prog := "ip"
	args := []string{
		"link",
		"set",
		"dev",
		ifName,
		mode.String(),
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	log.Debugf("out:\n%v", string(output))

	if err != nil {
		if removeErr := os.Remove(progPath); removeErr != nil {
			return fmt.Errorf("failed to attach XDP program (%s) to %s: %s (also failed to remove the pinned program: %s)\n%s", progPath, ifName, err, removeErr, output)
		} else {
			return fmt.Errorf("failed to attach XDP program (%s) to %s: %s\n%s", progPath, ifName, err, output)
		}
	}

	return nil
}

func (b *BPFLib) getMapArgs(ifName string) ([]string, error) {
	// FIXME harcoded ipv4, do we need both?
	mapName := getCIDRMapName(ifName, IPFamilyV4)
	mapPath := filepath.Join(b.xdpDir, mapName)

	failsafeMapPath := filepath.Join(b.calicoDir, failsafeMapName)

	// key: symbol of the map definition in the XDP program
	// value: path where the map is pinned
	maps := map[string]string{
		"calico_prefilter_v4": mapPath,
		failsafeSymbolMapName: failsafeMapPath,
	}

	var mapArgs []string

	for n, p := range maps {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return nil, fmt.Errorf("map %q needs to be loaded first", p)
		}

		mapArgs = append(mapArgs, []string{"map", "name", n, "pinned", p}...)
	}

	return mapArgs, nil
}

func (b *BPFLib) LoadXDP(objPath, ifName string, mode XDPMode) error {
	mapArgs, err := b.getMapArgs(ifName)
	if err != nil {
		return err
	}

	return b.loadXDPRaw(objPath, ifName, mode, mapArgs)
}

func (b *BPFLib) LoadXDPAuto(ifName string, mode XDPMode) error {
	return b.LoadXDP(xdpFilename, ifName, mode)
}

func (b *BPFLib) RemoveXDP(ifName string, mode XDPMode) error {
	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	prog := "ip"
	args := []string{
		"link",
		"set",
		"dev",
		ifName,
		mode.String(),
		"off"}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to detach XDP program (%s) from %s: %s\n%s", progPath, ifName, err, output)
	}

	return os.Remove(progPath)
}

func (b *BPFLib) GetXDPTag(ifName string) (string, error) {
	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"prog",
		"show",
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to show XDP program (%s): %s\n%s", progPath, err, output)
	}

	p := progInfo{}
	err = json.Unmarshal(output, &p)
	if err != nil {
		return "", fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if p.Err != "" {
		return "", fmt.Errorf("%s", p.Err)
	}

	return p.Tag, nil
}

func (b *BPFLib) GetXDPObjTag(objPath string) (tag string, err error) {
	// To find out what tag is assigned to an XDP object we create a temporary
	// veth pair and load the program. Then, the kernel will assign the tag and
	// we can read it.
	tmpIfA := "calico_tmp_A"
	tmpIfB := "calico_tmp_B"

	// clean up possible stale interfaces
	if err := maybeDeleteIface(tmpIfA); err != nil {
		return "", fmt.Errorf("cannot delete %q iface", tmpIfA)
	}
	if err := maybeDeleteIface(tmpIfB); err != nil {
		return "", fmt.Errorf("cannot delete %q iface", tmpIfB)
	}

	prog := "ip"
	createVethPairArgs := []string{
		"link",
		"add",
		tmpIfA,
		"type",
		"veth",
		"peer",
		"name",
		tmpIfB}
	deleteVethPairArgs := []string{
		"link",
		"del",
		tmpIfA}

	printCommand(prog, createVethPairArgs...)
	output, err := exec.Command(prog, createVethPairArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create temporary veth pair: %s\n%s", err, output)
	}
	defer func() {
		printCommand(prog, deleteVethPairArgs...)
		output, e := exec.Command(prog, deleteVethPairArgs...).CombinedOutput()
		if err == nil && e != nil {
			err = fmt.Errorf("failed to delete temporary veth pair: %s\n%s", e, output)
		}
	}()

	if err := b.loadXDPRaw(objPath, tmpIfA, XDPGeneric, nil); err != nil {
		return "", err
	}
	defer func() {
		e := b.RemoveXDP(tmpIfA, XDPGeneric)
		if err == nil {
			err = e
		}
	}()

	return b.GetXDPTag(tmpIfA)
}

func (b *BPFLib) GetXDPObjTagAuto() (string, error) {
	return b.GetXDPObjTag(xdpFilename)
}

func (b *BPFLib) GetMapsFromXDP(ifName string) ([]int, error) {
	progName := getProgName(ifName)
	progPath := filepath.Join(b.xdpDir, progName)

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"prog",
		"show",
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show XDP program (%s): %s\n%s", progPath, err, output)
	}
	p := progInfo{}
	err = json.Unmarshal(output, &p)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if p.Err != "" {
		return nil, fmt.Errorf("%s", p.Err)
	}

	return p.MapIds, nil
}

func (b *BPFLib) GetXDPID(ifName string) (int, error) {
	prog := "ip"
	args := []string{
		"link",
		"show",
		"dev",
		ifName}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("failed to show interface information (%s): %s\n%s", ifName, err, output)
	}

	s := strings.Fields(string(output))
	for i := range s {
		// Example of output:
		//
		// 196: test_A@test_B: <BROADCAST,MULTICAST> mtu 1500 xdpgeneric qdisc noop state DOWN mode DEFAULT group default qlen 1000
		//    link/ether 1a:d0:df:a5:12:59 brd ff:ff:ff:ff:ff:ff
		//    prog/xdp id 175 tag 5199fa060702bbff jited
		if s[i] == "prog/xdp" && len(s) > i+2 && s[i+1] == "id" {
			id, err := strconv.Atoi(s[i+2])
			if err != nil {
				continue
			}
			return id, nil
		}
	}

	return -1, errors.New("ID not found")
}

func (b *BPFLib) GetXDPMode(ifName string) (XDPMode, error) {
	prog := "ip"
	args := []string{
		"link",
		"show",
		"dev",
		ifName}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return XDPGeneric, fmt.Errorf("failed to show interface information (%s): %s\n%s", ifName, err, output)
	}

	s := strings.Fields(string(output))
	// Note: using a slice (rather than a map[string]XDPMode) here to ensure deterministic ordering.
	for _, modeMapping := range []struct {
		String string
		Mode   XDPMode
	}{
		{"xdpgeneric", XDPGeneric},
		{"xdpoffload", XDPOffload},
		{"xdp", XDPDriver}, // We write "xdpdrv" but read back "xdp"
	} {
		for _, f := range s {
			if f == modeMapping.String {
				return modeMapping.Mode, nil
			}
		}
	}

	return XDPGeneric, errors.New("ID not found")
}

func (b *BPFLib) GetXDPIfaces() ([]string, error) {
	var xdpIfaces []string

	prog := "ip"
	args := []string{
		"link",
		"show"}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show interface informations: %s\n%s", err, output)
	}

	m := ifaceRegexp.FindAllStringSubmatch(string(output), -1)
	if len(m) < 2 {
		return nil, fmt.Errorf("failed to parse interface informations")
	}

	for _, i := range m {
		if len(i) != 2 {
			continue
		}

		// handle paired interfaces
		ifaceParts := strings.Split(i[1], "@")
		ifaceName := ifaceParts[0]

		if _, err := b.GetXDPID(ifaceName); err == nil {
			xdpIfaces = append(xdpIfaces, ifaceName)
		}
	}

	return xdpIfaces, nil
}

// failsafeToHex takes a protocol and port number and outputs a string slice
// of hex-encoded bytes ready to be passed to bpftool.
//
// For example, for 8080/TCP:
//
// [
//  06,     IPPROTO_TCP as defined by <linux/in.h>
//  00,     padding
//  90, 1F  LSB in little endian order
// ]
func failsafeToHex(proto uint8, port uint16) ([]string, error) {
	portBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBytes, port)

	hexStr := fmt.Sprintf("%02x 00 %02x %02x",
		proto,
		portBytes[0], portBytes[1])

	return strings.Split(hexStr, " "), nil
}

func hexToByte(hexString string) (byte, error) {
	hex := strings.TrimPrefix(hexString, "0x")
	proto64, err := strconv.ParseUint(hex, 16, 8)
	if err != nil {
		return 0, err
	}
	return byte(proto64), nil
}

// hexToFailsafe takes the bpftool hex representation of a protocol and port
// number and returns the protocol and port number.
func hexToFailsafe(hexString []string) (proto uint8, port uint16, err error) {
	proto, err = hexToByte(hexString[0])
	if err != nil {
		return
	}

	padding, err := hexToByte(hexString[1])
	if err != nil {
		return
	}

	if padding != 0 {
		err = fmt.Errorf("invalid proto in hex string: %q\n", hexString[1])
		return
	}

	portMSB, err := hexToByte(hexString[2])
	if err != nil {
		err = fmt.Errorf("invalid port MSB in hex string: %q\n", hexString[2])
		return
	}

	portLSB, err := hexToByte(hexString[3])
	if err != nil {
		err = fmt.Errorf("invalid port LSB in hex string: %q\n", hexString[3])
		return
	}

	port = binary.LittleEndian.Uint16([]byte{portLSB, portMSB})
	return
}

// CidrToHex takes a CIDR in string form (e.g. "192.168.0.0/16") and outputs a
// string slice of hex-encoded bytes ready to be passed to bpftool.
//
// For example, for "192.168.0.0/16":
//
// [
//  10, 00, 00, 00,   mask in little endian order
//  C0, A8, 00, 00    IP address
// ]
func CidrToHex(cidr string) ([]string, error) {
	cidrParts := strings.Split(cidr, "/")
	if len(cidrParts) != 2 {
		return nil, fmt.Errorf("failed to split CIDR %q", cidr)
	}
	rawIP := cidrParts[0]

	mask, err := strconv.Atoi(cidrParts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to convert mask %d to int", mask)
	}

	ip := net.ParseIP(rawIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", rawIP)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("IP %q is not IPv4", ip)
	}

	maskBytes := make([]byte, 4)
	if mask > math.MaxUint32 || mask < 0 {
		log.Fatal("mask should be between 0 and %v", math.MaxUint32)
	}
	binary.LittleEndian.PutUint32(maskBytes, uint32(mask))

	hexStr := fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x",
		maskBytes[0], maskBytes[1], maskBytes[2], maskBytes[3],
		ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	return strings.Split(hexStr, " "), nil
}

// hexToIPNet takes the bpftool hex representation of a CIDR (see above) and
// returns a net.IPNet.
func hexToIPNet(hexStrings []string, family IPFamily) (*net.IPNet, error) {
	hex, err := hexStringsToBytes(hexStrings)
	if err != nil {
		return nil, err
	}
	maskBytes := hex[0:4]
	ipBytes := hex[4:]
	mask := int(binary.LittleEndian.Uint32(maskBytes))

	return &net.IPNet{
		IP:   ipBytes,
		Mask: net.CIDRMask(mask, family.Size()*8),
	}, nil
}

// hexToCIDRMapValue takes a string slice containing the bpftool hex
// representation of a 1-byte value and returns it as an uint32
func hexToCIDRMapValue(hexStrings []string) (uint32, error) {
	hex, err := hexStringsToBytes(hexStrings)
	if err != nil {
		return 0, err
	}
	if len(hex) != 4 {
		return 0, fmt.Errorf("wrong size of hex in %q", hexStrings)
	}
	return nativeEndian.Uint32(hex), nil
}

// cidrMapValueToHex takes a ref count as unsigned 32 bit number and
// turns it into an array of hex strings, which bpftool can understand.
func cidrMapValueToHex(refCount uint32) []string {
	refCountBytes := make([]byte, 4)
	nativeEndian.PutUint32(refCountBytes, refCount)

	hexStr := fmt.Sprintf("%02x %02x %02x %02x",
		refCountBytes[0], refCountBytes[1], refCountBytes[2], refCountBytes[3])

	return strings.Split(hexStr, " ")
}

// hexStringsToBytes takes a string slice containing bpf data represented as
// bpftool hex and returns a slice of bytes containing that data.
func hexStringsToBytes(hexStrings []string) ([]byte, error) {
	var hex []byte
	for _, b := range hexStrings {
		h, err := hexToByte(b)
		if err != nil {
			return nil, err
		}
		hex = append(hex, byte(h))
	}
	return hex, nil
}

func MemberToIPMask(member string) (*net.IP, int, error) {
	var (
		mask  int
		rawIP string
	)

	memberParts := strings.Split(member, "/")
	switch len(memberParts) {
	case 1:
		mask = 32
		rawIP = memberParts[0]
	case 2:
		var err error
		mask, err = strconv.Atoi(memberParts[1])
		if err != nil {
			return nil, -1, fmt.Errorf("failed to convert mask %d to int", mask)
		}
		rawIP = memberParts[0]
	default:
		return nil, -1, fmt.Errorf("invalid member format %q", member)
	}

	ip := net.ParseIP(rawIP)
	if ip == nil {
		return nil, -1, fmt.Errorf("invalid IP %q", rawIP)
	}

	return &ip, mask, nil
}

func maybeDeleteIface(name string) error {
	args := []string{"-c", fmt.Sprintf("ip link del %s || true", name)}
	output, err := exec.Command("/bin/sh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot run ip command: %v\n%s", err, output)
	}
	return nil
}

func SupportsXDP() error {
	if err := isAtLeastKernel(v4Dot16Dot0); err != nil {
		return err
	}

	// Test endianness
	if nativeEndian != binary.LittleEndian {
		return fmt.Errorf("this bpf library only supports little endian architectures")
	}

	return nil
}

func (b *BPFLib) AttachToSockmap() error {
	mapPath := filepath.Join(b.sockmapDir, sockMapName)
	progPath := filepath.Join(b.sockmapDir, skMsgProgName)

	prog := "bpftool"
	args := []string{
		"prog",
		"attach",
		"pinned",
		progPath,
		"msg_verdict",
		"pinned",
		mapPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to attach sk_msg prog to sockmap: %s\n%s", err, output)
	}

	return nil
}

func (b *BPFLib) DetachFromSockmap(mode FindObjectMode) error {
	mapPath := filepath.Join(b.sockmapDir, sockMapName)

	progPath := filepath.Join(b.sockmapDir, skMsgProgName)

	prog := "bpftool"
	args := []string{
		"prog",
		"detach",
		"pinned",
		progPath,
		"msg_verdict",
		"pinned",
		mapPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		if mode != FindByID {
			return fmt.Errorf("failed to detach sk_msg prog from sockmap: %s\n%s", err, output)
		}
		progID, err2 := b.getSkMsgID()
		if err2 != nil {
			return fmt.Errorf("failed to detach sk_msg prog from sockmap: %s\n%s\n\nfailed to get the id of the program: %s", err, output, err2)
		}
		if progID >= 0 {
			mapID, err2 := b.getSockMapID(progID)
			if err2 != nil {
				return fmt.Errorf("failed to detach sk_msg prog from sockmap: %s\n%s\n\nfailed to get the id of the sockmap: %s", err, output, err2)
			}

			args := []string{
				"prog",
				"detach",
				"id",
				fmt.Sprintf("%d", progID),
				"msg_verdict",
				"id",
				fmt.Sprintf("%d", mapID)}

			printCommand(prog, args...)
			output2, err2 := exec.Command(prog, args...).CombinedOutput()
			if err2 != nil {
				return fmt.Errorf("failed to detach sk_msg prog from sockmap: %s\n%s\n\nfailed to detach sk_msg prog from sockmap by id: %s\n%s", err, output, err2, output2)
			}
		}
	}

	return nil
}

func (b *BPFLib) getSkMsgID() (int, error) {
	progs, err := getAllProgs()
	if err != nil {
		return -1, fmt.Errorf("failed to get sk msg prog id: %s", err)
	}

	for _, p := range progs {
		if p.Type == "sk_msg" {
			return p.Id, nil
		}
	}
	return -1, nil
}

func getAllProgs() ([]progInfo, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"prog",
		"show",
	}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get progs: %s\n%s", err, output)
	}

	var progs []progInfo
	err = json.Unmarshal(output, &progs)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	return progs, nil
}

func (b *BPFLib) getAttachedSockopsID() (int, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"cgroup",
		"show",
		b.cgroupV2Dir}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("failed to get attached sockmap id: %s\n%s", err, output)
	}

	var al []cgroupProgEntry
	err = json.Unmarshal(output, &al)
	if err != nil {
		return -1, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	for _, l := range al {
		if l.Name == "calico_sockops" && l.AttachType == "sock_ops" {
			return l.ID, nil
		}
	}

	return -1, nil
}

func (b *BPFLib) getSockMapID(progID int) (int, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"prog",
		"show",
		"id",
		fmt.Sprintf("%d", progID)}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("failed to get sockmap ID for prog %d: %s\n%s", progID, err, output)
	}

	p := progInfo{}
	err = json.Unmarshal(output, &p)
	if err != nil {
		return -1, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if p.Err != "" {
		return -1, fmt.Errorf("%s", p.Err)
	}

	for _, mapID := range p.MapIds {
		mapInfo, err := getMapStructGeneral([]string{"id", fmt.Sprintf("%d", mapID)})
		if err != nil {
			return -1, err
		}
		if mapInfo.Type == "sockhash" {
			return mapID, nil
		}
	}
	return -1, fmt.Errorf("sockhash map for prog %d not found", progID)
}

func jsonKeyToArgs(jsonKey []string) []string {
	var ret []string
	for _, b := range jsonKey {
		ret = append(ret, strings.TrimPrefix(b, "0x"))
	}

	return ret
}

func clearSockmap(mapArgs []string) error {
	prog := "bpftool"

	var e getnextEntry

	for {
		args := []string{
			"map",
			"--json",
			"getnext"}
		args = append(args, mapArgs...)

		printCommand(prog, args...)
		// don't check error here, we'll catch them parsing the output
		output, _ := exec.Command(prog, args...).CombinedOutput()

		err := json.Unmarshal(output, &e)
		if err != nil {
			return fmt.Errorf("cannot parse json output: %v\n%s", err, output)
		}

		if e.Err == "can't get next key: No such file or directory" {
			// reached the end
			return nil
		}

		if e.Err != "" {
			return fmt.Errorf("%s", e.Err)
		}

		keyArgs := jsonKeyToArgs(e.NextKey)
		args = []string{
			"map",
			"--json",
			"delete",
		}
		args = append(args, mapArgs...)
		args = append(args, "key", "hex")
		args = append(args, keyArgs...)

		printCommand(prog, args...)
		output, err = exec.Command(prog, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to delete item (%v) from map (%v): %s\n%s", e.NextKey, mapArgs, err, output)
		}
	}
}

func (b *BPFLib) RemoveSockmap(mode FindObjectMode) error {
	mapPath := filepath.Join(b.sockmapDir, sockMapName)
	defer os.Remove(mapPath)
	if err := clearSockmap([]string{"pinned", mapPath}); err != nil {
		if mode != FindByID {
			return fmt.Errorf("failed to clear sock map: %v", err)
		}

		m, err := b.getSockMap()
		if err != nil {
			return err
		}
		if m != nil {
			if err := clearSockmap([]string{"id", fmt.Sprintf("%d", m.Id)}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *BPFLib) getAllMaps() ([]mapInfo, error) {
	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"show"}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get all maps: %s\n%s", err, output)
	}

	var maps []mapInfo
	err = json.Unmarshal(output, &maps)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	return maps, nil
}

func (b *BPFLib) getSockMap() (*mapInfo, error) {
	maps, err := b.getAllMaps()
	if err != nil {
		return nil, err
	}

	for _, m := range maps {
		if m.Type == "sockhash" {
			return &m, nil
		}
	}
	return nil, nil
}

func (b *BPFLib) loadBPF(objPath, progPath, progType string, mapArgs []string) error {
	if err := os.MkdirAll(filepath.Dir(progPath), 0700); err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"prog",
		"load",
		objPath,
		progPath,
		"type",
		progType}

	args = append(args, mapArgs...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	log.Debugf("out:\n%v", string(output))

	if err != nil {
		// FIXME: for some reason this function was called several times for a
		// particular XDP program, just assume the map is loaded if the pinned
		// file is there for now
		if _, err := os.Stat(progPath); err != nil {
			return fmt.Errorf("failed to load BPF program (%s): %s\n%s", objPath, err, output)
		}
	}

	return nil
}

func (b *BPFLib) getSockmapArgs() ([]string, error) {
	sockmapPath := filepath.Join(b.sockmapDir, sockMapName)
	sockmapEndpointsPath := filepath.Join(b.sockmapDir, sockmapEndpointsMapName)

	// key: symbol of the map definition in the XDP program
	// value: path where the map is pinned
	maps := map[string]string{
		"calico_sock_map":     sockmapPath,
		"calico_sk_endpoints": sockmapEndpointsPath,
	}

	var mapArgs []string

	for n, p := range maps {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return nil, fmt.Errorf("map %q needs to be loaded first", p)
		}

		mapArgs = append(mapArgs, []string{"map", "name", n, "pinned", p}...)
	}

	return mapArgs, nil
}

func (b *BPFLib) LoadSockops(objPath string) error {
	objPath = path.Join(b.binDir, objPath)
	progPath := filepath.Join(b.sockmapDir, sockopsProgName)

	sockmapArgs, err := b.getSockmapArgs()
	if err != nil {
		return err
	}

	return b.loadBPF(objPath, progPath, "sockops", sockmapArgs)
}

func (b *BPFLib) LoadSockopsAuto() error {
	return b.LoadSockops(sockopsFilename)
}

func (b *BPFLib) RemoveSockops() error {
	progPath := filepath.Join(b.sockmapDir, sockopsProgName)
	return os.Remove(progPath)
}

func (b *BPFLib) getSkMsgArgs() ([]string, error) {
	sockmapPath := filepath.Join(b.sockmapDir, sockMapName)

	// key: symbol of the map definition in the XDP program
	// value: path where the map is pinned
	maps := map[string]string{
		"calico_sock_map": sockmapPath,
	}

	var mapArgs []string

	for n, p := range maps {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return nil, fmt.Errorf("map %q needs to be loaded first", p)
		}

		mapArgs = append(mapArgs, []string{"map", "name", n, "pinned", p}...)
	}

	return mapArgs, nil
}

func (b *BPFLib) LoadSkMsg(objPath string) error {
	objPath = path.Join(b.binDir, objPath)
	progPath := filepath.Join(b.sockmapDir, skMsgProgName)
	mapArgs, err := b.getSkMsgArgs()
	if err != nil {
		return err
	}

	return b.loadBPF(objPath, progPath, "sk_msg", mapArgs)
}

func (b *BPFLib) LoadSkMsgAuto() error {
	return b.LoadSkMsg(redirFilename)
}

func (b *BPFLib) RemoveSkMsg() error {
	progPath := filepath.Join(b.sockmapDir, skMsgProgName)
	return os.Remove(progPath)
}

func (b *BPFLib) AttachToCgroup() error {
	progPath := filepath.Join(b.sockmapDir, sockopsProgName)

	if b.cgroupV2Dir == "" {
		return errors.New("cgroup V2 not mounted")
	}

	prog := "bpftool"
	args := []string{
		"cgroup",
		"attach",
		b.cgroupV2Dir,
		"sock_ops",
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to attach sockops prog to cgroup: %s\n%s", err, output)
	}

	return nil
}

func (b *BPFLib) DetachFromCgroup(mode FindObjectMode) error {
	progPath := filepath.Join(b.sockmapDir, sockopsProgName)

	if b.cgroupV2Dir == "" {
		return errors.New("cgroup V2 not mounted")
	}

	prog := "bpftool"
	args := []string{
		"cgroup",
		"detach",
		b.cgroupV2Dir,
		"sock_ops",
		"pinned",
		progPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		if mode != FindByID {
			return fmt.Errorf("failed to detach sockops prog from cgroup: %s\n%s", err, output)
		}

		progID, err2 := b.getAttachedSockopsID()
		if err2 != nil {
			return fmt.Errorf("failed to detach sockops prog from cgroup: %s\n%s\n\nfailed to get the id of the program: %s", err, output, err2)
		}
		if progID >= 0 {
			args := []string{
				"cgroup",
				"detach",
				b.cgroupV2Dir,
				"sock_ops",
				"id",
				fmt.Sprintf("%d", progID)}

			printCommand(prog, args...)
			output2, err2 := exec.Command(prog, args...).CombinedOutput()
			if err2 != nil {
				return fmt.Errorf("failed to detach sockops prog from cgroup: %s\n%s\n\nfailed to detach sockops prog from cgroup by id: %s\n%s", err, output, err2, output2)
			}
		}
	}

	return nil
}

func (b *BPFLib) NewSockmap() (string, error) {
	mapPath := filepath.Join(b.sockmapDir, sockMapName)

	keySize := 12
	valueSize := 4

	return newMap(sockMapName,
		mapPath,
		"sockhash",
		65535,
		keySize,
		valueSize,
		0,
	)
}

func (b *BPFLib) NewSockmapEndpointsMap() (string, error) {
	mapPath := filepath.Join(b.sockmapDir, sockmapEndpointsMapName)

	keySize := 8
	valueSize := 4

	return newMap(sockmapEndpointsMapName,
		mapPath,
		"lpm_trie",
		65535,
		keySize,
		valueSize,
		1, // BPF_F_NO_PREALLOC
	)

}

func (b *BPFLib) UpdateSockmapEndpoints(ip net.IP, mask int) error {
	mapPath := filepath.Join(b.sockmapDir, sockmapEndpointsMapName)

	if err := os.MkdirAll(b.sockmapDir, 0700); err != nil {
		return err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return err
	}
	hexValue := []string{"01", "00", "00", "00"}

	prog := "bpftool"
	args := []string{
		"map",
		"update",
		"pinned",
		mapPath,
		"key",
		"hex"}
	args = append(args, hexKey...)
	args = append(args, "value", "hex")
	args = append(args, hexValue...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update map (%s) with (%v/%d): %s\n%s", sockmapEndpointsMapName, ip, mask, err, output)
	}

	return nil
}

func (b *BPFLib) DumpSockmapEndpointsMap(family IPFamily) ([]CIDRMapKey, error) {
	mapPath := filepath.Join(b.sockmapDir, sockmapEndpointsMapName)

	if err := os.MkdirAll(b.sockmapDir, 0700); err != nil {
		return nil, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"dump",
		"pinned",
		mapPath}

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to dump in map (%s): %s\n%s", sockmapEndpointsMapName, err, output)
	}

	var al []mapEntry
	err = json.Unmarshal(output, &al)
	if err != nil {
		return nil, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	var s []CIDRMapKey
	for _, l := range al {
		ipnet, err := hexToIPNet(l.Key, family)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bpf map key (%v) to ip and mask: %v", l.Key, err)
		}

		s = append(s, NewCIDRMapKey(ipnet))
	}

	return s, nil
}

func (b *BPFLib) LookupSockmapEndpointsMap(ip net.IP, mask int) (bool, error) {
	mapPath := filepath.Join(b.sockmapDir, sockmapEndpointsMapName)

	if err := os.MkdirAll(b.sockmapDir, 0700); err != nil {
		return false, err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return false, err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"lookup",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to lookup in map (%s): %s\n%s", sockmapEndpointsMapName, err, output)
	}

	l := mapEntry{}
	err = json.Unmarshal(output, &l)
	if err != nil {
		return false, fmt.Errorf("cannot parse json output: %v\n%s", err, output)
	}
	if l.Err != "" {
		return false, fmt.Errorf("%s", l.Err)
	}

	return true, err
}

func (b *BPFLib) RemoveItemSockmapEndpointsMap(ip net.IP, mask int) error {
	mapPath := filepath.Join(b.sockmapDir, sockmapEndpointsMapName)

	if err := os.MkdirAll(b.sockmapDir, 0700); err != nil {
		return err
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), mask)

	hexKey, err := CidrToHex(cidr)
	if err != nil {
		return err
	}

	prog := "bpftool"
	args := []string{
		"--json",
		"--pretty",
		"map",
		"delete",
		"pinned",
		mapPath,
		"key",
		"hex"}

	args = append(args, hexKey...)

	printCommand(prog, args...)
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to lookup in map (%s): %s\n%s", sockmapEndpointsMapName, err, output)
	}

	return nil
}

func (b *BPFLib) RemoveSockmapEndpointsMap() error {
	mapPath := filepath.Join(b.sockmapDir, sockmapEndpointsMapName)

	return os.Remove(mapPath)
}

func isAtLeastKernel(v *environment.Version) error {
	versionReader, err := environment.GetKernelVersionReader()
	if err != nil {
		return fmt.Errorf("failed to get kernel version reader: %v", err)
	}

	kernelVersion, err := environment.GetKernelVersion(versionReader)
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %v", err)
	}

	if kernelVersion.Compare(v) < 0 {
		return fmt.Errorf("kernel is too old (have: %v but want at least: %v)", kernelVersion, v)
	}

	return nil
}

func SupportsSockmap() error {
	if err := isAtLeastKernel(v4Dot20Dot0); err != nil {
		return err
	}

	// Test endianness
	if nativeEndian != binary.LittleEndian {
		return fmt.Errorf("this bpf library only supports little endian architectures")
	}

	return nil
}

func GetMinKernelVersionForDistro(distName string) *environment.Version {
	return distToVersionMap[distName]
}

func SupportsBPFDataplane() error {
	distName := environment.GetDistributionName()
	if err := isAtLeastKernel(GetMinKernelVersionForDistro(distName)); err != nil {
		return err
	}

	// Test endianness
	if nativeEndian != binary.LittleEndian {
		return errors.New("this bpf library only supports little endian architectures")
	}

	if !SyscallSupport() {
		return errors.New("BPF syscall support is not available on this platform")
	}

	return nil
}

// KTimeNanos returns a nanosecond timestamp that is comparable with the ones generated by BPF.
func KTimeNanos() int64 {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		log.WithError(err).Panic("Failed to read system clock")
	}
	return ts.Nano()
}

const jumpMapVersion = 2

func JumpMapName() string {
	return fmt.Sprintf("cali_jump%d", jumpMapVersion)
}
