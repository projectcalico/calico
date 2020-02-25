// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package ut_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/projectcalico/felix/ip"

	"github.com/projectcalico/felix/bpf/ipsets"
	"github.com/projectcalico/felix/bpf/jump"
	"github.com/projectcalico/felix/bpf/polprog"
	"github.com/projectcalico/felix/bpf/state"
	"github.com/projectcalico/felix/logutils"

	"github.com/projectcalico/felix/idalloc"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	. "github.com/onsi/gomega/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/conntrack"
	"github.com/projectcalico/felix/bpf/nat"
	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/proto"
)

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)
}

// Constants that are shared with the UT binaries that we build.
const (
	natTunnelMTU       = uint16(700)
	ethernetHeaderSize = 14
	testVxlanPort      = uint16(5665)
)

var (
	rulesDefaultAllow = [][][]*proto.Rule{{{{Action: "Allow"}}}}
	node1ip           = net.IPv4(10, 10, 0, 1).To4()
	node2ip           = net.IPv4(10, 10, 0, 2).To4()
)

// Globals that we use to configure the next test run.
var (
	hostIP  = node1ip
	skbMark uint32
)

const (
	resTC_ACT_OK int = iota
	resTC_ACT_RECLASSIFY
	resTC_ACT_SHOT
	resTC_ACT_PIPE
	resTC_ACT_STOLEN
	resTC_ACT_QUEUED
	resTC_ACT_REPEAT
	resTC_ACT_REDIRECT
	resTC_ACT_UNSPEC = (1 << 32) - 1
)

var retvalToStr = map[int]string{
	resTC_ACT_OK:         "TC_ACT_OK",
	resTC_ACT_RECLASSIFY: "TC_ACT_RECLASSIFY",
	resTC_ACT_SHOT:       "TC_ACT_SHOT",
	resTC_ACT_PIPE:       "TC_ACT_PIPE",
	resTC_ACT_STOLEN:     "TC_ACT_STOLEN",
	resTC_ACT_QUEUED:     "TC_ACT_QUEUED",
	resTC_ACT_REPEAT:     "TC_ACT_REPEAT",
	resTC_ACT_REDIRECT:   "TC_ACT_REDIRECT",
	resTC_ACT_UNSPEC:     "TC_ACT_UNSPEC",
}

func TestCompileTemplateRun(t *testing.T) {
	runBpfTest(t, "calico_to_workload_ep", nil, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketUDPDefault()
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())

		// Implicitly denied by normal policy: DROP
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})
}

// runBpfTest runs a specific section of the entire bpf program in isolation
func runBpfTest(t *testing.T, section string, rules [][][]*proto.Rule, testFn func(bpfProgRunFn)) {
	RegisterTestingT(t)

	tempDir, err := ioutil.TempDir("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	obj := "../../bpf-gpl/bin/test_"
	if strings.Contains(section, "from") {
		obj += "from_"
	} else {
		obj += "to_"
	}

	if strings.Contains(section, "host") {
		obj += "hep_"
	} else {
		obj += "wep_"
	}

	log.WithField("hostIP", hostIP).Info("Host IP")
	ipStr := fmt.Sprintf("0x%02x%02x%02x%02x", hostIP[3], hostIP[2], hostIP[1], hostIP[0])
	obj += fmt.Sprintf("fib_debug_skb0x%x_host%s", skbMark, ipStr)

	if strings.Contains(section, "_dsr") {
		obj += "_dsr"
		// XXX bit of a hack, we should change the section names to contain _dsr
		section = strings.Trim(section, "_dsr")
	}

	obj += ".o"

	err = bpftoolProgLoadAll(obj, bpfFsDir)
	Expect(err).NotTo(HaveOccurred())

	if err != nil {
		t.Log("Error:", string(err.(*exec.ExitError).Stderr))
	}
	Expect(err).NotTo(HaveOccurred())

	alloc := &forceAllocator{alloc: idalloc.New()}
	pg := polprog.NewBuilder(alloc, ipsMap.MapFD(), stateMap.MapFD(), jumpMap.MapFD())
	insns, err := pg.Instructions(rules)
	Expect(err).NotTo(HaveOccurred())
	polProgFD, err := bpf.LoadBPFProgramFromInsns(insns, "Apache-2.0")
	Expect(err).NotTo(HaveOccurred())
	progFDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(progFDBytes, uint32(polProgFD))
	err = jumpMap.Update([]byte{0, 0, 0, 0}, progFDBytes)
	Expect(err).NotTo(HaveOccurred())

	t.Run(section, func(_ *testing.T) {
		testFn(func(dataIn []byte) (bpfRunResult, error) {
			res, err := bpftoolProgRun(bpfFsDir+"/"+section, dataIn)
			log.Debugf("dataIn  = %+v", dataIn)
			if err == nil {
				log.Debugf("dataOut = %+v", res.dataOut)
			}
			return res, err
		})
	})
}

type forceAllocator struct {
	alloc *idalloc.IDAllocator
}

func (a *forceAllocator) GetNoAlloc(id string) uint64 {
	return a.alloc.GetOrAlloc(id)
}

func bpftool(args ...string) ([]byte, error) {
	args = append([]string{"--json", "--pretty"}, args...)
	cmd := exec.Command("bpftool", args...)
	log.WithField("cmd", cmd.String()).Debugf("executing")
	out, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			log.WithField("stderr", string(e.Stderr)).Errorf("bpftool %s failed", args[2])
			// to make the output reflect the new lines, logrus ignores it
			fmt.Print(fmt.Sprint(string(e.Stderr)))
		}
	}

	return out, err
}

var (
	mapInitOnce sync.Once

	natMap, natBEMap, ctMap, rtMap, ipsMap, stateMap, testStateMap, jumpMap, affinityMap bpf.Map
	allMaps                                                                              []bpf.Map
)

func initMapsOnce() {
	mapInitOnce.Do(func() {
		mc := &bpf.MapContext{}

		natMap = nat.FrontendMap(mc)
		natBEMap = nat.BackendMap(mc)
		ctMap = conntrack.Map(mc)
		rtMap = routes.Map(mc)
		ipsMap = ipsets.Map(mc)
		stateMap = state.Map(mc)
		testStateMap = state.MapForTest(mc)
		jumpMap = jump.MapForTest(mc)
		affinityMap = nat.AffinityMap(mc)

		allMaps = []bpf.Map{natMap, natBEMap, ctMap, rtMap, ipsMap, stateMap, testStateMap, jumpMap, affinityMap}
		for _, m := range allMaps {
			err := m.EnsureExists()
			if err != nil {
				log.WithError(err).Panic("Failed to initialise maps")
			}
		}
	})
}

func cleanUpMaps() {
	log.Info("Cleaning up all maps")
	for _, m := range allMaps {
		if m == stateMap || m == testStateMap || m == jumpMap {
			continue // Can't clean up array maps
		}
		var allKeys [][]byte
		err := m.Iter(func(k, v []byte) {
			allKeys = append(allKeys, k)
		})
		if err != nil {
			log.WithError(err).Panic("Failed to walk map")
		}
		for _, k := range allKeys {
			_ = m.Delete(k)
		}
	}
	log.Info("Cleaned up all maps")
}

func bpftoolProgLoadAll(fname, bpfFsDir string) error {
	log.WithField("program", fname).Debug("Loading BPF program")
	_, err := bpftool("prog", "loadall", fname, bpfFsDir, "type", "classifier",
		"map", "name", natMap.GetName(), "pinned", natMap.Path(),
		"map", "name", natBEMap.GetName(), "pinned", natBEMap.Path(),
		"map", "name", ctMap.GetName(), "pinned", ctMap.Path(),
		"map", "name", rtMap.GetName(), "pinned", rtMap.Path(),
		"map", "name", jumpMap.GetName(), "pinned", jumpMap.Path(),
		"map", "name", stateMap.GetName(), "pinned", stateMap.Path(),
		"map", "name", affinityMap.GetName(), "pinned", affinityMap.Path(),
	)
	if err != nil {
		return err
	}

	_, err = bpftool("map", "update", "pinned", jumpMap.Path(), "key", "0", "0", "0", "0", "value", "pinned", path.Join(bpfFsDir, "1_0"))
	if err != nil {
		return errors.Wrap(err, "failed to update jump map (epilogue program)")
	}
	_, err = bpftool("map", "update", "pinned", jumpMap.Path(), "key", "1", "0", "0", "0", "value", "pinned", path.Join(bpfFsDir, "1_1"))
	if err != nil {
		return errors.Wrap(err, "failed to update jump map (epilogue program)")
	}

	return nil
}

type bpfRunResult struct {
	Retval   int
	Duration int
	dataOut  []byte
}

func (r bpfRunResult) RetvalStr() string {
	s := retvalToStr[r.Retval]
	if s == "" {
		return fmt.Sprint(r.Retval)
	}
	return s
}

func bpftoolProgRun(progName string, dataIn []byte) (bpfRunResult, error) {
	var res bpfRunResult

	tempDir, err := ioutil.TempDir("", "bpftool-data-")
	Expect(err).NotTo(HaveOccurred())

	defer os.RemoveAll(tempDir)

	dataInFname := tempDir + "/data_in"
	dataOutFname := tempDir + "/data_out"

	if err := ioutil.WriteFile(dataInFname, dataIn, 0644); err != nil {
		return res, errors.Errorf("failed to write input data in file: %s", err)
	}

	out, err := bpftool("prog", "run", "pinned", progName, "data_in", dataInFname, "data_out", dataOutFname)
	if err != nil {
		return res, err
	}

	if err := json.Unmarshal(out, &res); err != nil {
		return res, errors.Errorf("failed to unmarshall json: %s", err)
	}

	res.dataOut, err = ioutil.ReadFile(dataOutFname)
	if err != nil {
		return res, errors.Errorf("failed to read output data from file: %s", err)
	}

	return res, nil
}

type bpfProgRunFn func(data []byte) (bpfRunResult, error)

// runBpfUnitTest runs a small unit in isolation. It requires a small .c file
// that wrapsthe unit and compiles into a calico_unittest section.
func runBpfUnitTest(t *testing.T, source string, testFn func(bpfProgRunFn)) {
	RegisterTestingT(t)

	tempDir, err := ioutil.TempDir("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	objFname := "../../bpf-gpl/ut/" + strings.TrimSuffix(source, path.Ext(source)) + ".o"

	err = bpftoolProgLoadAll(objFname, bpfFsDir)
	Expect(err).NotTo(HaveOccurred())

	t.Run(source, func(_ *testing.T) {
		testFn(func(dataIn []byte) (bpfRunResult, error) {
			res, err := bpftoolProgRun(bpfFsDir+"/calico_unittest", dataIn)
			log.Debugf("dataIn  = %+v", dataIn)
			if err == nil {
				log.Debugf("dataOut = %+v", res.dataOut)
			}
			return res, err
		})
	})
}

// layersMatchFields matches all Exported fields and ignore the ones explicitly
// listed. It always ignores BaseLayer as that is not set by the tests.
func layersMatchFields(l gopacket.Layer, ignore ...string) GomegaMatcher {
	toIgnore := make(map[string]bool)
	for _, x := range ignore {
		toIgnore[x] = true
	}

	toIgnore["BaseLayer"] = true

	f := Fields{}
	v := reflect.Indirect(reflect.ValueOf(l))
	if v.Kind() != reflect.Struct {
		return Reject()
	}

	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if !toIgnore[name] && v.Field(i).CanInterface() {
			val := v.Field(i).Interface()
			f[name] = Equal(val)
		}
	}

	return PointTo(MatchFields(IgnoreMissing|IgnoreExtras, f))
}

func udpResposeRaw(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv4L := pkt.Layer(layers.LayerTypeIPv4)
	ipv4R := ipv4L.(*layers.IPv4)
	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	udpL := pkt.Layer(layers.LayerTypeUDP)
	udpR := udpL.(*layers.UDP)
	udpR.SrcPort, udpR.DstPort = udpR.DstPort, udpR.SrcPort

	_ = udpR.SetNetworkLayerForChecksum(ipv4R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, udpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func dumpNATMap(natMap bpf.Map) {
	nt, err := nat.LoadFrontendMap(natMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range nt {
		fmt.Printf("%s : %s\n", k, v)
	}
}

func dumpCTMap(ctMap bpf.Map) {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("Conntrack dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func resetCTMap(ctMap bpf.Map) {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	for k := range ct {
		err := ctMap.Delete(k[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func saveCTMap(ctMap bpf.Map) conntrack.MapMem {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	return ct
}

func restoreCTMap(ctMap bpf.Map, m conntrack.MapMem) {
	for k, v := range m {
		err := ctMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func dumpRTMap(rtMap bpf.Map) {
	rt, err := routes.LoadMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range rt {
		fmt.Printf("%15s: %s\n", k.Dest(), v)
	}
}

func resetRTMap(ctMap bpf.Map) {
	rt, err := routes.LoadMap(ctMap)
	Expect(err).NotTo(HaveOccurred())
	for k := range rt {
		err := rtMap.Delete(k[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

var ethDefault = &layers.Ethernet{
	SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
	DstMAC:       []byte{0, 0, 0, 0, 0, 2},
	EthernetType: layers.EthernetTypeIPv4,
}

var payloadDefault = []byte("ABCDEABCDEXXXXXXXXXXXX")

var srcIP = net.IPv4(1, 1, 1, 1)
var dstIP = net.IPv4(2, 2, 2, 2)
var srcV4CIDR = ip.CIDRFromNetIP(srcIP).(ip.V4CIDR)

var ipv4Default = &layers.IPv4{
	Version:  4,
	IHL:      5,
	TTL:      64,
	Flags:    layers.IPv4DontFragment,
	SrcIP:    srcIP,
	DstIP:    dstIP,
	Protocol: layers.IPProtocolUDP,
}

var udpDefault = &layers.UDP{
	SrcPort: 1234,
	DstPort: 5678,
}

func testPacket(ethAlt *layers.Ethernet, ipv4Alt *layers.IPv4, l4Alt gopacket.Layer, payloadAlt []byte) (
	*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {

	var (
		eth     *layers.Ethernet
		ipv4    *layers.IPv4
		udp     *layers.UDP
		tcp     *layers.TCP
		icmp    *layers.ICMPv4
		payload []byte
	)

	if ethAlt != nil {
		eth = ethAlt
	} else {
		eth = ethDefault
	}

	if ipv4Alt != nil {
		ipv4 = ipv4Alt
	} else {
		ipv4 = ipv4Default
	}

	if l4Alt != nil {
		switch v := l4Alt.(type) {
		case *layers.UDP:
			udp = v
		case *layers.TCP:
			tcp = v
		case *layers.ICMPv4:
			icmp = v
		default:
			return nil, nil, nil, nil, nil, errors.Errorf("unrecognized l4 layer type %t", l4Alt)
		}
	} else {
		udp = udpDefault
	}

	if payloadAlt != nil {
		payload = payloadAlt
	} else {
		payload = payloadDefault
	}

	switch {
	case udp != nil:
		ipv4.Length = uint16(5*4 + 8 + len(payload))
		udp.Length = uint16(8 + len(payload))
		_ = udp.SetNetworkLayerForChecksum(ipv4)

		pkt := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
			eth, ipv4, udp, gopacket.Payload(payload))

		return eth, ipv4, udp, payload, pkt.Bytes(), err
	case tcp != nil:
		return nil, nil, nil, nil, nil, errors.Errorf("tcp not implemented yet")
	case icmp != nil:
		ipv4.Length = uint16(5*4 + 8 + len(payload))

		pkt := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
			eth, ipv4, icmp, gopacket.Payload(payload))

		return eth, ipv4, icmp, payload, pkt.Bytes(), err
	}

	panic("UNREACHABLE")
}

func testPacketUDPDefault() (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	return testPacket(nil, nil, nil, nil)
}
