// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/projectcalico/felix/bpf/tc"

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
	log.SetLevel(log.DebugLevel)
}

var (
	hostIP            = net.IPv4(10, 10, 0, 1)
	natTunnelMTU      = uint16(700)
	testVxlanPort     = uint16(5665)
	rulesDefaultAllow = [][][]*proto.Rule{{{{Action: "Allow"}}}}
	skbMark           uint32
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

var defaultCompileOpts = []tc.CompileOption{
	tc.CompileWithBpftoolLoader(),
	tc.CompileWithWorkingDir("../tc/templates"),
	tc.CompileWithSourceName("../tc/templates/tc_template.c"), // Relative to our dir
	tc.CompileWithIncludePath("../../include"),                // Relative to working dir
	tc.CompileWithFIBEnabled(true),
	tc.CompileWithLogLevel("DEBUG"),
	tc.CompileWithVxlanPort(testVxlanPort),
	tc.CompileWithNATTunnelMTU(natTunnelMTU),
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

	objFname := tempDir + "/tc.o"
	opts := append(defaultCompileOpts,
		tc.CompileWithOutputName(objFname),
		tc.CompileWithLogPrefix(section),
		tc.CompileWithEntrypointName(section),
		tc.CompileWithFlags(tc.SectionToFlags[section]),
		tc.CompileWithHostIP(hostIP), // to pick up new ip
		tc.CompileWithDefineValue("CALI_SET_SKB_MARK", fmt.Sprintf("0x%x", skbMark)),
	)

	err = tc.CompileProgramToFile(rules, idalloc.New(), opts...)
	Expect(err).NotTo(HaveOccurred())

	err = bpftoolProgLoadAll(objFname, bpfFsDir)
	if err != nil {
		t.Log("Error:", string(err.(*exec.ExitError).Stderr))
	}
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

func bpftoolProgLoadAll(fname, bpfFsDir string) error {
	mc := &bpf.MapContext{}
	natMap := nat.FrontendMap(mc)
	err := natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap(mc)
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	ctMap := conntrack.Map(mc)
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	rtMap := routes.Map(mc)
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// We need to populate the jump table map as tc would do.  It has to be populated with file descriptors for the
	// BPF programs so our standard map machinery isn't much use.  For now, just use bpftool.
	jumpMapPath := path.Join(bpfFsDir, "cali_jump")
	_, err = bpftool("map", "create", jumpMapPath, "type", "prog_array", "key", "4", "value", "4", "entries", "8", "name", "cali_jump")
	if err != nil {
		return err
	}

	_, err = bpftool("prog", "loadall", fname, bpfFsDir, "type", "classifier",
		"map", "name", natMap.GetName(), "pinned", natMap.Path(),
		"map", "name", natBEMap.GetName(), "pinned", natBEMap.Path(),
		"map", "name", ctMap.GetName(), "pinned", ctMap.Path(),
		"map", "name", rtMap.GetName(), "pinned", rtMap.Path(),
		"map", "name", "cali_jump", "pinned", jumpMapPath,
	)
	if err != nil {
		return err
	}

	// tc loads the program at section "1/0" into the map with id=1 (which is the jump map) and key=0.
	// bpftool pins section "1/0" into the file system as "1_0"; to populate the map, we just need to insert the
	// pinned program at the right key.
	_, err = bpftool("map", "update", "pinned", jumpMapPath, "key", "0", "0", "0", "0", "value", "pinned", path.Join(bpfFsDir, "1_0"))
	if err != nil {
		return err
	}
	_, err = bpftool("map", "update", "pinned", jumpMapPath, "key", "1", "0", "0", "0", "value", "pinned", path.Join(bpfFsDir, "1_1"))
	if err != nil {
		return err
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

var unittestH = `
/*
 * THIS FILE IS GENERATED
 */
 #ifndef __BPF_UNITTEST_H__
 #define __BPF_UNITTEST_H__
 #include "%s"
 #endif
`

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

	objFname := tempDir + "/" + strings.TrimSuffix(source, path.Ext(source))

	wdir := "../tc/templates"
	unittestFName := wdir + "/unittest.h"

	err = ioutil.WriteFile(unittestFName,
		[]byte(fmt.Sprintf(unittestH, source)), 0644)
	Expect(err).NotTo(HaveOccurred())

	defer os.Remove(unittestFName)

	curwd, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred())

	opts := append(defaultCompileOpts,
		tc.CompileWithOutputName(objFname),
		tc.CompileWithWorkingDir(wdir),
		tc.CompileWithSourceName(wdir+"/tc_template.c"),
		tc.CompileWithIncludePath(curwd+"/progs"),
		tc.CompileWithIncludePath("../include"),
		tc.CompileWithLogPrefix("UNITTEST"),
		tc.CompileWithDefine("CALI_UNITTEST"),
		tc.CompileWithHostIP(hostIP),
	)

	err = tc.CompileProgramToFile(nil, idalloc.New(), opts...)
	Expect(err).NotTo(HaveOccurred())

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

func dumpCTMap(ctMap bpf.Map) {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range ct {
		fmt.Printf("%s : %s\n", k, v)
	}
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

var ethDefault = &layers.Ethernet{
	SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
	DstMAC:       []byte{0, 0, 0, 0, 0, 2},
	EthernetType: layers.EthernetTypeIPv4,
}

var payloadDefault = []byte("ABCDEABCDEXXXXXXXXXXXX")

var ipv4Default = &layers.IPv4{
	Version:  4,
	IHL:      5,
	Flags:    layers.IPv4DontFragment,
	SrcIP:    net.IPv4(1, 1, 1, 1),
	DstIP:    net.IPv4(2, 2, 2, 2),
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
