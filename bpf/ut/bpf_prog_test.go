// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	intdataplane "github.com/projectcalico/felix/dataplane/linux"
	"github.com/projectcalico/felix/proto"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

var (
	hostIP            = net.IPv4(10, 10, 0, 1)
	testVxlanPort     = uint16(5665)
	rulesDefaultAllow = [][][]*proto.Rule{{{{Action: "Allow"}}}}
)

const (
	//	resTC_ACT_OK int = iota
	//	resTC_ACT_RECLASSIFY
	resTC_ACT_SHOT int = 2
	//	resTC_ACT_PIPE
	//	resTC_ACT_STOLEN
	//	resTC_ACT_QUEUED
	//	resTC_ACT_REPEAT
	//	resTC_ACT_REDIRECT
	resTC_ACT_UNSPEC = (1 << 32) - 1
)

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

	objFname := tempDir + "/redir_tc.o"

	err = intdataplane.CompileTCProgramToFile(rules,
		idalloc.New(),
		intdataplane.CompileWithBpftoolLoader(),
		intdataplane.CompileWithWorkingDir("../xdp"),
		intdataplane.CompileWithSourceName("../xdp/redir_tc.c"),
		intdataplane.CompileWithOutputName(objFname),
		intdataplane.CompileWithFIBEnabled(true),
		intdataplane.CompileWithLogLevel("DEBUG"),
		intdataplane.CompileWithLogPrefix(section),
		intdataplane.CompileWithHostIP(hostIP),
		intdataplane.CompileWithVxlanPort(testVxlanPort),
	)
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

	_, err = bpftool("prog", "loadall", fname, bpfFsDir, "type", "classifier",
		"map", "name", natMap.(*bpf.PinnedMap).Name, "pinned", natMap.(*bpf.PinnedMap).Filename,
		"map", "name", natBEMap.(*bpf.PinnedMap).Name, "pinned", natBEMap.(*bpf.PinnedMap).Filename,
		"map", "name", ctMap.(*bpf.PinnedMap).Name, "pinned", ctMap.(*bpf.PinnedMap).Filename,
	)
	return err
}

type bpfRunResult struct {
	Retval   int
	Duration int
	dataOut  []byte
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

	wdir := "../xdp"
	unittestFName := wdir + "/unittest.h"

	err = ioutil.WriteFile(unittestFName,
		[]byte(fmt.Sprintf(unittestH, source)), 0644)
	Expect(err).NotTo(HaveOccurred())

	defer os.Remove(unittestFName)

	curwd, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred())

	err = intdataplane.CompileTCProgramToFile(nil,
		idalloc.New(),
		intdataplane.CompileWithBpftoolLoader(),
		intdataplane.CompileWithWorkingDir(wdir),
		intdataplane.CompileWithSourceName(wdir+"/redir_tc.c"),
		intdataplane.CompileWithOutputName(objFname),
		intdataplane.CompileWithFIBEnabled(true),
		intdataplane.CompileWithLogLevel("DEBUG"),
		intdataplane.CompileWithLogPrefix("UNITTEST"),
		intdataplane.CompileWithDefine("CALI_UNITTEST"),
		intdataplane.CompileWithVxlanPort(testVxlanPort),
		intdataplane.CompileWithIncludePath(curwd+"/progs"),
		intdataplane.CompileWithHostIP(hostIP),
	)
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

var ethDefault = &layers.Ethernet{
	SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
	DstMAC:       []byte{0, 0, 0, 0, 0, 2},
	EthernetType: layers.EthernetTypeIPv4,
}

var payloadDefault = []byte("ABCDEABCDEXXXXXXXXXXXX")

var ipv4Default = &layers.IPv4{
	Version:  4,
	IHL:      5,
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
