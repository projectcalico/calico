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
	"github.com/projectcalico/felix/idalloc"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/dataplane/linux"
)

func TestCompileTemplateRun(tt *testing.T) {
	t := NewWithT(tt)

	tempDir, err := ioutil.TempDir("", "calico-bpf-")
	t.Expect(err).NotTo(HaveOccurred())

	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	t.Expect(err).NotTo(HaveOccurred())

	defer os.RemoveAll(bpfFsDir)

	objFname := tempDir + "/redir_tc.o"

	err = intdataplane.CompileTCProgramToFile(nil,
		idalloc.New(),
		intdataplane.CompileWithBpftoolLoader(),
		intdataplane.CompileWithWorkingDir("../xdp"),
		intdataplane.CompileWithSourceName("../xdp/redir_tc.c"),
		intdataplane.CompileWithOutputName(objFname),
		intdataplane.CompileWithFIBEnabled(true),
		intdataplane.CompileWithLogLevel("DEBUG"),
		intdataplane.CompileWithLogPrefix("COMPILE_TEST"),
	)
	t.Expect(err).NotTo(HaveOccurred())

	err = bpftoolProgLoadAll(objFname, bpfFsDir)
	t.Expect(err).NotTo(HaveOccurred())

	dataInFname := tempDir + "/data_in"

	payload := []byte("ABCDEABCDEXXXXXXXXXXXX")
	pkt := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{},
		&layers.Ethernet{
			// zeroed MACs, does not matter
			SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
			DstMAC:       []byte{0, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.IPv4(1, 1, 1, 1),
			DstIP:    net.IPv4(2, 2, 2, 2),
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 1234,
			DstPort: 5678,
			Length:  uint16(len(payload)),
		},
		gopacket.Payload(payload),
	)
	t.Expect(err).NotTo(HaveOccurred())

	err = ioutil.WriteFile(dataInFname, pkt.Bytes(), 0644)
	t.Expect(err).NotTo(HaveOccurred())

	res, err := bpftoolProgRun(bpfFsDir+"/calico_to_workload_ep", dataInFname)
	t.Expect(err).NotTo(HaveOccurred())

	// Implicitly denied by normal policy: DROP
	t.Expect(res.Retval).To(Equal(2))
}

func bpftool(args ...string) ([]byte, error) {
	args = append([]string{"--json", "--pretty"}, args...)
	cmd := exec.Command("bpftool", args...)
	return cmd.Output()
}

func bpftoolProgLoadAll(fname, bpfFsDir string) error {
	_, err := bpftool("prog", "loadall", fname, bpfFsDir, "type", "classifier")
	return err
}

type runResult struct {
	Retval   int
	Duration int
}

func bpftoolProgRun(progName, dataInFname string) (runResult, error) {
	var res runResult

	out, err := bpftool("prog", "run", "pinned", progName, "data_in", dataInFname)
	if err != nil {
		return res, err
	}

	err = json.Unmarshal(out, &res)

	return res, err
}
