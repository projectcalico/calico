// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

package ut

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/tc"
	"github.com/projectcalico/calico/felix/bpf/xdp"
)

func TestReattachPrograms(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := bpf.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

	// TC program 1
	ap1 := tc.AttachPoint{
		Type:     tc.EpTypeWorkload,
		ToOrFrom: tc.ToEp,
		Hook:     bpf.HookIngress,
		DSR:      true,
		LogLevel: "DEBUG",
	}
	vethName1, veth1 := createVeth()
	defer deleteLink(veth1)
	ap1.Iface = vethName1
	log.Debugf("Testing %v in %v", ap1.ProgramName(), ap1.FileName())

	// TC program 2
	ap2 := tc.AttachPoint{
		Type:     tc.EpTypeWorkload,
		ToOrFrom: tc.ToEp,
		Hook:     bpf.HookEgress,
		DSR:      false,
		LogLevel: "DEBUG",
	}
	vethName2, veth2 := createVeth()
	defer deleteLink(veth2)
	ap2.Iface = vethName2
	log.Debugf("Testing %v in %v", ap2.ProgramName(), ap2.FileName())

	// XDP Program 1
	ap3 := xdp.AttachPoint{
		LogLevel: "DEBUG",
		Modes:    []bpf.XDPMode{bpf.XDPGeneric},
	}
	vethName3, veth3 := createVeth()
	defer deleteLink(veth3)
	ap3.Iface = vethName3
	log.Debugf("Testing %v in %v", ap3.SectionName(), ap3.FileName())

	// Start with a clean base state in case another test left something behind.
	t.Log("Doing initial clean up")
	tc.CleanUpMaps()
	bpf.CleanAttachedProgDir()

	startingJumpMaps := countJumpMaps()
	startingTCDirs := countTCDirs()
	startingHashFiles := countHashFiles()

	// Attach the first TC program
	t.Log("Adding program, should add one dir and one map")
	ap1.HostIP = net.ParseIP("10.0.0.1")
	ap1.IntfIP = net.ParseIP("10.0.0.2")
	err = tc.EnsureQdisc(ap1.Iface)
	Expect(err).NotTo(HaveOccurred())
	ap1ProgIdOld, err := ap1.AttachProgram()
	Expect(err).NotTo(HaveOccurred())
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+1), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+1), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles+1), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).To(BeARegularFile())

	// Reattach the same TC program
	t.Log("Replacing program should not add another map and dir")
	ap1ProgIdNew, err := ap1.AttachProgram()
	Expect(err).NotTo(HaveOccurred())
	Expect(ap1ProgIdOld).To(Equal(ap1ProgIdNew)) // no change, no reload
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+1), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+1), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles+1), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).To(BeARegularFile())

	t.Log("Replacing program should not add another map and dir")
	ap1.HostIP = net.ParseIP("10.0.0.3")
	ap1.IntfIP = net.ParseIP("10.0.0.4")
	ap1ProgIdOld = ap1ProgIdNew
	ap1ProgIdNew, err = ap1.AttachProgram()
	Expect(err).NotTo(HaveOccurred())
	Expect(ap1ProgIdOld).NotTo(Equal(ap1ProgIdNew)) // because we changed configuration, so reloaded

	// Attach the second TC program
	t.Log("Adding another program, should add one dir and one map")
	ap2.HostIP = net.ParseIP("10.0.1.1")
	ap2.IntfIP = net.ParseIP("10.0.1.2")
	err = tc.EnsureQdisc(ap2.Iface)
	Expect(err).NotTo(HaveOccurred())
	_, err = ap2.AttachProgram()
	Expect(err).NotTo(HaveOccurred())
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+2), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+2), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles+2), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).To(BeARegularFile())
	Expect(bpf.RuntimeJSONFilename(ap2.IfaceName(), "egress")).To(BeARegularFile())

	// Attach the first XDP program
	t.Log("Adding another program (XDP), should add one dir and one map")
	ap2.HostIP = net.ParseIP("10.0.3.1")
	ap2.IntfIP = net.ParseIP("10.0.3.2")
	_, err = ap3.AttachProgram()
	Expect(err).NotTo(HaveOccurred())
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+3), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+3), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles+3), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).To(BeARegularFile())
	Expect(bpf.RuntimeJSONFilename(ap2.IfaceName(), "egress")).To(BeARegularFile())
	Expect(bpf.RuntimeJSONFilename(ap3.IfaceName(), "xdp")).To(BeARegularFile())

	// Clean up maps, but nothing should change
	t.Log("Cleaning up, should remove the first map")
	tc.CleanUpMaps()
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+3), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+3), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles+3), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).To(BeARegularFile())
	Expect(bpf.RuntimeJSONFilename(ap2.IfaceName(), "egress")).To(BeARegularFile())
	Expect(bpf.RuntimeJSONFilename(ap3.IfaceName(), "xdp")).To(BeARegularFile())

	// Remove both TC programs
	t.Log("Removing all TC programs and cleaning up their jump maps, should keep only one jump map and hash file")
	err = tc.RemoveQdisc(vethName1)
	Expect(err).NotTo(HaveOccurred())
	err = tc.RemoveQdisc(vethName2)
	Expect(err).NotTo(HaveOccurred())
	tc.CleanUpMaps()
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+1), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+1), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles+1), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).ToNot(BeAnExistingFile())
	Expect(bpf.RuntimeJSONFilename(ap2.IfaceName(), "egress")).ToNot(BeAnExistingFile())
	Expect(bpf.RuntimeJSONFilename(ap3.IfaceName(), "xdp")).To(BeARegularFile())

	// Reattach the same XDP program, nothing should change
	t.Log("Reattaching the same XDP program, should not add any dir or map")
	ap2.HostIP = net.ParseIP("10.0.3.3")
	ap2.IntfIP = net.ParseIP("10.0.3.4")
	_, err = ap3.AttachProgram()
	Expect(err).NotTo(HaveOccurred())
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+1), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+1), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles+1), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).ToNot(BeAnExistingFile())
	Expect(bpf.RuntimeJSONFilename(ap2.IfaceName(), "egress")).ToNot(BeAnExistingFile())
	Expect(bpf.RuntimeJSONFilename(ap3.IfaceName(), "xdp")).To(BeARegularFile())

	// Remove the XDP program, everything should go back to the initial state
	t.Log("Removing the XDP program and cleaning up its jump map, should return to base state")
	err = ap3.DetachProgram()
	Expect(err).NotTo(HaveOccurred())
	tc.CleanUpMaps()
	Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps), "unexpected number of jump maps")
	Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs), "unexpected number of TC dirs")
	Expect(countHashFiles()).To(BeNumerically("==", startingHashFiles), "unexpected number of hash files")
	Expect(bpf.RuntimeJSONFilename(ap1.IfaceName(), "ingress")).ToNot(BeAnExistingFile())
	Expect(bpf.RuntimeJSONFilename(ap2.IfaceName(), "egress")).ToNot(BeAnExistingFile())
	Expect(bpf.RuntimeJSONFilename(ap3.IfaceName(), "xdp")).ToNot(BeAnExistingFile())
}

func countJumpMaps() int {
	var count int
	err := filepath.Walk("/sys/fs/bpf/tc", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), bpf.JumpMapName()) {
			log.Debugf("Jump map: %s", p)
			count++
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return count
}

func countTCDirs() int {
	var count int
	err := filepath.Walk("/sys/fs/bpf/tc", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			log.Debugf("TC dir: %s", p)
			count++
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return count
}

func countHashFiles() int {
	var count int
	err := filepath.Walk(bpf.RuntimeProgDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(info.Name(), ".json") {
			log.Debugf("Hash file: %s", p)
			count++
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return count
}
