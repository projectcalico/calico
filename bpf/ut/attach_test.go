// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/tc"
)

func TestJumpMapCleanup(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := bpf.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

	ap := tc.AttachPoint{
		Type:     tc.EpTypeWorkload,
		ToOrFrom: tc.ToEp,
		Hook:     tc.HookIngress,
		DSR:      true,
		LogLevel: "DEBUG",
	}

	t.Run(ap.ProgramName(), func(t *testing.T) {
		RegisterTestingT(t)

		vethName, veth := createVeth()
		defer deleteLink(veth)

		ap.Iface = vethName

		log.Debugf("Testing %v in %v", ap.ProgramName(), ap.FileName())

		// Start with a clean base state in case another test left something behind.
		t.Log("Doing initial clean up")
		tc.CleanUpJumpMaps()

		t.Log("Adding program, should add one dir and one map.")
		startingJumpMaps := countJumpMaps()
		startingTCDirs := countTCDirs()
		ap.HostIP = net.ParseIP("10.0.0.1")
		err := tc.EnsureQdisc(ap.Iface)
		Expect(err).NotTo(HaveOccurred())
		err = ap.AttachProgram()
		Expect(err).NotTo(HaveOccurred())
		Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+1), "unexpected number of jump maps")
		Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+1), "unexpected number of TC dirs")

		t.Log("Replacing program should add another map and dir.")
		ap.HostIP = net.ParseIP("10.0.0.2")
		err = ap.AttachProgram()
		Expect(err).NotTo(HaveOccurred())
		Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+2), "unexpected number of jump maps after replacing program")
		Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+2), "unexpected number of TC dirs after replacing program")

		t.Log("Cleaning up, should remove the first map.")
		tc.CleanUpJumpMaps()
		Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps+1), "unexpected number of jump maps after clean up")
		Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs+1), "unexpected number of TC dirs after clean up")

		// Remove the program.
		t.Log("Removing all programs and cleaning up, should return to base state.")
		err = tc.RemoveQdisc(vethName)
		Expect(err).NotTo(HaveOccurred())
		tc.CleanUpJumpMaps()
		Expect(countJumpMaps()).To(BeNumerically("==", startingJumpMaps), "unexpected number of jump maps")
		Expect(countTCDirs()).To(BeNumerically("==", startingTCDirs), "unexpected number of TC dirs")
	})
}

func countJumpMaps() int {
	var count int
	err := filepath.Walk("/sys/fs/bpf/tc", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), "cali_jump") {
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
		if info.IsDir() && len(info.Name()) == 40 {
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
