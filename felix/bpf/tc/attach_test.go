// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package tc_test

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/tc"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func TestAttachPoint(t *testing.T) {
	RegisterTestingT(t)

	logLevel := log.GetLevel()
	defer log.SetLevel(logLevel)
	log.SetLevel(log.DebugLevel)

	progs, _ := bpf.GetAllProgs("classifier")
	Expect(progs).To(HaveLen(0))

	cmd := exec.Command("ip", "link", "add", "dummy", "type", "dummy")
	err := cmd.Run()

	defer func() {
		cmd := exec.Command("ip", "link", "delete", "dummy", "type", "dummy")
		_ = cmd.Run()
	}()

	Expect(err).ShouldNot(HaveOccurred())

	cmd = exec.Command("ip", "addr", "add", "1.1.1.1/24", "dev", "dummy")
	err = cmd.Run()
	Expect(err).ShouldNot(HaveOccurred())

	cmd = exec.Command("ip", "link", "set", "dummy", "up")
	err = cmd.Run()
	Expect(err).ShouldNot(HaveOccurred())

	err = os.MkdirAll("/sys/fs/bpf/tc/dummy_igr", 0777)
	Expect(err).ShouldNot(HaveOccurred())
	err = os.MkdirAll("/sys/fs/bpf/tc/dummy_egr", 0777)
	Expect(err).ShouldNot(HaveOccurred())

	err = tc.EnsureQdisc("dummy")
	Expect(err).ShouldNot(HaveOccurred())

	ap := tc.AttachPoint{
		Type:     tc.EpTypeWorkload,
		ToOrFrom: tc.FromEp,
		Hook:     bpf.HookIngress,
		Iface:    "dummy",
		LogLevel: "off",
		IntfIP:   net.ParseIP("1.1.1.1"),
		HostIP:   net.ParseIP("1.1.1.2"),
	}

	fds, err := ap.AttachPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(fds[0]).NotTo(Equal(bpf.MapFD(0)))
	Expect(fds[1]).To(Equal(bpf.MapFD(0)))
	closeFds(fds)

	progsPerPath := 1 /* main tc program */ + len(tcdefs.JumpMapIndexes["IPv4"]) - 1 /* host ct conflixt */

	Eventually(func() []bpf.ProgInfo {
		progs, _ := bpf.GetAllProgs("sched_cls")
		return progs
	}, "5s", "300ms").Should(HaveLen(progsPerPath))

	atp, err := ap.ListAttachedPrograms()
	Expect(err).ShouldNot(HaveOccurred())

	// Try the same again
	fds, err = ap.AttachPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(fds[0]).NotTo(Equal(bpf.MapFD(0)))
	Expect(fds[1]).To(Equal(bpf.MapFD(0)))
	closeFds(fds)

	atp2, err := ap.ListAttachedPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(atp).To(Equal(atp2))

	// Change configuration and try again - it should reattach
	ap.IntfIP = net.ParseIP("1.1.5.5")

	fds, err = ap.AttachPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(fds[0]).NotTo(Equal(bpf.MapFD(0)))
	Expect(fds[1]).To(Equal(bpf.MapFD(0)))
	closeFds(fds)

	atp, err = ap.ListAttachedPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(atp).NotTo(Equal(atp2))

	ap.LogLevel = "debug" // Without filters

	fds, err = ap.AttachPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(fds[0]).NotTo(Equal(bpf.MapFD(0)))
	Expect(fds[1]).To(Equal(bpf.MapFD(0)))
	closeFds(fds)

	atp, err = ap.ListAttachedPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(atp).NotTo(Equal(atp2))

	ap.LogLevel = "debug-filters"

	fds, err = ap.AttachPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(fds[0]).NotTo(Equal(bpf.MapFD(0)))
	Expect(fds[1]).NotTo(Equal(bpf.MapFD(0)))

	id1, err := jump.GetEntry(fds[0], tcdefs.ProgIndexNoDebug)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(id1).ShouldNot(Equal(0))

	id2, err := jump.GetEntry(fds[0], tcdefs.ProgIndexDebug)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(id2).ShouldNot(Equal(0))

	closeFds(fds)

	Eventually(func() []bpf.ProgInfo {
		progs, _ := bpf.GetAllProgs("sched_cls")
		return progs
	}, "5s", "300ms").Should(HaveLen(1 /* filter */ + 2*progsPerPath))

	atp3, err := ap.ListAttachedPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(atp).NotTo(Equal(atp3))

	id, err := strconv.Atoi(atp3[0].ID())
	Expect(err).ShouldNot(HaveOccurred())
	prog, err := bpf.GetProgramByID(id)
	Expect(err).ShouldNot(HaveOccurred())

	Expect(prog.Name).To(Equal("calico_log_filt"))
	Expect(prog.MapIds).To(HaveLen(1))

	jmpID := prog.MapIds[0]
	jmp, err := bpf.DumpJumpMap(jmpID)
	Expect(jmp[tcdefs.ProgIndexNoDebug]).To(Equal(id1))
	Expect(jmp[tcdefs.ProgIndexDebug]).To(Equal(id2))

	prog, err = bpf.GetProgramByID(id1)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(prog.Name).To(Equal("calico_from_wor"))
	Expect(prog.MapIds).To(ContainElement(jmpID))

	prog, err = bpf.GetProgramByID(id2)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(prog.Name).To(Equal("calico_from_wor"))
	Expect(prog.MapIds).NotTo(ContainElement(jmpID))

	ap.LogLevel = "off"

	fds, err = ap.AttachPrograms()
	Expect(err).ShouldNot(HaveOccurred())
	Expect(fds[0]).NotTo(Equal(bpf.MapFD(0)))
	Expect(fds[1]).To(Equal(bpf.MapFD(0)))
	closeFds(fds)

	// We must cleanup otherwise the pinned jump map for debug path will hold the debug programs.
	tc.CleanUpMaps()

	Eventually(func() []bpf.ProgInfo {
		progs, _ := bpf.GetAllProgs("sched_cls")
		return progs
	}, "5s", "300ms").Should(HaveLen(progsPerPath))

}

func closeFds(fds []bpf.MapFD) {
	for _, fd := range fds {
		if fd != bpf.MapFD(0) {
			err := fd.Close()
			Expect(err).ShouldNot(HaveOccurred())
		}
	}
}
