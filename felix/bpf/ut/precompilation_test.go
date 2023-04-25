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
	"fmt"
	"math/rand"
	"net"
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
	"github.com/projectcalico/calico/felix/bpf/tc"
	"github.com/projectcalico/calico/felix/bpf/utils"
	"github.com/projectcalico/calico/felix/bpf/xdp"
)

func checkBTFEnabled() []bool {
	if bpfutils.BTFEnabled {
		return []bool{false, true}
	}
	return []bool{false}
}

func TestPrecompiledBinariesAreLoadable(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := utils.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

	defer func() {
		bpfutils.BTFEnabled = bpfutils.SupportsBTF()
	}()

	defer bpf.CleanUpMaps()

	for _, at := range tc.ListAttachTypes() {
		for _, btfEnabled := range checkBTFEnabled() {
			bpfutils.BTFEnabled = btfEnabled
			if at.Family == 6 {
				continue
			}

			ap := tc.AttachPoint{
				IPv6Enabled: true,
				Type:        at.Type,
				ToOrFrom:    at.ToOrFrom,
				Hook:        bpf.HookIngress,
				ToHostDrop:  at.ToHostDrop,
				FIB:         at.FIB,
				DSR:         at.DSR,
				LogLevel:    at.LogLevel,
				HostIP:      net.ParseIP("10.0.0.1"),
				IntfIP:      net.ParseIP("10.0.0.2"),
			}

			t.Run(ap.FileName(4), func(t *testing.T) {
				RegisterTestingT(t)
				log.WithField("AttachType", at).WithField("btf", btfEnabled).
					Debugf("Testing %v in %v", ap.ProgramName(), ap.FileName(4))

				vethName, veth := createVeth()
				defer deleteLink(veth)
				ap.Iface = vethName
				err := tc.EnsureQdisc(ap.Iface)
				Expect(err).NotTo(HaveOccurred())
				opts, err := ap.AttachProgram()
				Expect(err).NotTo(HaveOccurred())
				Expect(opts).NotTo(Equal(nil))
			})
		}
	}

	// Test XDP objects are loadable
	for _, logLevel := range []string{"OFF", "INFO", "DEBUG"} {
		logLevel := logLevel
		// Compile the XDP endpoint programs.
		logCxt := log.WithField("logLevel", logLevel)

		ap := xdp.AttachPoint{
			LogLevel: logLevel,
			Modes:    []bpf.XDPMode{bpf.XDPGeneric},
		}

		t.Run(ap.FileName(), func(t *testing.T) {
			RegisterTestingT(t)
			logCxt.Debugf("Testing %v in %v", ap.ProgramName(), ap.FileName())

			vethName, veth := createVeth()
			defer deleteLink(veth)
			ap.Iface = vethName
			opts, err := ap.AttachProgram()
			Expect(err).NotTo(HaveOccurred())
			Expect(opts).NotTo(Equal(nil))
		})
	}
}

func createVeth() (string, netlink.Link) {
	vethName := fmt.Sprintf("test%xa", rand.Uint32())
	la := netlink.NewLinkAttrs()
	la.Name = vethName
	la.Flags = net.FlagUp
	var veth netlink.Link = &netlink.Veth{
		LinkAttrs: la,
		PeerName:  vethName + "b",
	}
	err := netlink.LinkAdd(veth)
	Expect(err).NotTo(HaveOccurred(), "failed to create test veth")
	return vethName, veth
}

func deleteLink(veth netlink.Link) {
	err := netlink.LinkDel(veth)
	Expect(err).NotTo(HaveOccurred(), "failed to delete test veth")
}
