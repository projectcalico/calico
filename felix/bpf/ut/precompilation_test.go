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

// Copyright (c) 2020  All rights reserved.

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
)

func checkBTFEnabled() []bool {
	if bpfutils.BTFEnabled {
		return []bool{false, true}
	}
	return []bool{false}
}

func TestPrecompiledBinariesAreLoadable(t *testing.T) {
	RegisterTestingT(t)

	bpffs, err := bpf.MaybeMountBPFfs()
	Expect(err).NotTo(HaveOccurred())
	Expect(bpffs).To(Equal("/sys/fs/bpf"))

	defer func() {
		bpfutils.BTFEnabled = bpfutils.SupportsBTF()
	}()

	for _, logLevel := range []string{"OFF", "INFO", "DEBUG"} {
		logLevel := logLevel
		// Compile the TC endpoint programs.
		logCxt := log.WithField("logLevel", logLevel)
		for _, btfEnabled := range checkBTFEnabled() {
			bpfutils.BTFEnabled = btfEnabled
			for _, epToHostDrop := range []bool{false, true} {
				epToHostDrop := epToHostDrop
				logCxt = logCxt.WithField("epToHostDrop", epToHostDrop)
				for _, fibEnabled := range []bool{false, true} {
					fibEnabled := fibEnabled
					logCxt = logCxt.WithField("fibEnabled", fibEnabled)
					epTypes := []tc.EndpointType{
						tc.EpTypeWorkload,
						tc.EpTypeHost,
						tc.EpTypeTunnel,
						tc.EpTypeWireguard,
					}
					for _, epType := range epTypes {
						epType := epType
						logCxt = logCxt.WithField("epType", epType)
						if epToHostDrop && epType != tc.EpTypeWorkload {
							log.Debug("Skipping combination since epToHostDrop only affect workloads")
							continue
						}
						for _, toOrFrom := range []tc.ToOrFromEp{tc.FromEp, tc.ToEp} {
							toOrFrom := toOrFrom

							logCxt := logCxt.WithField("toOrFrom", toOrFrom)
							if toOrFrom == tc.ToEp && (fibEnabled || epToHostDrop) {
								log.Debug("Skipping combination since fibEnabled/epToHostDrop only affect from targets")
								continue
							}

							for _, dsr := range []bool{false, true} {
								if dsr && !((epType == tc.EpTypeWorkload && toOrFrom == tc.FromEp) ||
									(epType == tc.EpTypeHost)) {
									log.Debug("DSR only affects from WEP and HEP")
									continue
								}

								ap := tc.AttachPoint{
									Type:       epType,
									ToOrFrom:   toOrFrom,
									Hook:       tc.HookIngress,
									ToHostDrop: epToHostDrop,
									FIB:        fibEnabled,
									DSR:        dsr,
									LogLevel:   logLevel,
									HostIP:     net.ParseIP("10.0.0.1"),
									IntfIP:     net.ParseIP("10.0.0.2"),
								}

								t.Run(ap.FileName(), func(t *testing.T) {
									RegisterTestingT(t)
									logCxt.Debugf("Testing %v in %v", ap.ProgramName(), ap.FileName())

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
					}
				}
			}
		}
	}
}

func createVeth() (string, netlink.Link) {
	vethName := fmt.Sprintf("test%xa", rand.Uint32())
	var veth netlink.Link = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  vethName,
			Flags: net.FlagUp,
		},
		PeerName: vethName + "b",
	}
	err := netlink.LinkAdd(veth)
	Expect(err).NotTo(HaveOccurred(), "failed to create test veth")
	return vethName, veth
}

func deleteLink(veth netlink.Link) {
	err := netlink.LinkDel(veth)
	Expect(err).NotTo(HaveOccurred(), "failed to delete test veth")
}
