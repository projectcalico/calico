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

//go:build fvtests

package fv_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

// These tests verify that test-connection and test-workload work properly across all the different protocols.
var _ = describeConnCheckTests("tcp")
var _ = describeConnCheckTests("sctp")
var _ = describeConnCheckTests("udp")
var _ = describeConnCheckTests("ip4:253")
var _ = describeConnCheckTests("udp-recvmsg")
var _ = describeConnCheckTests("udp-noconn")

func describeConnCheckTests(protocol string) bool {
	return infrastructure.DatastoreDescribe("Connectivity checker self tests: "+protocol,
		[]apiconfig.DatastoreType{apiconfig.EtcdV3}, // Skipping k8s since these tests don't rely on the datastore.
		func(getInfra infrastructure.InfraFactory) {

			var (
				infra infrastructure.DatastoreInfra
				tc    infrastructure.TopologyContainers
				hostW [2]*workload.Workload
				cc    *connectivity.Checker
			)

			BeforeEach(func() {
				infra = getInfra()
				tc, _ = infrastructure.StartNNodeTopology(2, infrastructure.DefaultTopologyOptions(), infra)

				// Create host-networked "workloads", one on each "host".
				for ii := range tc.Felixes {
					// Workload doesn't understand the extra connectivity types that test-connection tries.
					wlProto := protocol
					if strings.Contains(protocol, "-") {
						wlProto = strings.Split(protocol, "-")[0]
					}
					hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", wlProto)
				}

				cc = &connectivity.Checker{}
				cc.Protocol = protocol
			})

			AfterEach(func() {
				for _, wl := range hostW {
					wl.Stop()
				}
				tc.Stop()

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})

			It("should have host-to-host on right port only", func() {
				cc.ExpectSome(tc.Felixes[0], hostW[1])
				if !strings.HasPrefix(protocol, "ip") {
					cc.ExpectNone(tc.Felixes[0], hostW[1], 8066)
				}
				cc.CheckConnectivity()
			})

			if protocol == "udp" {
				Describe("with tc configured to drop 5% of packets", func() {
					BeforeEach(func() {
						// Make sure we have connectivity before we start packet loss measurements.
						cc.ExpectSome(tc.Felixes[0], hostW[1])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						tc.Felixes[0].Exec("tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "5%")
					})

					It("and a 1% threshold, should see packet loss", func() {
						failed := false
						cc.OnFail = func(msg string) {
							log.WithField("msg", msg).Info("Connectivity checker failed (as expected)")
							failed = true
						}
						cc.ExpectLoss(tc.Felixes[0], hostW[1], 2*time.Second, 1, -1)
						cc.CheckConnectivityPacketLoss()

						Expect(failed).To(BeTrue(), "Expected the connection checker to detect packet loss")
					})

					It("and a 20% threshold, should tolerate packet loss", func() {
						cc.ExpectLoss(tc.Felixes[0], hostW[1], 2*time.Second, 20, -1)
						cc.CheckConnectivityPacketLoss()
					})

					It("with tcpdump", func() {
						tcpdF := tc.Felixes[0].AttachTCPDump("eth0")
						tcpdF.SetLogEnabled(true)
						tcpdF.AddMatcher("UDP", regexp.MustCompile(`.*UDP.*`))
						tcpdF.Start()

						tcpdW := hostW[1].AttachTCPDump()
						tcpdW.SetLogEnabled(true)
						tcpdW.AddMatcher("UDP", regexp.MustCompile(`.*UDP.*`))
						tcpdW.Start()

						cc.ExpectLoss(tc.Felixes[0], hostW[1], 2*time.Second, 20, -1)
						cc.CheckConnectivityPacketLoss()
						Eventually(func() int { return tcpdF.MatchCount("UDP") }).Should(BeNumerically(">", 0))
						Eventually(func() int { return tcpdW.MatchCount("UDP") }).Should(BeNumerically(">", 0))
					})
				})
			}
		},
	)
}

var _ = infrastructure.DatastoreDescribe("Container self tests",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3}, // Skipping k8s since these tests don't rely on the datastore.
	func(getInfra infrastructure.InfraFactory) {

		var (
			infra   infrastructure.DatastoreInfra
			tc      infrastructure.TopologyContainers
			options infrastructure.TopologyOptions
		)

		BeforeEach(func() {
			options = infrastructure.DefaultTopologyOptions()
		})

		JustBeforeEach(func() {
			infra = getInfra()
			tc, _ = infrastructure.StartNNodeTopology(1, options, infra)
		})

		AfterEach(func() {
			tc.Stop()
			if CurrentGinkgoTestDescription().Failed {
				infra.DumpErrorData()
			}
			infra.Stop()
		})

		It("should only report that existing files actually exist", func() {
			Expect(tc.Felixes[0].FileExists("/usr/local/bin/calico-felix")).To(BeTrue())
			Expect(tc.Felixes[0].FileExists("/garbage")).To(BeFalse())
		})

		Describe("with DebugPanicAfter set to 2s", func() {
			BeforeEach(func() {
				options.ExtraEnvVars["FELIX_DebugPanicAfter"] = "2"
			})

			It("should panic and drop a core file", func() {
				tc.Felixes[0].WaitNotRunning(5 * time.Second)
				dir, err := os.ReadDir("/tmp")
				Expect(err).NotTo(HaveOccurred())
				name := ""
				var filesToClean []string
				for _, f := range dir {
					if strings.Contains(f.Name(), "core_"+tc.Felixes[0].Hostname) {
						name = f.Name()
						filesToClean = append(filesToClean, name)
					}
				}
				defer func() {
					// The core files get owned by root, use temporary privileged container to clean them up.
					for _, s := range filesToClean {
						utils.Run("docker", "run",
							"--rm",
							"-v", "/tmp:/tmp",
							"--privileged",
							"--entrypoint", "rm", utils.Config.FelixImage, "/tmp/"+s)
					}
				}()
				Expect(name).NotTo(Equal(""), "Couldn't find core file")
				s, err := os.Stat("/tmp/" + name)
				Expect(err).NotTo(HaveOccurred())
				Expect(s.Size()).To(BeNumerically(">", 4096))
			})
		})

		Describe("with DebugSimulateDataRace set", func() {
			BeforeEach(func() {
				options.ExtraEnvVars["FELIX_DebugSimulateDataRace"] = "true"
			})

			if os.Getenv("FV_RACE_DETECTOR_ENABLED") == "true" {
				It("should detect a race", func() {
					Eventually(tc.Felixes[0].DataRaces).ShouldNot(BeEmpty())
					tc.Felixes[0].DisableRaceDetector()
				})
			} else {
				It("should not detect a race because race detector is disabled", func() {
					Consistently(tc.Felixes[0].DataRaces).Should(BeEmpty())
				})
			}
		})
	},
)
