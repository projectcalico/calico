// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
)

var _ = infrastructure.DatastoreDescribe(
	"QoS controls tests",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes, apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {

		var (
			infra  infrastructure.DatastoreInfra
			tc     infrastructure.TopologyContainers
			topt   infrastructure.TopologyOptions
			w      [2]*workload.Workload
			cancel context.CancelFunc
		)

		BeforeEach(func() {
			infra = getInfra()
			topt = infrastructure.DefaultTopologyOptions()
			tc, _ = infrastructure.StartNNodeTopology(2, topt, infra)

			infra.AddDefaultAllow()

			for ii := range w {
				wIP := fmt.Sprintf("10.65.%d.2", ii)
				wName := fmt.Sprintf("w%d", ii)
				w[ii] = workload.Run(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
				w[ii].ConfigureInInfra(infra)
			}

			// Wait until routes are present
			Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(ContainSubstring(w[0].InterfaceName))
			Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))
		})

		AfterEach(func() {
			tc.Stop()
			infra.Stop()

			if cancel != nil {
				cancel()
			}
		})

		Context("With bandwidth limits", func() {
			getQdisc := func() string {
				out, err := tc.Felixes[1].ExecOutput("tc", "qdisc")
				log.Infof("tc qdisc output:\n%v", out)
				Expect(err).NotTo(HaveOccurred())
				return out
			}

			It("should limit bandwidth correctly", func() {
				By("Starting iperf3 server on workload 0")
				serverCmd := w[0].ExecCommand("iperf3", "-s")
				err := serverCmd.Start()
				Expect(err).NotTo(HaveOccurred())

				By("Running iperf3 client on workload 1")
				out, err := w[1].ExecOutput("iperf3", "-c", w[0].IP, "-O5", "-J")
				Expect(err).NotTo(HaveOccurred())
				baselineRate, err := getRateFromJsonOutput(out)
				Expect(err).NotTo(HaveOccurred())
				log.Infof("iperf client rate with no bandwidth limit (bps): %v", baselineRate)
				// Expect the baseline rate to be much greater (>=100x) the bandwidth
				// that we are going to configure just below. In practice we see
				// several Gbps here.
				Expect(baselineRate).To(BeNumerically(">=", 100000.0*100))

				By("Setting 100kbps limit for ingress on workload 1")
				w[1].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
					IngressBandwidth: 100000,
					IngressBurst:     200000,
				}
				w[1].UpdateInInfra(infra)
				Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

				By("Waiting for the config to appear in 'tc qdisc'")
				// ingress config should be present
				Eventually(getQdisc, "10s", "1s").Should(MatchRegexp(`qdisc tbf \d+: dev ` + regexp.QuoteMeta(w[1].InterfaceName) + ` root refcnt \d+ rate ` + regexp.QuoteMeta("100Kbit")))
				// egress config should not be present
				Consistently(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev bwcali.* root refcnt \d+ rate ` + regexp.QuoteMeta("100Kbit")))

				out, err = w[1].ExecOutput("iperf3", "-c", w[0].IP, "-O5", "-J", "-R")
				Expect(err).NotTo(HaveOccurred())
				ingressLimitedRate, err := getRateFromJsonOutput(out)
				Expect(err).NotTo(HaveOccurred())
				log.Infof("iperf client rate with ingress bandwidth limit (bps): %v", ingressLimitedRate)
				// Expect the limited rate to be within 20% of the desired rate
				Expect(ingressLimitedRate).To(BeNumerically(">=", 100000.0*0.8))
				Expect(ingressLimitedRate).To(BeNumerically("<=", 100000.0*1.2))

				By("Setting 100kbps limit for egress on workload 1")
				w[1].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
					EgressBandwidth: 100000,
					EgressBurst:     200000,
				}
				w[1].UpdateInInfra(infra)
				Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

				By("Waiting for the config to appear in 'tc qdisc'")
				// ingress config should not be present
				Eventually(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev ` + regexp.QuoteMeta(w[1].InterfaceName) + ` root refcnt \d+ rate ` + regexp.QuoteMeta("100Kbit")))
				// egress config should be present
				Eventually(getQdisc, "10s", "1s").Should(And(MatchRegexp(`qdisc ingress ffff: dev `+regexp.QuoteMeta(w[1].InterfaceName)+` parent ffff:fff1`), MatchRegexp(`qdisc tbf \d+: dev bwcali.* root refcnt \d+ rate `+regexp.QuoteMeta("100Kbit"))))

				out, err = w[1].ExecOutput("iperf3", "-c", w[0].IP, "-O5", "-J")
				Expect(err).NotTo(HaveOccurred())
				egressLimitedRate, err := getRateFromJsonOutput(out)
				Expect(err).NotTo(HaveOccurred())
				log.Infof("iperf client rate with egress bandwidth limit (bps): %v", egressLimitedRate)
				// Expect the limited rate to be within 20% of the desired rate
				Expect(egressLimitedRate).To(BeNumerically(">=", 100000.0*0.8))
				Expect(egressLimitedRate).To(BeNumerically("<=", 100000.0*1.2))

				By("Removing all limits from workload 1")
				w[1].WorkloadEndpoint.Spec.QoSControls = nil
				w[1].UpdateInInfra(infra)
				Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

				By("Waiting for the config to disappear in 'tc qdisc'")
				// ingress config should not be present
				Consistently(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev ` + regexp.QuoteMeta(w[1].InterfaceName) + ` root refcnt \d+ rate ` + regexp.QuoteMeta("100Kbit")))
				// egress config should not be present
				Eventually(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev bwcali.* root refcnt \d+ rate ` + regexp.QuoteMeta("100Kbit")))

				By("Killing and cleaning up iperf3 server process")
				err = serverCmd.Process.Kill()
				Expect(err).NotTo(HaveOccurred())
				err = serverCmd.Process.Release()
				Expect(err).NotTo(HaveOccurred())

			})
		})

		Context("With packet rate limits", func() {
			getRules := func(felixId int) string {
				out, err := tc.Felixes[felixId].ExecOutput("iptables-save", "-c")
				log.Infof("iptables-save -c output:\n%v", out)
				Expect(err).NotTo(HaveOccurred())
				return out
			}

			It("should limit packet rate correctly", func() {
				format.MaxLength = 1000000

				By("Starting iperf3 server on workload 0")
				serverCmd := w[0].ExecCommand("iperf3", "-s")
				err := serverCmd.Start()
				Expect(err).NotTo(HaveOccurred())

				By("Running iperf3 client on workload 1")
				out, err := w[1].ExecOutput("iperf3", "-c", w[0].IP, "-O5", "-M1000", "-J")
				Expect(err).NotTo(HaveOccurred())
				baselineRate, err := getRateFromJsonOutput(out)
				Expect(err).NotTo(HaveOccurred())
				log.Infof("iperf client rate with no packet rate limit (bps): %v", baselineRate)
				// Expect the baseline rate to be much greater (>=100x) the bandwidth that we
				// would get with the packet rate we are going to configure just below. In
				// practice we see several Gbps here.
				Expect(baselineRate).To(BeNumerically(">=", 800000.0*100))

				By("Setting 100 packets/s limit for ingress on workload 0 (iperf3 server)")
				w[0].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
					IngressPacketRate: 100,
				}
				w[0].UpdateInInfra(infra)
				Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(ContainSubstring(w[0].InterfaceName))

				By("Waiting for the config to appear in 'iptables-save' on workload 0")
				// ingress config should be present
				Eventually(getRules(0), "10s", "1s").Should(And(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Mark packets within ingress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Drop packets over ingress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))
				// egress config should not be present
				Consistently(getRules(0), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Mark packets within egress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Drop packets over egress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))

				out, err = w[1].ExecOutput("iperf3", "-c", w[0].IP, "-O5", "-M1000", "-J")
				Expect(err).NotTo(HaveOccurred())
				ingressLimitedRate, err := getRateFromJsonOutput(out)
				Expect(err).NotTo(HaveOccurred())
				log.Infof("iperf client rate with ingress packet rate limit on server (bps): %v", ingressLimitedRate)
				// Expect the limited rate to be below an estimated desired rate (1000 byte packets * 8 bits/byte * 100 packets/s = 800000 bps)
				Expect(ingressLimitedRate).To(BeNumerically("<=", 800000.0))

				By("Removing all limits from workload 0")
				w[0].WorkloadEndpoint.Spec.QoSControls = nil
				w[0].UpdateInInfra(infra)
				Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(ContainSubstring(w[0].InterfaceName))

				By("Waiting for the config to disappear in 'iptables-save' on workload 0")
				// ingress config should not be present
				Eventually(getRules(0), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Mark packets within ingress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Drop packets over ingress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))
				// egress config should not be present
				Consistently(getRules(0), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Mark packets within egress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .* -m comment --comment "Drop packets over egress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))

				By("Setting 100kbps limit for egress on workload 1 (iperf3 client)")
				w[1].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
					EgressPacketRate: 100,
				}
				w[1].UpdateInInfra(infra)
				Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

				By("Waiting for the config to appear in 'iptables-save' on workload 1")
				// ingress config should not be present
				Eventually(getRules(1), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Mark packets within ingress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Drop packets over ingress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))
				// egress config should be present
				Eventually(getRules(1), "10s", "1s").Should(And(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Mark packets within egress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Drop packets over egress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))

				out, err = w[1].ExecOutput("iperf3", "-c", w[0].IP, "-O5", "-M1000", "-J")
				Expect(err).NotTo(HaveOccurred())
				egressLimitedRate, err := getRateFromJsonOutput(out)
				Expect(err).NotTo(HaveOccurred())
				log.Infof("iperf client rate with egress packet rate limit on client (bps): %v", egressLimitedRate)
				// Expect the limited rate to be below an estimated desired rate (1000 byte packets * 8 bits/byte * 100 packets/s = 800000 bps)
				Expect(egressLimitedRate).To(BeNumerically("<=", 800000.0))

				By("Removing all limits from workload 1")
				w[1].WorkloadEndpoint.Spec.QoSControls = nil
				w[1].UpdateInInfra(infra)
				Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

				By("Waiting for the config to disappear in 'iptables-save' on workload 1")
				// ingress config should not be present
				Consistently(getRules(1), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Mark packets within ingress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Drop packets over ingress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))
				// egress config should not be present
				Eventually(getRules(1), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Mark packets within egress packet rate limit" -m limit --limit `+regexp.QuoteMeta("100/sec")+` -j MARK --set-xmark 0x\d+/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .* -m comment --comment "Drop packets over egress packet rate limit" -m mark ! --mark 0x\d+/0x\d+ -j DROP`)))

				By("Killing and cleaning up iperf3 server process")
				err = serverCmd.Process.Kill()
				Expect(err).NotTo(HaveOccurred())
				err = serverCmd.Process.Release()
				Expect(err).NotTo(HaveOccurred())

			})
		})
	})

func getRateFromJsonOutput(output string) (float64, error) {
	perf := make(map[string]interface{})
	err := json.Unmarshal([]byte(output), &perf)
	if err != nil {
		return 0.0, err
	}
	rate := perf["end"].(map[string]interface{})["sum_received"].(map[string]interface{})["bits_per_second"]
	floatRate, ok := rate.(float64)
	if !ok {
		return 0.0, fmt.Errorf("failed typeassertion to float64")
	}
	return floatRate, nil
}
