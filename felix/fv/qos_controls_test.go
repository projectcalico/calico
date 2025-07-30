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
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func init() {
	// Stop Gomega from chopping off diffs in logs.
	format.MaxLength = 0
}

type iperfReport struct {
	Start struct {
		Connected []struct {
			Socket     int    `json:"socket"`
			LocalHost  string `json:"local_host"`
			LocalPort  int    `json:"local_port"`
			RemoteHost string `json:"remote_host"`
			RemotePort int    `json:"remote_port"`
		} `json:"connected"`
		Version    string `json:"version"`
		SystemInfo string `json:"system_info"`
		Timestamp  struct {
			Time     string `json:"time"`
			Timesecs int    `json:"timesecs"`
		} `json:"timestamp"`
		ConnectingTo struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"connecting_to"`
		Cookie        string `json:"cookie"`
		TCPMssDefault int    `json:"tcp_mss_default"`
		SockBufsize   int    `json:"sock_bufsize"`
		SndbufActual  int    `json:"sndbuf_actual"`
		RcvbufActual  int    `json:"rcvbuf_actual"`
		TestStart     struct {
			Protocol   string `json:"protocol"`
			NumStreams int    `json:"num_streams"`
			Blksize    int    `json:"blksize"`
			Omit       int    `json:"omit"`
			Duration   int    `json:"duration"`
			Bytes      int    `json:"bytes"`
			Blocks     int    `json:"blocks"`
			Reverse    int    `json:"reverse"`
			Tos        int    `json:"tos"`
		} `json:"test_start"`
	} `json:"start"`
	Intervals []struct {
		Streams []struct {
			Socket        int     `json:"socket"`
			Start         float64 `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int     `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Retransmits   int     `json:"retransmits"`
			SndCwnd       int     `json:"snd_cwnd"`
			Rtt           int     `json:"rtt"`
			Rttvar        int     `json:"rttvar"`
			Pmtu          int     `json:"pmtu"`
			Omitted       bool    `json:"omitted"`
			Sender        bool    `json:"sender"`
		} `json:"streams"`
		Sum struct {
			Start         float64 `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int     `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Retransmits   int     `json:"retransmits"`
			Omitted       bool    `json:"omitted"`
			Sender        bool    `json:"sender"`
		} `json:"sum"`
	} `json:"intervals"`
	End struct {
		Streams []struct {
			Sender struct {
				Socket        int     `json:"socket"`
				Start         float64 `json:"start"`
				End           float64 `json:"end"`
				Seconds       float64 `json:"seconds"`
				Bytes         int64   `json:"bytes"`
				BitsPerSecond float64 `json:"bits_per_second"`
				Retransmits   int     `json:"retransmits"`
				MaxSndCwnd    int     `json:"max_snd_cwnd"`
				MaxRtt        int     `json:"max_rtt"`
				MinRtt        int     `json:"min_rtt"`
				MeanRtt       int     `json:"mean_rtt"`
				Sender        bool    `json:"sender"`
			} `json:"sender"`
			Receiver struct {
				Socket        int     `json:"socket"`
				Start         float64 `json:"start"`
				End           float64 `json:"end"`
				Seconds       float64 `json:"seconds"`
				Bytes         int64   `json:"bytes"`
				BitsPerSecond float64 `json:"bits_per_second"`
				Sender        bool    `json:"sender"`
			} `json:"receiver"`
		} `json:"streams"`
		SumSent struct {
			Start         float64 `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int64   `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Retransmits   int     `json:"retransmits"`
			Sender        bool    `json:"sender"`
		} `json:"sum_sent"`
		SumReceived struct {
			Start         float64 `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int64   `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Sender        bool    `json:"sender"`
		} `json:"sum_received"`
		CPUUtilizationPercent struct {
			HostTotal    float64 `json:"host_total"`
			HostUser     float64 `json:"host_user"`
			HostSystem   float64 `json:"host_system"`
			RemoteTotal  float64 `json:"remote_total"`
			RemoteUser   float64 `json:"remote_user"`
			RemoteSystem float64 `json:"remote_system"`
		} `json:"cpu_utilization_percent"`
		SenderTCPCongestion   string `json:"sender_tcp_congestion"`
		ReceiverTCPCongestion string `json:"receiver_tcp_congestion"`
	} `json:"end"`
}

var _ = infrastructure.DatastoreDescribe(
	"QoS controls tests",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes, apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		type testConf struct {
			Encap string
		}
		for _, testConfig := range []testConf{
			{Encap: "none"},
			{Encap: "ipip"},
			{Encap: "vxlan"},
		} {
			encap := testConfig.Encap

			Describe(fmt.Sprintf("encap='%s'", encap), func() {
				var (
					infra        infrastructure.DatastoreInfra
					tc           infrastructure.TopologyContainers
					calicoClient client.Interface
					topt         infrastructure.TopologyOptions
					w            [2]*workload.Workload
					cancel       context.CancelFunc
				)

				BeforeEach(func() {
					infra = getInfra()
					topt = infrastructure.DefaultTopologyOptions()

					switch encap {
					case "none":
						if !BPFMode() {
							Skip("Skipping QoS control tests on no-encap and iptables/nftables mode.")
						}
						topt.IPIPMode = apiv3.IPIPModeNever
						topt.VXLANMode = apiv3.VXLANModeNever
					case "ipip":
						if !BPFMode() {
							Skip("Skipping QoS control tests on IPIP encap and iptables/nftables mode.")
						}
						topt.VXLANMode = apiv3.VXLANModeNever
						topt.IPIPMode = apiv3.IPIPModeAlways
						topt.SimulateBIRDRoutes = true
					case "vxlan":
						topt.IPIPMode = apiv3.IPIPModeNever
						topt.VXLANMode = apiv3.VXLANModeAlways
						topt.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(topt.IPPoolCIDR, topt.IPv6PoolCIDR)
						topt.SimulateBIRDRoutes = false
					}

					topt.UseIPPools = true
					topt.DelayFelixStart = true
					topt.TriggerDelayedFelixStart = true

					if _, ok := infra.(*infrastructure.EtcdDatastoreInfra); ok && BPFMode() {
						Skip("Skipping QoS control tests on etcd datastore and BPF mode.")
					}

					tc, calicoClient = infrastructure.StartNNodeTopology(2, topt, infra)

					infra.AddDefaultAllow()

					for ii := range w {
						wIP := fmt.Sprintf("10.65.%d.2", ii)
						wName := fmt.Sprintf("w%d", ii)
						w[ii] = workload.Run(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
						w[ii].ConfigureInInfra(infra)
						if topt.UseIPPools {
							// Assign the workload's IP in IPAM, this will trigger calculation of routes.
							err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
								IP:       cnet.MustParseIP(wIP),
								HandleID: &w[ii].Name,
								Attrs: map[string]string{
									ipam.AttributeNode: tc.Felixes[ii].Hostname,
								},
								Hostname: tc.Felixes[ii].Hostname,
							})
							Expect(err).NotTo(HaveOccurred())
						}
					}

					if BPFMode() {
						ensureBPFProgramsAttached(tc.Felixes[0])
						ensureBPFProgramsAttached(tc.Felixes[1])
					}

					// Wait until routes are present
					Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "20s").Should(ContainSubstring(w[0].InterfaceName))
					Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "20s").Should(ContainSubstring(w[1].InterfaceName))
				})

				AfterEach(func() {
					for _, felix := range tc.Felixes {
						felix.Exec("ip", "route")
						if BPFMode() {
							felix.Exec("calico-bpf", "counters", "dump")
							felix.Exec("calico-bpf", "ifstate", "dump")
						}
					}

					tc.Stop()
					infra.Stop()

					if cancel != nil {
						cancel()
					}
				})

				getRules := func(felixId int) func() string {
					return func() string {
						var args []string
						if NFTMode() {
							args = []string{"nft", "list", "ruleset"}
						} else {
							args = []string{"iptables-save", "-c"}
						}
						out, err := tc.Felixes[felixId].ExecOutput(args...)
						Expect(err).NotTo(HaveOccurred())
						logrus.Infof("%s output:\n%v", strings.Join(args, " "), out)
						return out
					}
				}

				getBPFPacketRateAndBurst := func(felixId, wlId int, hook string) func() string {
					return func() string {
						var args []string
						var out string

						args = []string{"bash", "-c", fmt.Sprintf(`bpftool -j net |jq '.[].tc[] | select(.devname == "%s" and .kind == "tcx/%s") | .prog_id'`, w[wlId].InterfaceName, hook)}
						out, _ = tc.Felixes[felixId].ExecOutput(args...)
						logrus.Infof("%s output:\n%v", strings.Join(args, " "), out)
						progId := strings.TrimSuffix(out, "\n")
						if progId == "null" {
							return ""
						}

						args = []string{"bash", "-c", fmt.Sprintf(`for map_id in $(bpftool prog show id %s -j |jq '.map_ids[]'); do bpftool map dump id ${map_id} -j |jq '.[].formatted.value.".rodata"[]?."__globals".v4 | ."%s_packet_rate"? '; done`, progId, hook)}
						out, _ = tc.Felixes[felixId].ExecOutput(args...)
						logrus.Infof("%s output:\n%v", strings.Join(args, " "), out)
						packetRate := strings.TrimSuffix(out, "\n")
						if packetRate == "null" {
							return ""
						}

						args = []string{"bash", "-c", fmt.Sprintf(`for map_id in $(bpftool prog show id %s -j |jq '.map_ids[]'); do bpftool map dump id ${map_id} -j |jq '.[].formatted.value.".rodata"[]?."__globals".v4 | ."%s_packet_burst"? '; done`, progId, hook)}
						out, _ = tc.Felixes[felixId].ExecOutput(args...)
						logrus.Infof("%s output:\n%v", strings.Join(args, " "), out)
						packetBurst := strings.TrimSuffix(out, "\n")
						if packetBurst == "null" {
							return ""
						}

						return packetRate + " " + packetBurst
					}
				}

				Context("With bandwidth limits", func() {
					BeforeEach(func() {
						if BPFMode() && BPFAttachType() == "tc" {
							Skip("Skipping QoS control bandwidth tests on BPF TC attach mode.")
						}
					})
					getQdisc := func() string {
						out, err := tc.Felixes[1].ExecOutput("tc", "qdisc")
						logrus.Infof("tc qdisc output:\n%v", out)
						Expect(err).NotTo(HaveOccurred())
						return out
					}

					It("should limit bandwidth correctly", func() {
						By("Starting iperf3 server on workload 0")
						serverCmd := w[0].ExecCommand("iperf3", "-s")
						err := serverCmd.Start()
						Expect(err).NotTo(HaveOccurred())

						By("Running iperf3 client on workload 1")
						baselineRate, baselinePeakrate, err := retryIperf3Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-O5", "-J")
						Expect(err).NotTo(HaveOccurred())
						logrus.Infof("iperf client rate with no bandwidth limit (bps): %v", baselineRate)
						// Expect the baseline rate and peakrate to be much greater (>=10x) than the rate and peakrate limits
						// that we are going to configure just below. In practice we see several Gbps here.
						Expect(baselineRate).To(BeNumerically(">=", 10000000.0*10))
						Expect(baselinePeakrate).To(BeNumerically(">=", 100000000.0*10))

						By("Setting 10Mbps limit and 100Mbps peakrate for ingress on workload 1")
						w[1].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
							IngressBandwidth: 10000000,
							IngressBurst:     300000000,
							IngressPeakrate:  100000000,
						}
						w[1].UpdateInInfra(infra)
						Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

						By("Waiting for the config to appear in 'tc qdisc'")
						// ingress config should be present
						Eventually(getQdisc, "10s", "1s").Should(MatchRegexp(`qdisc tbf \d+: dev ` + regexp.QuoteMeta(w[1].InterfaceName) + ` root refcnt \d+ rate ` + regexp.QuoteMeta("10Mbit") + `.* peakrate ` + regexp.QuoteMeta("100Mbit")))
						// egress config should not be present
						Consistently(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev bwcali.* root refcnt \d+ rate ` + regexp.QuoteMeta("10Mbit")))

						ingressLimitedRate, ingressLimitedPeakrate, err := retryIperf3Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-O5", "-J", "-R")
						Expect(err).NotTo(HaveOccurred())
						logrus.Infof("iperf client rate with ingress bandwidth limit (bps): %v", ingressLimitedRate)
						// Expect the limited rate and peakrate to be within 20% of the desired rate and peakrate
						Expect(ingressLimitedRate).To(BeNumerically(">=", 10000000.0*0.8))
						Expect(ingressLimitedRate).To(BeNumerically("<=", 10000000.0*1.2))
						Expect(ingressLimitedPeakrate).To(BeNumerically(">=", 10000000.0))
						Expect(ingressLimitedPeakrate).To(BeNumerically("<=", 100000000.0*1.2))

						By("Setting 10Mbps limit and 100Mbps peakrate for egress on workload 1")
						w[1].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
							EgressBandwidth: 10000000,
							EgressBurst:     300000000,
							EgressPeakrate:  100000000,
						}
						w[1].UpdateInInfra(infra)
						Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

						By("Waiting for the config to appear in 'tc qdisc'")
						// ingress config should not be present
						Eventually(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev ` + regexp.QuoteMeta(w[1].InterfaceName) + ` root refcnt \d+ rate ` + regexp.QuoteMeta("10Mbit")))
						// egress config should be present
						Eventually(getQdisc, "10s", "1s").Should(And(MatchRegexp(`qdisc ingress ffff: dev `+regexp.QuoteMeta(w[1].InterfaceName)+` parent ffff:fff1`), MatchRegexp(`qdisc tbf \d+: dev bwcali.* root refcnt \d+ rate `+regexp.QuoteMeta("10Mbit")+`.* peakrate `+regexp.QuoteMeta("100Mbit"))))

						egressLimitedRate, egressLimitedPeakrate, err := retryIperf3Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-O5", "-J")
						Expect(err).NotTo(HaveOccurred())
						logrus.Infof("iperf client rate with egress bandwidth limit (bps): %v", egressLimitedRate)
						// Expect the limited rate and peakrate to be within 20% of the desired rate and peakrate
						Expect(egressLimitedRate).To(BeNumerically(">=", 10000000.0*0.8))
						Expect(egressLimitedRate).To(BeNumerically("<=", 10000000.0*1.2))
						Expect(egressLimitedPeakrate).To(BeNumerically(">=", 10000000.0))
						Expect(egressLimitedPeakrate).To(BeNumerically("<=", 100000000.0*1.2))

						By("Removing all limits from workload 1")
						w[1].WorkloadEndpoint.Spec.QoSControls = nil
						w[1].UpdateInInfra(infra)
						Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

						By("Waiting for the config to disappear in 'tc qdisc'")
						// ingress config should not be present
						Consistently(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev ` + regexp.QuoteMeta(w[1].InterfaceName) + ` root refcnt \d+ rate ` + regexp.QuoteMeta("10Mbit")))
						// egress config should not be present
						Eventually(getQdisc, "10s", "1s").ShouldNot(MatchRegexp(`qdisc tbf \d+: dev bwcali.* root refcnt \d+ rate ` + regexp.QuoteMeta("10Mbit")))

						By("Killing and cleaning up iperf3 server process")
						err = serverCmd.Process.Kill()
						Expect(err).NotTo(HaveOccurred())
						err = serverCmd.Process.Release()
						Expect(err).NotTo(HaveOccurred())

					})
				})

				Context("With packet rate limits", func() {
					It("should limit packet rate correctly", func() {
						By("Starting iperf2 server on workload 0")
						serverCmd := w[0].ExecCommand("iperf", "-s", "-u", "-i1")
						err := serverCmd.Start()
						Expect(err).NotTo(HaveOccurred())

						By("Running iperf2 client on workload 1 with no packet rate limits")
						baselineRate, err := retryIperf2Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-u", "-l1000", "-b100M", "-t10")
						Expect(err).NotTo(HaveOccurred())
						logrus.Infof("iperf client rate with no packet rate limit (bps): %v", baselineRate)
						// Expect the baseline rate to be much greater than the bandwidth that we
						// would get with the packet rate limit we are going to configure just below (within
						// 20% of the requested 100Mbit/sec).
						Expect(baselineRate).To(BeNumerically(">=", 100*1e6*0.8))

						By("Setting 100 packets/s limit for ingress on workload 0 (iperf2 server)")
						w[0].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
							IngressPacketRate:  100,
							IngressPacketBurst: 200,
						}
						w[0].UpdateInInfra(infra)
						Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(ContainSubstring(w[0].InterfaceName))

						if BPFMode() {
							By("Waiting for the config to appear in the BPF maps on workload 0")
							Eventually(getBPFPacketRateAndBurst(0, 0, "ingress"), "10s", "1s").Should(Equal("100 200"))
							Consistently(getBPFPacketRateAndBurst(0, 0, "egress"), "10s", "1s").Should(Equal("0 0"))
						} else {
							By("Waiting for the config to appear in 'iptables-save/nft list ruleset' on workload 0")
							if NFTMode() {
								// ingress config should be present
								Eventually(getRules(0), "10s", "1s").Should(MatchRegexp(`(?s)chain filter-cali-tw-` + w[0].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
								// egress config should not be present
								Consistently(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-fw-` + w[0].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
							} else {
								// ingress config should be present
								Eventually(getRules(0), "10s", "1s").Should(And(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m mark ! --mark 0x\d+\/0x\d+ -j DROP`)))
								// egress config should not be present
								Consistently(getRules(0), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m mark ! --mark 0x\d+\/0x\d+ -j DROP`)))
							}
						}

						By("Running iperf2 client on workload 1 with packet rate limit for ingress on workload 0")
						ingressLimitedPeakrate, err := retryIperf2Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-u", "-l1000", "-b10M", "-t1")
						logrus.Infof("iperf client peakrate with ingress packet rate limit on client (bps): %v", ingressLimitedPeakrate)
						// Expect the limited peakrate to be below an estimated desired rate (1000 byte packet * 8 bits/byte * (100 packets/s + 200 packet burst) = 2400000bps), with a 20% margin
						Expect(ingressLimitedPeakrate).To(BeNumerically(">=", 1000*8*100))
						Expect(ingressLimitedPeakrate).To(BeNumerically("<=", 1000*8*300*1.2))

						By("Sleeping for 5 seconds to clear any burst buffer/counters")
						time.Sleep(5 * time.Second)

						ingressLimitedRate, err := retryIperf2Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-u", "-l1000", "-b10M", "-t10")
						Expect(err).NotTo(HaveOccurred())
						logrus.Infof("iperf client rate with ingress packet rate limit on client (bps): %v", ingressLimitedRate)
						// Expect the limited rate to be below an estimated desired rate (1000 byte packets * 8 bits/byte * 100 packets/s = 800000bps) , with a 20% margin
						Expect(ingressLimitedRate).To(BeNumerically(">=", 1000*8*100*0.8))
						Expect(ingressLimitedRate).To(BeNumerically("<=", 1000*8*100*1.2))

						By("Removing all limits from workload 0")
						w[0].WorkloadEndpoint.Spec.QoSControls = nil
						w[0].UpdateInInfra(infra)
						Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(ContainSubstring(w[0].InterfaceName))

						if BPFMode() {
							By("Waiting for the config to disappear in the BPF maps on workload 0")
							Eventually(getBPFPacketRateAndBurst(0, 0, "ingress"), "10s", "1s").Should(Equal("0 0"))
							Consistently(getBPFPacketRateAndBurst(0, 0, "egress"), "10s", "1s").Should(Equal("0 0"))
						} else {
							By("Waiting for the config to disappear in 'iptables-save/nft list ruleset' on workload 0")
							if NFTMode() {
								// ingress config should not be present
								Eventually(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-tw-` + w[0].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
								// egress config should not be present
								Consistently(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-fw-` + w[0].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
							} else {
								// ingress config should not be present
								Eventually(getRules(0), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m mark ! --mark 0x\d+\/0x\d+ -j DROP`)))
								// egress config should not be present
								Consistently(getRules(0), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[0].InterfaceName)+` .*-m mark ! --mark 0x\d+\/0x\d+ -j DROP`)))
							}
						}

						By("Setting 100kpps limit for egress on workload 1 (iperf2 client)")
						w[1].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
							EgressPacketRate:  100,
							EgressPacketBurst: 200,
						}
						w[1].UpdateInInfra(infra)
						Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

						if BPFMode() {
							By("Waiting for the config to appear in the BPF maps on workload 1")
							Eventually(getBPFPacketRateAndBurst(1, 1, "ingress"), "10s", "1s").Should(Equal("0 0"))
							Eventually(getBPFPacketRateAndBurst(1, 1, "egress"), "10s", "1s").Should(Equal("100 200"))
						} else {
							By("Waiting for the config to appear in 'iptables-save/nft list ruleset' on workload 1")
							if NFTMode() {
								// ingress config should not be present
								Eventually(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-tw-` + w[1].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
								// egress config should be present
								Eventually(getRules(1), "10s", "1s").Should(MatchRegexp(`(?s)chain filter-cali-fw-` + w[1].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
							} else {
								// ingress config should not be present
								Eventually(getRules(1), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m mark ! --mark 0x\d+\/0x\d+ -j DROP`)))
								// egress config should be present
								Eventually(getRules(1), "10s", "1s").Should(And(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m mark ! --mark 0x\d+\/0x\d+ -j DROP`)))
							}
						}

						By("Running iperf2 client on workload 1 with packet rate limit for egress on workload 1")
						egressLimitedPeakrate, err := retryIperf2Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-u", "-l1000", "-b10M", "-t1")
						logrus.Infof("iperf client peakrate with egress packet rate limit on client (bps): %v", egressLimitedPeakrate)
						// Expect the limited peakrate to be below an estimated desired rate (1000 byte packet * 8 bits/byte * (100 packets/s + 200 packet burst) = 2400000bps), with a 20% margin
						Expect(egressLimitedPeakrate).To(BeNumerically(">=", 1000*8*100))
						Expect(egressLimitedPeakrate).To(BeNumerically("<=", 1000*8*300*1.2))

						By("Sleeping for 5 seconds to clear any burst buffer/counters")
						time.Sleep(5 * time.Second)

						egressLimitedRate, err := retryIperf2Client(w[1], 5, 5*time.Second, "-c", w[0].IP, "-u", "-l1000", "-b10M", "-t10")
						Expect(err).NotTo(HaveOccurred())
						logrus.Infof("iperf client rate with egress packet rate limit on client (bps): %v", egressLimitedRate)
						// Expect the limited rate to be below an estimated desired rate (1000 byte packets * 8 bits/byte * 100 packets/s = 800000bps) , with a 20% margin
						Expect(egressLimitedRate).To(BeNumerically(">=", 1000*8*100*0.8))
						Expect(egressLimitedRate).To(BeNumerically("<=", 1000*8*100*1.2))

						By("Removing all limits from workload 1")
						w[1].WorkloadEndpoint.Spec.QoSControls = nil
						w[1].UpdateInInfra(infra)
						Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

						if BPFMode() {
							By("Waiting for the config to disappear in the BPF maps on workload 1")
							Consistently(getBPFPacketRateAndBurst(1, 1, "ingress"), "10s", "1s").Should(Equal("0 0"))
							Eventually(getBPFPacketRateAndBurst(1, 1, "egress"), "10s", "1s").Should(Equal("0 0"))
						} else {
							By("Waiting for the config to disappear in 'iptables-save/nft list ruleset' on workload 1")
							if NFTMode() {
								// ingress config should not be present
								Consistently(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-tw-` + w[1].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
								// egress config should not be present
								Eventually(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-fw-` + w[1].InterfaceName + ` {[^}]*limit rate over ` + regexp.QuoteMeta("100") + `/second burst ` + regexp.QuoteMeta("200") + ` packets drop`))
							} else {
								// ingress config should not be present
								Consistently(getRules(1), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-tw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m mark ! --mark 0x\d+/0x\d+ -j DROP`)))
								// egress config should not be present
								Eventually(getRules(1), "10s", "1s").ShouldNot(Or(MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m limit --limit `+regexp.QuoteMeta("100")+`/sec --limit-burst `+regexp.QuoteMeta("200")+` -j MARK --set-xmark 0x\d+\/0x\d+`), MatchRegexp(`-A cali-fw-`+regexp.QuoteMeta(w[1].InterfaceName)+` .*-m mark ! --mark 0x\d+\/0x\d+ -j DROP`)))
							}
						}

						By("Killing and cleaning up iperf2 server process")
						err = serverCmd.Process.Kill()
						Expect(err).NotTo(HaveOccurred())
						err = serverCmd.Process.Release()
						Expect(err).NotTo(HaveOccurred())

					})
				})

				Context("With connection limits", func() {
					BeforeEach(func() {
						if BPFMode() {
							Skip("Skipping QoS control connection limit tests on BPF mode.")
						}
					})
					tryConnect := func(w *workload.Workload, ip string, port int, opts workload.PersistentConnectionOpts) func() error {
						return func() error {
							logrus.Info("Trying to start connection")
							pc, err := w.StartPersistentConnectionMayFail(ip, port, opts)
							if err == nil {
								pc.Stop()
							}
							return err
						}
					}

					It("should limit connections correctly", func() {
						const numConnections = 4
						pcs := make([]*connectivity.PersistentConnection, numConnections)

						By("Starting persistent connections on workload 1")
						for i := range len(pcs) {
							pcs[i] = w[1].StartPersistentConnection(w[0].IP, 8055, workload.PersistentConnectionOpts{})
						}

						By("Starting n+1th connection on workload 1, expecting success")
						Eventually(tryConnect(w[1], w[0].IP, 8055, workload.PersistentConnectionOpts{}), "10s", "1s").ShouldNot(HaveOccurred())
						logrus.Infof("%dth connection suceeded as expected", numConnections)

						By("Stopping persistent connections")
						for i := range len(pcs) {
							pcs[i].Stop()
						}

						By("Setting connection limit for ingress on workload 0")
						w[0].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
							IngressMaxConnections: int64(numConnections),
						}
						w[0].UpdateInInfra(infra)
						Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(ContainSubstring(w[0].InterfaceName))

						By("Waiting for the config to appear in 'iptables-save/nft list ruleset' on workload 0")
						if NFTMode() {
							// ingress config should be present
							Eventually(getRules(0), "10s", "1s").Should(MatchRegexp(`(?s)chain filter-cali-tw-` + w[0].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
							// egress config should not be present
							Consistently(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-fw-` + w[0].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
						} else {
							// ingress config should be present
							Eventually(getRules(0), "10s", "1s").Should(MatchRegexp(`-A cali-tw-` + regexp.QuoteMeta(w[0].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + `.*-j REJECT --reject-with tcp-reset`))
							// egress config should not be present
							Consistently(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`-A cali-fw-` + regexp.QuoteMeta(w[0].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + ` .*-j REJECT --reject-with tcp-reset`))
						}

						By("Starting persistent connections on workload 1")
						for i := range len(pcs) {
							pcs[i] = w[1].StartPersistentConnection(w[0].IP, 8055, workload.PersistentConnectionOpts{})
						}

						By("Starting n+1th connection on workload 1, expecting failure")
						Eventually(tryConnect(w[1], w[0].IP, 8055, workload.PersistentConnectionOpts{}), "10s", "1s").Should(HaveOccurred())
						logrus.Infof("%dth connection failed as expected", numConnections)

						By("Stopping one persistent connection to free up a spot in the limit")
						pcs[len(pcs)-1].Stop()

						By("Starting nth connection on workload 1, expecting success")
						Eventually(tryConnect(w[1], w[0].IP, 8055, workload.PersistentConnectionOpts{}), "10s", "1s").ShouldNot(HaveOccurred())
						logrus.Infof("%dth connection failed as expected", numConnections-1)

						By("Stopping remaining persistent connections")
						for i := range len(pcs) - 1 {
							pcs[i].Stop()
						}

						By("Removing all limits from workload 0")
						w[0].WorkloadEndpoint.Spec.QoSControls = nil
						w[0].UpdateInInfra(infra)
						Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(ContainSubstring(w[0].InterfaceName))

						By("Waiting for the config to disappear in 'iptables-save/nft list ruleset' on workload 0")
						if NFTMode() {
							// ingress config should be present
							Eventually(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-tw-` + w[0].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
							// egress config should not be present
							Consistently(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-fw-` + w[0].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
						} else {
							// ingress config should be present
							Eventually(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`-A cali-tw-` + regexp.QuoteMeta(w[0].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + ` .*-j REJECT --reject-with tcp-reset`))
							// egress config should not be present
							Consistently(getRules(0), "10s", "1s").ShouldNot(MatchRegexp(`-A cali-fw-` + regexp.QuoteMeta(w[0].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + ` .*-j REJECT --reject-with tcp-reset`))
						}

						By("Setting connection limit for egress on workload 1 (clients)")
						w[1].WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
							EgressMaxConnections: int64(numConnections),
						}
						w[1].UpdateInInfra(infra)
						Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

						By("Waiting for the config to appear in 'iptables-save/nft list ruleset' on workload 1")
						if NFTMode() {
							// ingress config should not be present
							Consistently(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-tw-` + w[1].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
							// egress config should be present
							Eventually(getRules(1), "10s", "1s").Should(MatchRegexp(`(?s)chain filter-cali-fw-` + w[1].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
						} else {
							// ingress config should not be present
							Consistently(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`-A cali-tw-` + regexp.QuoteMeta(w[1].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + ` .*-j REJECT --reject-with tcp-reset`))
							// egress config should be present
							Eventually(getRules(1), "10s", "1s").Should(MatchRegexp(`-A cali-fw-` + regexp.QuoteMeta(w[1].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + ` .*-j REJECT --reject-with tcp-reset`))
						}

						By("Starting persistent connections on workload 1")
						for i := range len(pcs) {
							pcs[i] = w[1].StartPersistentConnection(w[0].IP, 8055, workload.PersistentConnectionOpts{})
						}

						By("Starting n+1th connection on workload 1, expecting failure")
						Eventually(tryConnect(w[1], w[0].IP, 8055, workload.PersistentConnectionOpts{}), "10s", "1s").Should(HaveOccurred())
						logrus.Infof("%dth connection failed as expected", numConnections)

						By("Stopping persistent connections")
						for i := range len(pcs) {
							pcs[i].Stop()
						}

						By("Removing all limits from workload 1")
						w[1].WorkloadEndpoint.Spec.QoSControls = nil
						w[1].UpdateInInfra(infra)
						Eventually(tc.Felixes[1].ExecOutputFn("ip", "r", "get", "10.65.1.2"), "10s").Should(ContainSubstring(w[1].InterfaceName))

						By("Waiting for the config to disappear in 'iptables-save/nft list ruleset' on workload 1")
						if NFTMode() {
							// ingress config should not be present
							Consistently(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-tw-` + w[1].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
							// egress config should not be present
							Eventually(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`(?s)chain filter-cali-fw-` + w[1].InterfaceName + ` {[^}]*ct count over ` + fmt.Sprintf("%d", numConnections) + ` reject with tcp reset`))
						} else {
							// ingress config should not be present
							Consistently(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`-A cali-tw-` + regexp.QuoteMeta(w[1].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + ` .*-j REJECT --reject-with tcp-reset`))
							// egress config should not be present
							Eventually(getRules(1), "10s", "1s").ShouldNot(MatchRegexp(`-A cali-fw-` + regexp.QuoteMeta(w[1].InterfaceName) + ` .*-m connlimit .*--connlimit-above ` + fmt.Sprintf("%d", numConnections) + ` .*-j REJECT --reject-with tcp-reset`))
						}

						By("Starting persistent connections on workload 1")
						for i := range len(pcs) {
							pcs[i] = w[1].StartPersistentConnection(w[0].IP, 8055, workload.PersistentConnectionOpts{})
						}

						By("Starting n+1th connection on workload 1, expecting success")
						Eventually(tryConnect(w[1], w[0].IP, 8055, workload.PersistentConnectionOpts{}), "10s", "1s").ShouldNot(HaveOccurred())
						logrus.Infof("%dth connection suceeded as expected", numConnections)

						By("Stopping persistent connections")
						for i := range len(pcs) {
							pcs[i].Stop()
						}
					})
				})
			})
		}
	})

// parseIperf3JsonOutput parses json output from 'iperf3' and returns
// the whole test duration's rate in bits per second, as well as the
// first interval's rate (in order to verify peakrate configuration)
// and possibly an error.
func parseIperf3JsonOutput(output string) (float64, float64, error) {
	var rate, peakrate float64
	perf := iperfReport{}
	err := json.Unmarshal([]byte(output), &perf)
	if err != nil {
		return 0.0, 0.0, fmt.Errorf("failed to unmarshal iperf data: %w", err)
	}
	// iperf3 reports the result of its 10-second run in perf.End, but it also reports results for every 1-second interval in perf.Intervals[] (even those ignored for the sum calculation with the '-O' argument)
	rate = perf.End.SumReceived.BitsPerSecond
	// Use the first 1-second interval reported rate to verify peakrate controls
	if len(perf.Intervals) > 0 {
		peakrate = perf.Intervals[0].Sum.BitsPerSecond
	}
	logrus.WithFields(logrus.Fields{"rate": rate, "peakrate": peakrate, "perf": perf}).Infof("Finished parseIperf3JsonOutput")
	return rate, peakrate, nil
}

// retryIperf3Client retries running the 'iperf3' client until it successfully can return a rate and a peakrate, or fails if it
// cannot after retryNum tries.
func retryIperf3Client(w *workload.Workload, retryNum int, retryInterval time.Duration, args ...string) (float64, float64, error) {
	var err error
	var rate, peakrate float64
	var out string

	args = append([]string{"iperf3"}, args...)

	for i := range retryNum {
		// Use i+1 when logging to begin counting from 1, not 0
		logrus.Infof("retryIperf3Client: Retry %d of %d", i+1, retryNum)
		out, err = w.ExecOutput(args...)
		if err != nil {
			time.Sleep(retryInterval)
			continue
		}
		rate, peakrate, err = parseIperf3JsonOutput(out)
		if err != nil || rate == 0 || peakrate == 0 {
			time.Sleep(retryInterval)
			continue
		}
		break
	}

	if err != nil {
		return 0.0, 0.0, fmt.Errorf("retryIperf3Client error: %w", err)
	}

	return rate, peakrate, nil
}

// parseIperf2Output parses the output from 'iperf2' and returns
// the whole test duration's rate in bits per second and possibly
// an error.
func parseIperf2Output(output string) (float64, error) {
	var err error
	var rate float64

	logrus.WithFields(logrus.Fields{"output": output}).Infof("Starting parseIperf2Output")

	// Regex to find the bandwidth line under "Server Report"
	re := regexp.MustCompile(`Server Report:\s*\n(?:.*\n){1,2}\[\s*\d+\]\s+[^\n]*?(\d+(?:\.\d+)?\s*[KMG]?bits/sec)`)
	match := re.FindStringSubmatch(output)
	if len(match) == 0 {
		return 0.0, fmt.Errorf("failed to find rate in iperf2 output")
	}
	rateLine := match[1]

	// Regex to extract number and unit from the bandwidth value
	rateRe := regexp.MustCompile(`([\d.]+)\s*([KMG])?bits/sec`)
	rateMatch := rateRe.FindStringSubmatch(rateLine)
	if len(rateMatch) < 2 {
		return 0.0, fmt.Errorf("could not parse rate value")
	}
	num, err := strconv.ParseFloat(rateMatch[1], 64)
	if err != nil {
		return 0.0, fmt.Errorf("error converting rate: %w", err)
	}

	multiplier := 1.0
	if len(rateMatch) >= 3 {
		switch strings.ToUpper(rateMatch[2]) {
		case "K":
			multiplier = 1e3
		case "M":
			multiplier = 1e6
		case "G":
			multiplier = 1e9
		}
	}

	rate = num * multiplier

	logrus.WithFields(logrus.Fields{"rate": rate, "output": output}).Infof("Finished parseIperf2Output")

	return rate, nil
}

// retryIperf2Client retries running the 'iperf2' client until it successfully can return a rate, or fails if it
// cannot after retryNum tries.
func retryIperf2Client(w *workload.Workload, retryNum int, retryInterval time.Duration, args ...string) (float64, error) {
	var err error
	var rate float64
	var out string

	args = append([]string{"iperf"}, args...)

	for i := range retryNum {
		// Use i+1 when logging to begin counting from 1, not 0
		logrus.Infof("retryIperf2Client: Retry %d of %d", i+1, retryNum)
		out, err = w.ExecOutput(args...)
		if err != nil {
			time.Sleep(retryInterval)
			continue
		}
		rate, err = parseIperf2Output(out)
		if err != nil || rate == 0 {
			time.Sleep(retryInterval)
			continue
		}
		break
	}

	if err != nil {
		return 0.0, fmt.Errorf("retryIperf2Client error: %w", err)
	}

	return rate, nil
}
