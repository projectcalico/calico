// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/proxy"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/timeshim"
)

// We run with and without connection-time load balancing for a couple of reasons:
//   - We can only test the non-connection time NAT logic (and node ports) with it disabled.
//   - Since the connection time program applies to the whole host, the different felix nodes actually share the
//     connection-time program.  This is a bit of a broken test but it's better than nothing since all felix nodes
//     should be programming the same NAT mappings.
var _ = describeBPFTests(withProto("tcp"), withConnTimeLoadBalancingEnabled(), withNonProtocolDependentTests())
var _ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withProto("tcp"), withConnTimeLoadBalancingEnabled(), withNonProtocolDependentTests(), withIPFamily(6))
var _ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled(), withIPFamily(6))
var _ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled(), withUDPUnConnected())
var _ = describeBPFTests(withProto("tcp"))
var _ = describeBPFTests(withProto("tcp"), withIPFamily(6))
var _ = describeBPFTests(withProto("udp"))
var _ = describeBPFTests(withProto("udp"), withUDPUnConnected())
var _ = describeBPFTests(withProto("udp"), withUDPConnectedRecvMsg(), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withTunnel("ipip"), withProto("tcp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withTunnel("ipip"), withProto("udp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withTunnel("ipip"), withProto("tcp"))
var _ = describeBPFTests(withTunnel("ipip"), withProto("udp"))
var _ = describeBPFTests(withProto("tcp"), withDSR())
var _ = describeBPFTests(withProto("udp"), withDSR())
var _ = describeBPFTests(withTunnel("ipip"), withProto("tcp"), withDSR())
var _ = describeBPFTests(withTunnel("ipip"), withProto("udp"), withDSR())
var _ = describeBPFTests(withTunnel("wireguard"), withProto("tcp"))
var _ = describeBPFTests(withTunnel("wireguard"), withProto("tcp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withTunnel("vxlan"), withProto("tcp"))
var _ = describeBPFTests(withTunnel("vxlan"), withProto("tcp"), withConnTimeLoadBalancingEnabled())

// Run a stripe of tests with BPF logging disabled since the compiler tends to optimise the code differently
// with debug disabled and that can lead to verifier issues.
var _ = describeBPFTests(withProto("tcp"),
	withConnTimeLoadBalancingEnabled(),
	withBPFLogLevel("info"))

type bpfTestOptions struct {
	connTimeEnabled bool
	protocol        string
	udpUnConnected  bool
	bpfLogLevel     string
	tunnel          string
	dsr             bool
	udpConnRecvMsg  bool
	nonProtoTests   bool
	ipv6            bool
}

type bpfTestOpt func(opts *bpfTestOptions)

func withIPFamily(family int) bpfTestOpt {
	return func(opts *bpfTestOptions) {
		if family == 6 {
			opts.ipv6 = true
		} else {
			opts.ipv6 = false
		}
	}
}

func withProto(proto string) bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.protocol = proto
	}
}

func withConnTimeLoadBalancingEnabled() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.connTimeEnabled = true
	}
}

func withNonProtocolDependentTests() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.nonProtoTests = true
	}
}

func withBPFLogLevel(level string) bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.bpfLogLevel = level
	}
}

func withTunnel(tunnel string) bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.tunnel = tunnel
	}
}

func withUDPUnConnected() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.udpUnConnected = true
	}
}

func withDSR() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.dsr = true
	}
}

func withUDPConnectedRecvMsg() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.udpConnRecvMsg = true
	}
}

const expectedRouteDump = `10.65.0.0/16: remote in-pool nat-out
10.65.0.2/32: local workload in-pool nat-out idx -
10.65.0.3/32: local workload in-pool nat-out idx -
10.65.1.0/26: remote workload in-pool nat-out nh FELIX_1
10.65.2.0/26: remote workload in-pool nat-out nh FELIX_2
111.222.0.1/32: local host
111.222.1.1/32: remote host
111.222.2.1/32: remote host
FELIX_0/32: local host
FELIX_1/32: remote host
FELIX_2/32: remote host`

const expectedRouteDumpWithTunnelAddr = `10.65.0.0/16: remote in-pool nat-out
10.65.0.2/32: local workload in-pool nat-out idx -
10.65.0.3/32: local workload in-pool nat-out idx -
10.65.1.0/26: remote workload in-pool nat-out tunneled nh FELIX_1
10.65.2.0/26: remote workload in-pool nat-out tunneled nh FELIX_2
111.222.0.1/32: local host
111.222.1.1/32: remote host
111.222.2.1/32: remote host
FELIX_0/32: local host
FELIX_0_TNL/32: local host
FELIX_1/32: remote host
FELIX_1_TNL/32: remote host in-pool nat-out tunneled
FELIX_2/32: remote host
FELIX_2_TNL/32: remote host in-pool nat-out tunneled`

const expectedRouteDumpDSR = `10.65.0.0/16: remote in-pool nat-out
10.65.0.2/32: local workload in-pool nat-out idx -
10.65.0.3/32: local workload in-pool nat-out idx -
10.65.1.0/26: remote workload in-pool nat-out nh FELIX_1
10.65.2.0/26: remote workload in-pool nat-out nh FELIX_2
111.222.0.1/32: local host
111.222.1.1/32: remote host
111.222.2.1/32: remote host
245.245.0.0/16: remote no-dsr
FELIX_0/32: local host
FELIX_1/32: remote host
FELIX_2/32: remote host`

const expectedRouteDumpWithTunnelAddrDSR = `10.65.0.0/16: remote in-pool nat-out
10.65.0.2/32: local workload in-pool nat-out idx -
10.65.0.3/32: local workload in-pool nat-out idx -
10.65.1.0/26: remote workload in-pool nat-out tunneled nh FELIX_1
10.65.2.0/26: remote workload in-pool nat-out tunneled nh FELIX_2
111.222.0.1/32: local host
111.222.1.1/32: remote host
111.222.2.1/32: remote host
245.245.0.0/16: remote no-dsr
FELIX_0/32: local host
FELIX_0_TNL/32: local host
FELIX_1/32: remote host
FELIX_1_TNL/32: remote host in-pool nat-out tunneled
FELIX_2/32: remote host
FELIX_2_TNL/32: remote host in-pool nat-out tunneled`

func BPFMode() bool {
	return os.Getenv("FELIX_FV_ENABLE_BPF") == "true"
}

func BPFIPv6Support() bool {
	return false
}

func describeBPFTests(opts ...bpfTestOpt) bool {
	if !BPFMode() {
		// Non-BPF run.
		return true
	}

	testOpts := bpfTestOptions{
		bpfLogLevel: "debug",
		tunnel:      "none",
	}
	for _, o := range opts {
		o(&testOpts)
	}

	testIfTCP := testOpts.protocol == "tcp"
	testIfNotUDPUConnected := (!testOpts.udpUnConnected)

	protoExt := ""
	if testOpts.udpUnConnected {
		protoExt = "-unconnected"
	}
	if testOpts.udpConnRecvMsg {
		protoExt = "-conn-recvmsg"
	}

	family := "ipv4"
	if testOpts.ipv6 {
		family = "ipv6"
	}

	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ BPF tests (%s %s%s, ct=%v, log=%s, tunnel=%s, dsr=%v)",
		family,
		testOpts.protocol, protoExt, testOpts.connTimeEnabled,
		testOpts.bpfLogLevel, testOpts.tunnel, testOpts.dsr,
	)
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		var (
			infra              infrastructure.DatastoreInfra
			tc                 infrastructure.TopologyContainers
			calicoClient       client.Interface
			cc                 *Checker
			externalClient     *containers.Container
			deadWorkload       *workload.Workload
			options            infrastructure.TopologyOptions
			numericProto       uint8
			felixPanicExpected bool
		)

		containerIP := func(c *containers.Container) string {
			if testOpts.ipv6 {
				return c.IPv6
			}
			return c.IP
		}

		felixIP := func(f int) string {
			return containerIP(tc.Felixes[f].Container)
		}

		ipMask := func() string {
			if testOpts.ipv6 {
				return "128"
			}
			return "32"
		}

		switch testOpts.protocol {
		case "tcp":
			numericProto = 6
		case "udp":
			numericProto = 17
		default:
			Fail("bad protocol option")
		}

		BeforeEach(func() {
			felixPanicExpected = false

			iOpts := []infrastructure.CreateOption{}
			if testOpts.ipv6 {
				iOpts = append(iOpts,
					infrastructure.K8sWithIPv6(),
					infrastructure.K8sWithAPIServerBindAddress("::"),
					infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112"),
				)
			}

			infra = getInfra(iOpts...)

			cc = &Checker{
				CheckSNAT: true,
			}
			cc.Protocol = testOpts.protocol
			if testOpts.protocol == "udp" && testOpts.udpUnConnected {
				cc.Protocol += "-noconn"
			}
			if testOpts.protocol == "udp" && testOpts.udpConnRecvMsg {
				cc.Protocol += "-recvmsg"
			}

			options = infrastructure.DefaultTopologyOptions()
			options.EnableIPv6 = testOpts.ipv6
			options.FelixLogSeverity = "Debug"
			options.NATOutgoingEnabled = true
			options.AutoHEPsEnabled = true
			// override IPIP being enabled by default
			options.IPIPEnabled = false
			options.IPIPRoutesEnabled = false
			switch testOpts.tunnel {
			case "none":
				// nothing
			case "ipip":
				options.IPIPEnabled = true
				options.IPIPRoutesEnabled = true
			case "vxlan":
				options.VXLANMode = api.VXLANModeAlways
			case "wireguard":
				if testOpts.ipv6 {
					// Allocate tunnel address for Wireguard.
					options.WireguardEnabledV6 = true
					// Enable Wireguard.
					options.ExtraEnvVars["FELIX_WIREGUARDENABLEDV6"] = "true"
				} else {
					// Allocate tunnel address for Wireguard.
					options.WireguardEnabled = true
					// Enable Wireguard.
					options.ExtraEnvVars["FELIX_WIREGUARDENABLED"] = "true"
				}
			default:
				Fail("bad tunnel option")
			}
			if testOpts.tunnel != "none" {
				// Avoid felix restart mid-test, wait for the node resource to be created before starting Felix.
				options.DelayFelixStart = true
				options.TriggerDelayedFelixStart = true
			}
			options.ExtraEnvVars["FELIX_BPFLogLevel"] = fmt.Sprint(testOpts.bpfLogLevel)
			if testOpts.dsr {
				options.ExtraEnvVars["FELIX_BPFExternalServiceMode"] = "dsr"
			}
			// ACCEPT is what is set by our manifests and operator by default.
			options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "ACCEPT"
			options.ExternalIPs = true
			options.ExtraEnvVars["FELIX_BPFExtToServiceConnmark"] = "0x80"
			options.ExtraEnvVars["FELIX_HEALTHENABLED"] = "true"
			if !testOpts.ipv6 {
				options.ExtraEnvVars["FELIX_BPFDSROptoutCIDRs"] = "245.245.0.0/16"
				options.ExtraEnvVars["FELIX_HEALTHHOST"] = "0.0.0.0"
			} else {
				options.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
				options.ExtraEnvVars["FELIX_HEALTHHOST"] = "::"
			}

			if testOpts.protocol == "tcp" {
				filters := map[string]string{"all": "tcp"}
				felixConfig := api.NewFelixConfiguration()
				felixConfig.SetName("default")
				felixConfig.Spec = api.FelixConfigurationSpec{
					BPFLogFilters: &filters,
				}
				if testOpts.connTimeEnabled {
					felixConfig.Spec.BPFCTLBLogFilter = "all"
				}
				options.InitialFelixConfiguration = felixConfig
			}

			if !testOpts.connTimeEnabled {
				options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBDisabled)
				options.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)
				if testOpts.protocol == "udp" {
					options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBTCP)
				}
			} else {
				options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBEnabled)
				options.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATDisabled)
				if testOpts.protocol == "tcp" {
					options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBTCP)
				}
			}

		})

		JustAfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				var (
					currBpfsvcs   []nat.MapMem
					currBpfeps    []nat.BackendMapMem
					currBpfsvcsV6 []nat.MapMemV6
					currBpfepsV6  []nat.BackendMapMemV6
				)

				if testOpts.ipv6 {
					currBpfsvcsV6, currBpfepsV6 = dumpNATmapsV6(tc.Felixes)
				} else {
					currBpfsvcs, currBpfeps = dumpNATmaps(tc.Felixes)
				}

				for i, felix := range tc.Felixes {
					felix.Exec("conntrack", "-L")
					felix.Exec("calico-bpf", "policy", "dump", "cali8d1e69e5f89", "all", "--asm")
					if testOpts.ipv6 {
						felix.Exec("ip6tables-save", "-c")
						felix.Exec("ip", "-6", "link")
						felix.Exec("ip", "-6", "addr")
						felix.Exec("ip", "-6", "rule")
						felix.Exec("ip", "-6", "route")
						felix.Exec("ip", "-6", "route", "show", "table", "1")
						felix.Exec("ip", "-6", "neigh")
						felix.Exec("calico-bpf", "-6", "ipsets", "dump")
						felix.Exec("calico-bpf", "-6", "routes", "dump")
						felix.Exec("calico-bpf", "-6", "nat", "dump")
						felix.Exec("calico-bpf", "-6", "nat", "aff")
						felix.Exec("calico-bpf", "-6", "conntrack", "dump")
						felix.Exec("calico-bpf", "-6", "arp", "dump")
					} else {
						felix.Exec("iptables-save", "-c")
						felix.Exec("ip", "link")
						felix.Exec("ip", "addr")
						felix.Exec("ip", "rule")
						felix.Exec("ip", "route")
						felix.Exec("ip", "neigh")
						felix.Exec("arp")
						felix.Exec("calico-bpf", "ipsets", "dump")
						felix.Exec("calico-bpf", "routes", "dump")
						felix.Exec("calico-bpf", "nat", "dump")
						felix.Exec("calico-bpf", "nat", "aff")
						felix.Exec("calico-bpf", "conntrack", "dump")
						felix.Exec("calico-bpf", "arp", "dump")
					}
					felix.Exec("calico-bpf", "counters", "dump")
					felix.Exec("calico-bpf", "ifstate", "dump")
					if testOpts.ipv6 {
						log.Infof("[%d]FrontendMapV6: %+v", i, currBpfsvcsV6[i])
						log.Infof("[%d]NATBackendV6: %+v", i, currBpfepsV6[i])
						log.Infof("[%d]SendRecvMapV6: %+v", i, dumpSendRecvMapV6(felix))
					} else {
						log.Infof("[%d]FrontendMap: %+v", i, currBpfsvcs[i])
						log.Infof("[%d]NATBackend: %+v", i, currBpfeps[i])
						log.Infof("[%d]SendRecvMap: %+v", i, dumpSendRecvMap(felix))
					}
				}
				externalClient.Exec("ip", "route", "show", "cached")
			}
		})

		AfterEach(func() {
			log.Info("AfterEach starting")
			for _, f := range tc.Felixes {
				if !felixPanicExpected {
					_ = f.ExecMayFail("calico-bpf", "connect-time", "clean")
				}
				f.Stop()
			}
			externalClient.Stop()
			log.Info("AfterEach done")
		})

		AfterEach(func() {
			infra.Stop()
		})

		createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Creating policy")
			policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}

		updatePolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Updating policy")
			policy, err := calicoClient.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}
		_ = updatePolicy

		Describe("with a single node and an allow-all policy", func() {
			var (
				hostW   *workload.Workload
				w       [2]*workload.Workload
				wepCopy [2]*libapi.WorkloadEndpoint
			)

			if !testOpts.connTimeEnabled {
				// These tests don't depend on NAT.
				return
			}

			if testOpts.tunnel != "none" {
				// Single node so tunnel doesn't matter.
				return
			}

			JustBeforeEach(func() {
				tc, calicoClient = infrastructure.StartNNodeTopology(1, options, infra)

				hostW = workload.Run(
					tc.Felixes[0],
					"host",
					"default",
					felixIP(0), // Same IP as felix means "run in the host's namespace"
					"8055",
					testOpts.protocol)

				// Start a couple of workloads so we can check workload-to-workload and workload-to-host.
				for i := 0; i < 2; i++ {
					wIP := fmt.Sprintf("10.65.0.%d", i+2)
					if testOpts.ipv6 {
						wIP = fmt.Sprintf("dead:beef::%d", i+2)
					}
					w[i] = workload.Run(tc.Felixes[0], fmt.Sprintf("w%d", i), "default", wIP, "8055", testOpts.protocol)
					w[i].WorkloadEndpoint.Labels = map[string]string{"name": w[i].Name}
					// WEP gets clobbered when we add it to the datastore, take a copy so we can re-create the WEP.
					wepCopy[i] = w[i].WorkloadEndpoint
					w[i].ConfigureInInfra(infra)
				}

				err := infra.AddDefaultDeny()
				Expect(err).NotTo(HaveOccurred())

				ensureBPFProgramsAttached(tc.Felixes[0])

				pol := api.NewGlobalNetworkPolicy()
				pol.Namespace = "fv"
				pol.Name = "policy-1"
				pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
				pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
				pol.Spec.Selector = "all()"

				pol = createPolicy(pol)
			})

			if testOpts.bpfLogLevel == "debug" && testOpts.protocol == "tcp" {
				Describe("with custom IptablesMarkMask", func() {
					BeforeEach(func() {
						// Disable core dumps, we know we're about to cause a panic.
						options.ExtraEnvVars["GOTRACEBACK"] = ""
						felixPanicExpected = true
					})

					It("0xffff000 not covering BPF bits should panic", func() {
						felixPanicExpected = true
						panicC := tc.Felixes[0].WatchStdoutFor(regexp.MustCompile("PANIC.*IptablesMarkMask doesn't cover bits that are used"))

						fc, err := calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
						felixConfigExists := err == nil
						if !felixConfigExists {
							fc = api.NewFelixConfiguration()
						}
						fc.Name = "default"
						mark := uint32(0x0ffff000)
						fc.Spec.IptablesMarkMask = &mark
						if felixConfigExists {
							_, err = calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
						} else {
							fc, err = calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
						}
						Expect(err).NotTo(HaveOccurred())

						Eventually(panicC, "5s", "100ms").Should(BeClosed())
					})

					It("0xfff00000 only covering BPF bits should panic", func() {
						panicC := tc.Felixes[0].WatchStdoutFor(regexp.MustCompile("PANIC.*Not enough mark bits available"))

						fc, err := calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
						felixConfigExists := err == nil
						if !felixConfigExists {
							fc = api.NewFelixConfiguration()
						}
						fc.Name = "default"
						mark := uint32(0xfff00000)
						fc.Spec.IptablesMarkMask = &mark
						if felixConfigExists {
							_, err = calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
						} else {
							fc, err = calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
						}
						Expect(err).NotTo(HaveOccurred())

						Eventually(panicC, "5s", "100ms").Should(BeClosed())
					})
				})
			}

			Describe("with DefaultEndpointToHostAction=DROP", func() {
				BeforeEach(func() {
					options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "DROP"
				})
				It("should only allow traffic from workload to workload", func() {
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					cc.ExpectNone(w[1], hostW)
					cc.ExpectSome(hostW, w[0])
					cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
				})
			})

			Describe("with DefaultEndpointToHostAction=RETURN", func() {
				BeforeEach(func() {
					options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "RETURN"
					options.AutoHEPsEnabled = false
				})
				It("should allow traffic from workload to host", func() {
					cc.Expect(Some, w[1], hostW)
					cc.Expect(Some, hostW, w[0])
					cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
				})
			})

			getMapIDByPath := func(felix *infrastructure.Felix, filename string) (int, error) {
				out, err := felix.ExecOutput("bpftool", "map", "show", "pinned", filename, "-j")
				if err != nil {
					return 0, err
				}
				var mapMeta struct {
					ID    int    `json:"id"`
					Error string `json:"error"`
				}
				err = json.Unmarshal([]byte(out), &mapMeta)
				if err != nil {
					return 0, err
				}
				if mapMeta.Error != "" {
					return 0, errors.New(mapMeta.Error)
				}
				return mapMeta.ID, nil
			}

			mustGetMapIDByPath := func(felix *infrastructure.Felix, filename string) int {
				var mapID int
				Eventually(func() error {
					var err error
					mapID, err = getMapIDByPath(felix, filename)
					return err
				}, "5s").ShouldNot(HaveOccurred())
				return mapID
			}

			Describe("with DefaultEndpointToHostAction=ACCEPT", func() {
				BeforeEach(func() {
					options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "ACCEPT"
				})
				It("should allow traffic from workload to workload and to/from host", func() {
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					cc.ExpectSome(w[1], hostW)
					cc.ExpectSome(hostW, w[0])
					cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
				})
			})

			if testOpts.protocol == "udp" && testOpts.connTimeEnabled {
				Describe("with BPFHostNetworkedNAT enabled", func() {
					BeforeEach(func() {
						options.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)
						options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBTCP)
					})
					It("should not program non-udp services", func() {
						clusterIP := "10.101.0.201"
						if testOpts.ipv6 {
							clusterIP = "dead:beef::abcd:0:0:201"
						}
						udpsvc := &v1.Service{
							TypeMeta: typeMetaV1("Service"),
							ObjectMeta: metav1.ObjectMeta{
								Name:      "udp-service",
								Namespace: "default",
							},
							Spec: v1.ServiceSpec{
								ClusterIP: clusterIP,
								Type:      v1.ServiceTypeClusterIP,
								Ports: []v1.ServicePort{
									{
										Protocol: v1.ProtocolUDP,
										Port:     1234,
									},
								},
							},
						}

						k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient

						_, err := k8sClient.CoreV1().Services("default").Create(context.Background(),
							udpsvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())

						Eventually(func() bool {
							return checkServiceRoute(tc.Felixes[0], udpsvc.Spec.ClusterIP)
						}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(), "Failed to sync with udp service")

						clusterIP2 := "10.101.0.202"
						if testOpts.ipv6 {
							clusterIP2 = "dead:beef::abcd:0:0:202"
						}
						tcpsvc := &v1.Service{
							TypeMeta: typeMetaV1("Service"),
							ObjectMeta: metav1.ObjectMeta{
								Name:      "tcp-service",
								Namespace: "default",
							},
							Spec: v1.ServiceSpec{
								ClusterIP: clusterIP2,
								Type:      v1.ServiceTypeClusterIP,
								Ports: []v1.ServicePort{
									{
										Protocol: v1.ProtocolTCP,
										Port:     4321,
									},
								},
							},
						}

						_, err = k8sClient.CoreV1().Services("default").Create(context.Background(),
							tcpsvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())

						Consistently(func() bool {
							return checkServiceRoute(tc.Felixes[0], tcpsvc.Spec.ClusterIP)
						}, 1*time.Second, 300*time.Millisecond).Should(BeFalse(), "Unexpected TCP service")

						clusterIP3 := "10.101.0.203"
						if testOpts.ipv6 {
							clusterIP3 = "dead:beef::abcd:0:0:203"
						}
						tcpudpsvc := &v1.Service{
							TypeMeta: typeMetaV1("Service"),
							ObjectMeta: metav1.ObjectMeta{
								Name:      "tcp-udp-service",
								Namespace: "default",
							},
							Spec: v1.ServiceSpec{
								ClusterIP: clusterIP3,
								Type:      v1.ServiceTypeClusterIP,
								Ports: []v1.ServicePort{
									{
										Name:     "udp",
										Protocol: v1.ProtocolUDP,
										Port:     1234,
									},
									{
										Name:     "tcp",
										Protocol: v1.ProtocolTCP,
										Port:     4321,
									},
								},
							},
						}

						_, err = k8sClient.CoreV1().Services("default").Create(context.Background(),
							tcpudpsvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())

						Eventually(func() bool {
							return checkServiceRoute(tc.Felixes[0], tcpudpsvc.Spec.ClusterIP)
						}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(), "Failed to sync with tcpudp service")

						Expect(checkServiceRoute(tc.Felixes[0], tcpsvc.Spec.ClusterIP)).To(BeFalse())
					})
				})
			}

			if testOpts.protocol != "udp" { // No need to run these tests per-protocol.

				mapPath := conntrack.Map().Path()

				if testOpts.ipv6 {
					mapPath = conntrack.MapV6().Path()
				}

				Describe("with map repinning enabled", func() {
					BeforeEach(func() {
						options.ExtraEnvVars["FELIX_DebugBPFMapRepinEnabled"] = "true"
					})

					It("should repin maps", func() {
						// Wait for the first felix to create its maps.
						mapID := mustGetMapIDByPath(tc.Felixes[0], mapPath)

						// Now, start a completely independent felix, which will get its own bpffs.  It should re-pin the
						// maps, picking up the ones from the first felix.
						tc, _ := infrastructure.StartSingleNodeTopology(options, infra)
						defer tc.Stop()

						secondMapID := mustGetMapIDByPath(tc.Felixes[0], mapPath)
						Expect(mapID).NotTo(BeNumerically("==", 0))
						Expect(mapID).To(BeNumerically("==", secondMapID))
					})
				})

				Describe("with map repinning disabled", func() {
					It("should repin maps", func() {
						// Wait for the first felix to create its maps.
						mapID := mustGetMapIDByPath(tc.Felixes[0], mapPath)

						// Now, start a completely independent felix, which will get its own bpffs.  It should make its own
						// maps.
						tc, _ := infrastructure.StartSingleNodeTopology(options, infra)
						defer tc.Stop()

						secondMapID := mustGetMapIDByPath(tc.Felixes[0], mapPath)
						Expect(mapID).NotTo(BeNumerically("==", 0))
						Expect(mapID).NotTo(BeNumerically("==", secondMapID))
					})
				})

				It("should recover if the BPF programs are removed", func() {
					flapInterface := func() {
						By("Flapping interface")
						tc.Felixes[0].Exec("ip", "link", "set", "down", w[0].InterfaceName)
						tc.Felixes[0].Exec("ip", "link", "set", "up", w[0].InterfaceName)
					}

					recreateWEP := func() {
						By("Recreating WEP.")
						w[0].RemoveFromInfra(infra)
						w[0].WorkloadEndpoint = wepCopy[0]
						w[0].ConfigureInInfra(infra)
					}

					for _, trigger := range []func(){flapInterface, recreateWEP} {
						// Wait for initial programming to complete.
						cc.Expect(Some, w[0], w[1])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						By("handling ingress program removal")
						tc.Felixes[0].Exec("tc", "filter", "del", "ingress", "dev", w[0].InterfaceName)

						// Removing the ingress program should break connectivity due to the lack of "seen" mark.
						cc.Expect(None, w[0], w[1])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						// Trigger felix to recover.
						trigger()
						cc.Expect(Some, w[0], w[1])
						cc.CheckConnectivity()

						// Check the program is put back.
						Eventually(func() string {
							out, _ := tc.Felixes[0].ExecOutput("tc", "filter", "show", "ingress", "dev", w[0].InterfaceName)
							return out
						}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
							fmt.Sprintf("from wep not loaded for %s", w[0].InterfaceName))

						By("handling egress program removal")
						tc.Felixes[0].Exec("tc", "filter", "del", "egress", "dev", w[0].InterfaceName)
						// Removing the egress program doesn't stop traffic.

						// Trigger felix to recover.
						trigger()

						// Check the program is put back.
						Eventually(func() string {
							out, _ := tc.Felixes[0].ExecOutput("tc", "filter", "show", "egress", "dev", w[0].InterfaceName)
							return out
						}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
							fmt.Sprintf("to wep not loaded for %s", w[0].InterfaceName))
						cc.CheckConnectivity()

						By("Handling qdisc removal")
						tc.Felixes[0].Exec("tc", "qdisc", "delete", "dev", w[0].InterfaceName, "clsact")

						// Trigger felix to recover.
						trigger()

						// Check programs are put back.
						Eventually(func() string {
							out, _ := tc.Felixes[0].ExecOutput("tc", "filter", "show", "ingress", "dev", w[0].InterfaceName)
							return out
						}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
							fmt.Sprintf("from wep not loaded for %s", w[0].InterfaceName))
						Eventually(func() string {
							out, _ := tc.Felixes[0].ExecOutput("tc", "filter", "show", "egress", "dev", w[0].InterfaceName)
							return out
						}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
							fmt.Sprintf("to wep not loaded for %s", w[0].InterfaceName))
						cc.CheckConnectivity()
						cc.ResetExpectations()

						// Add a policy to block traffic.
						By("Adding deny policy")
						denyPol := api.NewGlobalNetworkPolicy()
						denyPol.Name = "policy-2"
						var one float64 = 1
						denyPol.Spec.Order = &one
						denyPol.Spec.Ingress = []api.Rule{{Action: "Deny"}}
						denyPol.Spec.Egress = []api.Rule{{Action: "Deny"}}
						denyPol.Spec.Selector = "all()"
						denyPol = createPolicy(denyPol)

						cc.Expect(None, w[0], w[1])
						cc.Expect(None, w[1], w[0])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						By("Removing deny policy")
						_, err := calicoClient.GlobalNetworkPolicies().Delete(context.Background(), "policy-2", options2.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())

						cc.Expect(Some, w[0], w[1])
						cc.Expect(Some, w[1], w[0])
						cc.CheckConnectivity()
						cc.ResetExpectations()
					}
				})
			}

			if testOpts.nonProtoTests {
				// We can only test that felix _sets_ this because the flag is one-way and cannot be unset.
				It("should enable the kernel.unprivileged_bpf_disabled sysctl", func() {
					Eventually(func() string {
						out, err := tc.Felixes[0].ExecOutput("sysctl", "kernel.unprivileged_bpf_disabled")
						if err != nil {
							log.WithError(err).Error("Failed to run sysctl")
						}
						return out
					}).Should(ContainSubstring("kernel.unprivileged_bpf_disabled = 1"))
				})

				It("should remove terminating workload from the NAT backends", func() {
					By("Creating a fake service with fake endpoint")

					clusterIP := "10.101.0.254"
					svcIP1 := "192.168.12.1"
					svcIP2 := "192.168.12.2"
					svcIP3 := "192.168.12.3"
					addrType := discovery.AddressTypeIPv4
					family := 4
					if testOpts.ipv6 {
						clusterIP = "dead:beef::abcd:0:0:254"
						svcIP1 = "dead:beef::192:168:12:1"
						svcIP2 = "dead:beef::192:168:12:2"
						svcIP3 = "dead:beef::192:168:12:3"
						addrType = discovery.AddressTypeIPv6
						family = 6
					}

					fakeSvc := &v1.Service{
						TypeMeta:   typeMetaV1("Service"),
						ObjectMeta: objectMetaV1("fake-service"),
						Spec: v1.ServiceSpec{
							ClusterIP: clusterIP,
							Type:      "ClusterIP",
							Ports: []v1.ServicePort{
								{
									Protocol: v1.ProtocolTCP,
									Port:     int32(11666),
								},
							},
						},
					}

					k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
					_, err := k8sClient.CoreV1().Services("default").Create(context.Background(), fakeSvc, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())

					portName := ""
					portProto := v1.ProtocolTCP
					portPort := int32(11166)
					falsePtr := new(bool)
					*falsePtr = false
					truePtr := new(bool)
					*truePtr = true

					fakeEps := &discovery.EndpointSlice{
						TypeMeta: metav1.TypeMeta{
							Kind:       "EndpointSlice",
							APIVersion: "discovery.k8s.io/v1",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fake-service-eps",
							Namespace: "default",
							Labels: map[string]string{
								"kubernetes.io/service-name": "fake-service",
							},
						},
						AddressType: addrType,
						Endpoints: []discovery.Endpoint{
							{
								Addresses: []string{svcIP1},
								Conditions: discovery.EndpointConditions{
									Ready:       truePtr,
									Terminating: falsePtr,
								},
							},
							{
								Addresses: []string{svcIP2},
								Conditions: discovery.EndpointConditions{
									Ready:       truePtr,
									Terminating: falsePtr,
								},
							},
							{
								Addresses: []string{svcIP3},
								Conditions: discovery.EndpointConditions{
									Ready:       truePtr,
									Terminating: falsePtr,
								},
							},
						},
						Ports: []discovery.EndpointPort{{
							Name:     &portName,
							Protocol: &portProto,
							Port:     &portPort,
						}},
					}

					_, err = k8sClient.DiscoveryV1().EndpointSlices("default").
						Create(context.Background(), fakeEps, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())

					var natK nat.FrontendKeyInterface
					if testOpts.ipv6 {
						natK = nat.NewNATKeyV6(net.ParseIP(clusterIP), 11666, 6)
					} else {
						natK = nat.NewNATKey(net.ParseIP(clusterIP), 11666, 6)
					}

					Eventually(func(g Gomega) {
						natmap, natbe := dumpNATMapsAny(family, tc.Felixes[0])
						g.Expect(natmap).To(HaveKey(natK))
						g.Expect(natmap[natK].Count()).To(Equal(uint32(3)))
						svc := natmap[natK]
						bckID := svc.ID()
						g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 0)))
						g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 1)))
						g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 2)))
						g.Expect(natbe).NotTo(HaveKey(nat.NewNATBackendKey(bckID, 3)))
					}, "5s").Should(Succeed(), "service or backedns didn't show up")

					fakeEps.Endpoints[1].Conditions.Ready = falsePtr
					fakeEps.Endpoints[1].Conditions.Terminating = truePtr

					_, err = k8sClient.DiscoveryV1().EndpointSlices("default").
						Update(context.Background(), fakeEps, metav1.UpdateOptions{})
					Expect(err).NotTo(HaveOccurred())

					Eventually(func(g Gomega) {
						natmap, natbe := dumpNATMapsAny(family, tc.Felixes[0])
						g.Expect(natmap).To(HaveKey(natK))
						g.Expect(natmap[natK].Count()).To(Equal(uint32(2)))
						svc := natmap[natK]
						bckID := svc.ID()
						g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 0)))
						g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 1)))
						g.Expect(natbe).NotTo(HaveKey(nat.NewNATBackendKey(bckID, 2)))
					}, "5s").Should(Succeed(), "NAT did not get updated properly")
				})

				It("should cleanup after we disable eBPF", func() {
					By("Waiting for dp to get setup up")

					ensureAllNodesBPFProgramsAttached(tc.Felixes)

					By("Changing env and restarting felix")

					tc.Felixes[0].SetEnv(map[string]string{"FELIX_BPFENABLED": "false"})
					tc.Felixes[0].Restart()

					By("Checking that all programs got cleaned up")

					Eventually(func() string {
						out, _ := tc.Felixes[0].ExecOutput("bpftool", "-jp", "prog", "show")
						return out
					}, "15s", "1s").ShouldNot(
						Or(ContainSubstring("cali_"), ContainSubstring("calico_"), ContainSubstring("xdp_cali_")))

					// N.B. calico_failsafe map is created in iptables mode by
					// bpf.NewFailsafeMap() It has calico_ prefix. All other bpf
					// maps have only cali_ prefix.
					Eventually(func() string {
						out, _ := tc.Felixes[0].ExecOutput("bpftool", "-jp", "map", "show")
						return out
					}, "15s", "1s").ShouldNot(Or(ContainSubstring("cali_"), ContainSubstring("xdp_cali_")))
				})
			}
		})

		const numNodes = 3
		var (
			w     [numNodes][2]*workload.Workload
			hostW [numNodes]*workload.Workload
		)

		setupCluster := func() {
			tc, calicoClient = infrastructure.StartNNodeTopology(numNodes, options, infra)

			addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
				if labels == nil {
					labels = make(map[string]string)
				}

				wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
				if testOpts.ipv6 {
					wIP = net.ParseIP(fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)).String()
				}
				wName := fmt.Sprintf("w%d%d", ii, wi)

				w := workload.New(tc.Felixes[ii], wName, "default",
					wIP, strconv.Itoa(port), testOpts.protocol)

				labels["name"] = w.Name
				labels["workload"] = "regular"

				w.WorkloadEndpoint.Labels = labels
				if run {
					err := w.Start()
					Expect(err).NotTo(HaveOccurred())
					w.ConfigureInInfra(infra)
				}
				if options.UseIPPools {
					// Assign the workload's IP in IPAM, this will trigger calculation of routes.
					err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
						IP:       cnet.MustParseIP(wIP),
						HandleID: &w.Name,
						Attrs: map[string]string{
							ipam.AttributeNode: tc.Felixes[ii].Hostname,
						},
						Hostname: tc.Felixes[ii].Hostname,
					})
					Expect(err).NotTo(HaveOccurred())
				}

				return w
			}

			// Start a host networked workload on each host for connectivity checks.
			for ii := range tc.Felixes {
				// We tell each host-networked workload to open:
				// TODO: Copied from another test
				// - its normal (uninteresting) port, 8055
				// - port 2379, which is both an inbound and an outbound failsafe port
				// - port 22, which is an inbound failsafe port.
				// This allows us to test the interaction between do-not-track policy and failsafe
				// ports.
				hostW[ii] = workload.Run(
					tc.Felixes[ii],
					fmt.Sprintf("host%d", ii),
					"default",
					felixIP(ii), // Same IP as felix means "run in the host's namespace"
					"8055",
					testOpts.protocol)

				hostW[ii].WorkloadEndpoint.Labels = map[string]string{"name": hostW[ii].Name}

				// Two workloads on each host so we can check the same host and other host cases.
				w[ii][0] = addWorkload(true, ii, 0, 8055, map[string]string{"port": "8055"})
				w[ii][1] = addWorkload(true, ii, 1, 8056, nil)
			}

			// Create a workload on node 0 that does not run, but we can use it to set up paths
			deadWorkload = addWorkload(false, 0, 2, 8057, nil)

			// We will use this container to model an external client trying to connect into
			// workloads on a host.  Create a route in the container for the workload CIDR.
			// TODO: Copied from another test
			externalClient = infrastructure.RunExtClient("ext-client")
			_ = externalClient

			err := infra.AddDefaultDeny()
			Expect(err).NotTo(HaveOccurred())
			if !options.TestManagesBPF {
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
				felixReady := func(f *infrastructure.Felix) int {
					return healthStatus(containerIP(f.Container), "9099", "readiness")
				}

				for _, f := range tc.Felixes {
					Eventually(felixReady(f), "5s", "100ms").Should(BeGood())
				}
			}
		}

		Describe(fmt.Sprintf("with a %d node cluster", numNodes), func() {
			BeforeEach(func() {
				setupCluster()
			})

			clusterIP := "10.101.0.10"
			extIP := "10.1.2.3"
			excludeSvcIP := "10.101.0.222"

			if testOpts.ipv6 {
				clusterIP = "dead:beef::abcd:0:0:10"
				extIP = "dead:beef::abcd:1:2:3"
				excludeSvcIP = "dead:beef::abcd:0:0:222"
			}

			if testOpts.protocol == "udp" && testOpts.udpUnConnected {
				It("should have no connectivity to a pod before it is added to the datamodel", func() {
					// Above BeforeEach adds a default-deny but for this test we want policy to be open
					// so that it's only the lack of datastore configuration that blocks traffic.
					policy := api.NewNetworkPolicy()
					policy.Name = "allow-all"
					policy.Namespace = "default"
					one := float64(1)
					policy.Spec.Order = &one
					policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
					policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
					policy.Spec.Selector = "all()"
					_, err := calicoClient.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)

					// The hardest path to secure with BPF is packets to the newly-added workload.  We can't block
					// the traffic with BPF until we have a BPF program in place so we rely on iptables catch-alls.

					// Set up a workload but do not add it to the datastore.
					wlIP := "10.65.1.5"
					if testOpts.ipv6 {
						wlIP = "dead:beef::1:5"
					}
					dpOnlyWorkload := workload.New(tc.Felixes[1], "w-dp", "default", wlIP, "8057", testOpts.protocol)
					err = dpOnlyWorkload.Start()
					Expect(err).NotTo(HaveOccurred())
					tc.Felixes[1].Exec("ip", "route", "add", dpOnlyWorkload.IP, "dev", dpOnlyWorkload.InterfaceName, "scope", "link")

					// Attach tcpdump to the workload so we can verify that we don't see any packets at all.  We need
					// to verify ingress and egress separately since a round-trip test would be blocked by either.
					tcpdump := dpOnlyWorkload.AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					pattern := fmt.Sprintf(`IP .* %s\.8057: UDP`, dpOnlyWorkload.IP)
					if testOpts.ipv6 {
						pattern = fmt.Sprintf(`IP6 .* %s\.8057: UDP`, dpOnlyWorkload.IP)
					}
					tcpdump.AddMatcher("UDP-8057", regexp.MustCompile(pattern))
					tcpdump.Start()
					defer tcpdump.Stop()

					// Send packets in the background.
					var wg sync.WaitGroup
					wg.Add(1)
					ctx, cancelFn := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancelFn()
					go func() {
						defer wg.Done()
						defer GinkgoRecover()
						for {
							if ctx.Err() != nil {
								return
							}
							_, err = w[1][0].RunCmd("pktgen", w[1][0].IP, dpOnlyWorkload.IP, "udp",
								"--port-src", "30444", "--port-dst", "8057")
							Expect(err).NotTo(HaveOccurred())
							time.Sleep(100 * (time.Millisecond))
						}
					}()
					defer wg.Wait()

					Consistently(tcpdump.MatchCountFn("UDP-8057"), "5s", "200ms").Should(
						BeNumerically("==", 0),
						"Traffic to the workload should be blocked before datastore is configured")

					dpOnlyWorkload.ConfigureInInfra(infra)

					Eventually(tcpdump.MatchCountFn("UDP-8057"), "5s", "200ms").Should(
						BeNumerically(">", 0),
						"Traffic to the workload should be allowed after datastore is configured")
				})
			}

			It("should have correct routes", func() {
				if testOpts.ipv6 {
					// XXX
					return
				}
				tunnelAddr := ""
				tunnelAddrFelix1 := ""
				tunnelAddrFelix2 := ""
				expectedRoutes := expectedRouteDump
				if testOpts.dsr {
					expectedRoutes = expectedRouteDumpDSR
				}
				switch {
				case tc.Felixes[0].ExpectedIPIPTunnelAddr != "":
					tunnelAddr = tc.Felixes[0].ExpectedIPIPTunnelAddr
					tunnelAddrFelix1 = tc.Felixes[1].ExpectedIPIPTunnelAddr
					tunnelAddrFelix2 = tc.Felixes[2].ExpectedIPIPTunnelAddr
				case tc.Felixes[0].ExpectedVXLANTunnelAddr != "":
					tunnelAddr = tc.Felixes[0].ExpectedVXLANTunnelAddr
					tunnelAddrFelix1 = tc.Felixes[1].ExpectedVXLANTunnelAddr
					tunnelAddrFelix2 = tc.Felixes[2].ExpectedVXLANTunnelAddr
				case tc.Felixes[0].ExpectedWireguardTunnelAddr != "":
					tunnelAddr = tc.Felixes[0].ExpectedWireguardTunnelAddr
					tunnelAddrFelix1 = tc.Felixes[1].ExpectedWireguardTunnelAddr
					tunnelAddrFelix2 = tc.Felixes[2].ExpectedWireguardTunnelAddr
				}

				if tunnelAddr != "" {
					expectedRoutes = expectedRouteDumpWithTunnelAddr
					if testOpts.dsr {
						expectedRoutes = expectedRouteDumpWithTunnelAddrDSR
					}
				}

				dumpRoutes := func() string {
					out, err := tc.Felixes[0].ExecOutput("calico-bpf", "routes", "dump")
					if err != nil {
						return fmt.Sprint(err)
					}

					lines := strings.Split(out, "\n")
					var filteredLines []string
					idxRE := regexp.MustCompile(`idx \d+`)
					for _, l := range lines {
						l = strings.TrimLeft(l, " ")
						if len(l) == 0 {
							continue
						}
						l = strings.ReplaceAll(l, felixIP(0), "FELIX_0")
						l = strings.ReplaceAll(l, felixIP(1), "FELIX_1")
						l = strings.ReplaceAll(l, felixIP(2), "FELIX_2")
						l = idxRE.ReplaceAllLiteralString(l, "idx -")
						if tunnelAddr != "" {
							l = strings.ReplaceAll(l, tunnelAddr+"/32", "FELIX_0_TNL/32")
						}
						if tunnelAddrFelix1 != "" {
							l = strings.ReplaceAll(l, tunnelAddrFelix1+"/32", "FELIX_1_TNL/32")
						}
						if tunnelAddrFelix2 != "" {
							l = strings.ReplaceAll(l, tunnelAddrFelix2+"/32", "FELIX_2_TNL/32")
						}
						filteredLines = append(filteredLines, l)
					}
					sort.Strings(filteredLines)
					return strings.Join(filteredLines, "\n")
				}
				Eventually(dumpRoutes, "10s", "200ms").Should(Equal(expectedRoutes), dumpRoutes)
			})

			It("should only allow traffic from the local host by default", func() {
				// Same host, other workload.
				cc.ExpectNone(w[0][0], w[0][1])
				cc.ExpectNone(w[0][1], w[0][0])
				// Workloads on other host.
				cc.ExpectNone(w[0][0], w[1][0])
				cc.ExpectNone(w[1][0], w[0][0])
				// Hosts.
				cc.ExpectSome(tc.Felixes[0], w[0][0])
				cc.ExpectNone(tc.Felixes[1], w[0][0])
				cc.CheckConnectivity()
			})

			It("should allow host -> host", func() {
				// XXX as long as there is no HEP policy
				// using hostW as a sink
				cc.Expect(Some, tc.Felixes[0], hostW[0])
				cc.Expect(Some, tc.Felixes[0], hostW[1])
				cc.Expect(Some, tc.Felixes[1], hostW[0])
				cc.CheckConnectivity()
			})

			Context("with a policy allowing ingress to w[0][0] from all regular workloads", func() {
				var (
					pol       *api.GlobalNetworkPolicy
					k8sClient *kubernetes.Clientset
				)

				BeforeEach(func() {
					pol = api.NewGlobalNetworkPolicy()
					pol.Namespace = "fv"
					pol.Name = "policy-1"
					pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "workload=='regular'",
							},
						},
					}
					pol.Spec.Egress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "workload=='regular'",
							},
						},
					}
					pol.Spec.Selector = "workload=='regular'"

					pol = createPolicy(pol)

					k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
					_ = k8sClient
				})

				Context("with both applyOnForward=true/false", func() {
					BeforeEach(func() {
						// The next two policies are to make sure that applyOnForward of a
						// global policy is applied correctly to a host endpoint. The deny
						// policy is not applied to forwarded traffic!

						By("global policy denies traffic to host 1 on host 0", func() {

							nets := []string{felixIP(1) + "/" + ipMask()}
							switch testOpts.tunnel {
							case "ipip":
								nets = append(nets, tc.Felixes[1].ExpectedIPIPTunnelAddr+"/32")
							}

							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "host-0-1"
							pol.Spec.Egress = []api.Rule{
								{
									Action: "Deny",
									Destination: api.EntityRule{
										Nets: nets,
									},
								},
							}
							pol.Spec.Selector = "node=='" + tc.Felixes[0].Name + "'"
							pol.Spec.ApplyOnForward = false

							pol = createPolicy(pol)
						})

						By("global policy allows forwarded traffic to host 1 on host 0", func() {

							nets := []string{felixIP(1) + "/" + ipMask()}
							switch testOpts.tunnel {
							case "ipip":
								nets = append(nets, tc.Felixes[1].ExpectedIPIPTunnelAddr+"/32")
							}

							pol := api.NewGlobalNetworkPolicy()
							pol.Namespace = "fv"
							pol.Name = "host-0-1-forward"
							pol.Spec.Egress = []api.Rule{
								{
									Action: "Allow",
									Destination: api.EntityRule{
										Nets: nets,
									},
								},
							}
							pol.Spec.Selector = "node=='" + tc.Felixes[0].Name + "'"
							pol.Spec.ApplyOnForward = true

							pol = createPolicy(pol)
						})

						bpfWaitForPolicy(tc.Felixes[0], "eth0", "egress", "default.host-0-1")

					})
					It("should handle NAT outgoing", func() {
						By("SNATting outgoing traffic with the flag set")
						cc.ExpectSNAT(w[0][0], felixIP(0), hostW[1])
						cc.Expect(Some, w[0][0], hostW[0]) // no snat
						cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)

						if testOpts.tunnel == "none" {
							By("Leaving traffic alone with the flag clear")
							poolName := infrastructure.DefaultIPPoolName
							if testOpts.ipv6 {
								poolName = infrastructure.DefaultIPv6PoolName
							}
							pool, err := calicoClient.IPPools().Get(context.TODO(), poolName, options2.GetOptions{})
							Expect(err).NotTo(HaveOccurred())
							pool.Spec.NATOutgoing = false
							pool, err = calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
							Expect(err).NotTo(HaveOccurred())

							// Wait for the pool change to take effect
							Eventually(func() string {
								return bpfDumpRoutes(tc.Felixes[0])
							}, "5s", "1s").ShouldNot(ContainSubstring("workload in-pool nat-out"))

							cc.ResetExpectations()
							cc.ExpectSNAT(w[0][0], w[0][0].IP, hostW[1])
							cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)

							By("SNATting again with the flag set")
							pool.Spec.NATOutgoing = true
							pool, err = calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
							Expect(err).NotTo(HaveOccurred())

							// Wait for the pool change to take effect
							Eventually(func() string {
								return bpfDumpRoutes(tc.Felixes[0])
							}, "5s", "1s").Should(ContainSubstring("workload in-pool nat-out"))

							cc.ResetExpectations()
							cc.ExpectSNAT(w[0][0], felixIP(0), hostW[1])
							cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
						}
					})
				})

				It("connectivity from all workloads via workload 0's main IP", func() {
					cc.ExpectSome(w[0][1], w[0][0])
					cc.ExpectSome(w[1][0], w[0][0])
					cc.ExpectSome(w[1][1], w[0][0])
					cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
				})

				if (testOpts.protocol == "tcp" || (testOpts.protocol == "udp" && !testOpts.udpUnConnected)) &&
					testOpts.connTimeEnabled && !testOpts.dsr {

					It("should fail connect if there is no backed or a service", func() {
						var (
							natK   nat.FrontendKeyInterface
							family int
						)

						By("setting up a service without backends")

						clusterIP1 := "10.101.0.111"
						if testOpts.ipv6 {
							clusterIP1 = "dead:beef::abcd:0:0:111"
						}
						testSvc := k8sService("svc-no-backends", clusterIP1, w[0][0], 80, 1234, 0, testOpts.protocol)
						testSvcNamespace := testSvc.ObjectMeta.Namespace
						testSvc.Spec.Selector = map[string]string{"somelabel": "somevalue"}
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(),
							testSvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())

						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)
						if testOpts.ipv6 {
							natK = nat.NewNATKeyV6(net.ParseIP(ip), port, numericProto)
							family = 6
						} else {
							natK = nat.NewNATKey(net.ParseIP(ip), port, numericProto)
							family = 4
						}

						Eventually(func() bool {
							natmaps, _ := dumpNATMapsAny(family, tc.Felixes[0])
							if _, ok := natmaps[natK]; !ok {
								return false
							}
							return true
						}, "5s").Should(BeTrue(), "service NAT key didn't show up")

						By("starting tcpdump")
						tcpdump := w[0][0].AttachTCPDump()
						tcpdump.SetLogEnabled(true)

						var pattern string
						if testOpts.ipv6 {
							pattern = fmt.Sprintf(`IP6 %s.\d+ > %s\.80`, w[0][0].IP, testSvc.Spec.ClusterIP)
						} else {
							pattern = fmt.Sprintf(`IP %s.\d+ > %s\.80`, w[0][0].IP, testSvc.Spec.ClusterIP)
						}
						tcpdump.AddMatcher("no-backend", regexp.MustCompile(pattern))
						tcpdump.Start()
						defer tcpdump.Stop()

						By("testing connectivity")

						cc.Expect(None, w[0][0], TargetIP(testSvc.Spec.ClusterIP), ExpectWithPorts(80))
						cc.CheckConnectivity()

						// If connect never succeeded, no packets were sent and
						// therefore we must see none.
						Expect(tcpdump.MatchCount("no-backend")).To(Equal(0))
					})
				}

				// Test doesn't use services so ignore the runs with those turned on.
				if testOpts.protocol == "tcp" && !testOpts.connTimeEnabled && !testOpts.dsr {
					It("should not be able to spoof TCP", func() {
						if testOpts.ipv6 {
							// XXX the routing needs to be different and may not
							// apply to ipv6
							return
						}

						if !testOpts.ipv6 {
							By("Disabling dev RPF")
							setRPF(tc.Felixes, testOpts.tunnel, 0, 0)
						}
						// Make sure the workload is up and has configured its routes.
						By("Having basic connectivity")
						cc.Expect(Some, w[0][0], w[1][0])
						cc.CheckConnectivity()

						// Add a second interface to the workload, this will allow us to adjust the routes
						// inside the workload to move connections from one interface to the other.
						By("Having basic connectivity after setting up the spoof interface")
						w[0][0].AddSpoofInterface()
						// Check that the route manipulation succeeded.
						cc.CheckConnectivity()
						cc.ResetExpectations()

						// PHASE 1: basic single-shot connectivity checks to check that the test infra
						// is basically doing what we want.  I.e. if felix and the workload disagree on
						// interface then new connections get dropped.

						// Switch routes to use the spoofed interface, should fail.
						By("Workload using spoof0, felix expecting eth0, should fail")
						w[0][0].UseSpoofInterface(true)
						cc.Expect(None, w[0][0], w[1][0])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						By("Workload using spoof0, felix expecting spoof0, should succeed")
						w[0][0].RemoveFromInfra(infra)
						w[0][0].ConfigureInInfraAsSpoofInterface(infra)
						cc.Expect(Some, w[0][0], w[1][0])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						By("Both back to eth0, should succeed")
						w[0][0].RemoveSpoofWEPFromInfra(infra)
						w[0][0].ConfigureInInfra(infra)
						w[0][0].UseSpoofInterface(false)
						cc.Expect(Some, w[0][0], w[1][0])
						cc.CheckConnectivity()
						cc.ResetExpectations()

						// PHASE 2: keep a connection up and move it from one interface to the other using the pod's
						// routes.  To the host this looks like one workload is spoofing the other.
						By("Starting permanent connection")
						pc := w[0][0].StartPersistentConnection(w[1][0].IP, 8055, workload.PersistentConnectionOpts{
							MonitorConnectivity: true,
						})
						defer pc.Stop()

						expectPongs := func() {
							EventuallyWithOffset(1, pc.SinceLastPong, "5s").Should(
								BeNumerically("<", time.Second),
								"Expected to see pong responses on the connection but didn't receive any")
							log.Info("Pongs received within last 1s")
						}
						expectNoPongs := func() {
							EventuallyWithOffset(1, pc.SinceLastPong, "5s").Should(
								BeNumerically(">", time.Second),
								"Expected to see pong responses stop but continued to receive them")
							log.Info("No pongs received for >1s")
						}

						// Simulate a second WEP for the spoof interface.
						w[0][0].ConfigureOtherWEPInInfraAsSpoofInterface(infra)

						// Should get some pongs to start with...
						By("Should get pongs to start with")
						expectPongs()

						// Switch the route, should start dropping packets.
						w[0][0].UseSpoofInterface(true)
						By("Should no longer get pongs when using the spoof interface")
						expectNoPongs()

						// Switch the route back, should work.
						w[0][0].UseSpoofInterface(false)
						By("Should get pongs again after switching back")
						expectPongs()

						// Switch the route, should start dropping packets.
						w[0][0].UseSpoofInterface(true)
						By("Should no longer get pongs when using the spoof interface")
						expectNoPongs()

						// Move WEP to spoof interface
						w[0][0].RemoveFromInfra(infra)
						w[0][0].RemoveSpoofWEPFromInfra(infra)
						w[0][0].ConfigureInInfraAsSpoofInterface(infra)
						By("Should get pongs again after switching WEP to spoof iface")
						expectPongs()
					})
				}

				Describe("Test Load balancer service with external IP", func() {
					if testOpts.connTimeEnabled {
						// FIXME externalClient also does conntime balancing
						return
					}

					srcIPRange := []string{}
					externalIP := []string{extIP}
					testSvcName := "test-lb-service-extip"
					tgtPort := 8055
					var testSvc *v1.Service
					var ip []string
					var port uint16
					BeforeEach(func() {
						externalClient.Exec("ip", "route", "add", extIP, "via", felixIP(0))
						testSvc = k8sCreateLBServiceWithEndPoints(k8sClient, testSvcName, clusterIP, w[0][0], 80, tgtPort,
							testOpts.protocol, externalIP, srcIPRange)
						// when we point Load Balancer to a node in GCE it adds local routes to the external IP on the hosts.
						// Similarity add local routes for externalIP on testContainers.Felix[0], testContainers.Felix[1]
						tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
						tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
						ip = testSvc.Spec.ExternalIPs
						port = uint16(testSvc.Spec.Ports[0].Port)
						pol.Spec.Ingress = []api.Rule{
							{
								Action: "Allow",
								Source: api.EntityRule{
									Nets: []string{
										containerIP(externalClient) + "/" + ipMask(),
										w[0][1].IP + "/" + ipMask(),
										w[1][0].IP + "/" + ipMask(),
										w[1][1].IP + "/" + ipMask(),
									},
								},
							},
						}
						pol = updatePolicy(pol)
					})

					It("should have connectivity from workloads[1][0],[1][1], [0][1] and external client via external IP to workload 0", func() {
						cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
						cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)
						cc.ExpectSome(w[0][1], TargetIP(ip[0]), port)
						cc.ExpectSome(externalClient, TargetIP(ip[0]), port)
						cc.CheckConnectivity()
					})

					It("should handle temporary overlap of external IPs", func() {
						By("Having connectivity to external IP initially")
						cc.ExpectSome(externalClient, TargetIP(ip[0]), port)
						cc.CheckConnectivity()

						By("Adding second service with same external IP")
						clusterIP2 := "10.101.0.11"

						if testOpts.ipv6 {
							clusterIP2 = "dead:beef::abcd:0:0:11"
						}
						testSvc = k8sCreateLBServiceWithEndPoints(k8sClient, testSvcName+"-2", clusterIP2, w[0][0], 80, tgtPort,
							testOpts.protocol, externalIP, srcIPRange)

						By("Deleting first service")
						err := k8sClient.CoreV1().Services(testSvc.ObjectMeta.Namespace).Delete(context.Background(), testSvcName, metav1.DeleteOptions{})
						Expect(err).NotTo(HaveOccurred())

						By("Sleeping")
						time.Sleep(20 * time.Second)
						By("And still having connectivity...")
						cc.ExpectSome(externalClient, TargetIP(ip[0]), port)
						cc.CheckConnectivity()
					})
				})

				Context("Test load balancer service with src ranges", func() {
					var testSvc *v1.Service
					tgtPort := 8055
					externalIP := []string{extIP}
					srcIPRange := []string{"10.65.1.3/24"}
					if testOpts.ipv6 {
						srcIPRange = []string{"dead:beef::1:3/120"}
					}
					testSvcName := "test-lb-service-extip"
					var ip []string
					var port uint16
					BeforeEach(func() {
						testSvc = k8sCreateLBServiceWithEndPoints(k8sClient, testSvcName, clusterIP, w[0][0], 80, tgtPort,
							testOpts.protocol, externalIP, srcIPRange)
						tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
						tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
						ip = testSvc.Spec.ExternalIPs
						port = uint16(testSvc.Spec.Ports[0].Port)
					})
					It("should have connectivity from workloads[1][0],[1][1] via external IP to workload 0", func() {
						cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
						cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)
						cc.ExpectNone(w[0][1], TargetIP(ip[0]), port)
						cc.CheckConnectivity()
					})
				})

				Context("Test load balancer service with no backend", func() {
					if testOpts.connTimeEnabled || testOpts.udpUnConnected {
						// Skip UDP unconnected, connecttime load balancing cases as externalClient also does conntime balancing
						return
					}

					var testSvc *v1.Service
					tgtPort := 8055
					externalIP := []string{extIP}
					srcIPRange := []string{}
					testSvcName := "test-lb-service-extip"
					var port uint16
					var ip []string

					BeforeEach(func() {
						externalClient.Exec("ip", "route", "add", extIP, "via", felixIP(0))
						// create a service workload as nil, so that the service has no backend
						testSvc = k8sCreateLBServiceWithEndPoints(k8sClient, testSvcName, clusterIP, nil, 80, tgtPort,
							testOpts.protocol, externalIP, srcIPRange)
						tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
						tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
						ip = testSvc.Spec.ExternalIPs
						port = uint16(testSvc.Spec.Ports[0].Port)
						pol.Spec.Ingress = []api.Rule{
							{
								Action: "Allow",
								Source: api.EntityRule{
									Nets: []string{
										externalClient.IP + "/32",
									},
								},
							},
						}
						pol = updatePolicy(pol)
					})
					It("should not have connectivity from external client, and return connection refused", func() {
						icmpProto := "icmp"
						if testOpts.ipv6 {
							icmpProto = "icmp6"
						}

						tcpdump := externalClient.AttachTCPDump("any")
						tcpdump.SetLogEnabled(true)
						if testOpts.ipv6 {
							tcpdump.AddMatcher("unreach", regexp.MustCompile("destination unreachable"))
							tcpdump.AddMatcher("bad csum", regexp.MustCompile("bad icmp6 cksum"))
						} else {
							tcpdump.AddMatcher("unreach", regexp.MustCompile("port \\d+ unreachable"))
							tcpdump.AddMatcher("bad csum", regexp.MustCompile("wrong icmp cksum"))
						}

						tcpdump.Start("-vv", testOpts.protocol, "port", strconv.Itoa(int(port)), "or", icmpProto)
						defer tcpdump.Stop()

						cc.Expect(None, externalClient, TargetIP(ip[0]),
							ExpectWithPorts(port),
							ExpectNoneWithError("connection refused"),
						)
						cc.CheckConnectivity()

						Eventually(func() int { return tcpdump.MatchCount("unreach") }).
							Should(BeNumerically(">", 0))
						// XXX
						// Expect(tcpdump.MatchCount("bad csum")).To(Equal(0))
					})
				})

				Describe("Test load balancer service with external Client,src ranges", func() {
					if testOpts.connTimeEnabled {
						// FIXME externalClient also does conntime balancing
						return
					}

					var testSvc *v1.Service
					tgtPort := 8055
					externalIP := []string{extIP}
					testSvcName := "test-lb-service-extip"
					var ip []string
					var port uint16
					var srcIPRange []string
					BeforeEach(func() {
						ipRoute := []string{"ip"}
						srcIPRange = []string{"10.65.1.3/24"}
						if testOpts.ipv6 {
							ipRoute = append(ipRoute, "-6")
							srcIPRange = []string{"dead:beef::1:3/120"}
						}

						cmd := append(ipRoute[:len(ipRoute):len(ipRoute)],
							"route", "add", extIP, "via", felixIP(0))
						externalClient.Exec(cmd...)
						pol.Spec.Ingress = []api.Rule{
							{
								Action: "Allow",
								Source: api.EntityRule{
									Nets: []string{
										containerIP(externalClient) + "/" + ipMask(),
									},
								},
							},
						}
						pol = updatePolicy(pol)
						cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
							"route", "add", "local", extIP, "dev", "eth0")
						tc.Felixes[1].Exec(cmd...)
						tc.Felixes[0].Exec(cmd...)
					})
					Context("Test LB-service with external Client's IP not in src range", func() {
						BeforeEach(func() {
							testSvc = k8sCreateLBServiceWithEndPoints(k8sClient, testSvcName, clusterIP, w[0][0], 80, tgtPort,
								testOpts.protocol, externalIP, srcIPRange)
							ip = testSvc.Spec.ExternalIPs
							port = uint16(testSvc.Spec.Ports[0].Port)
						})
						It("should not have connectivity from external Client via external IP to workload 0", func() {
							cc.ExpectNone(externalClient, TargetIP(ip[0]), port)
							cc.CheckConnectivity()
						})
					})
					Context("Test LB-service with external Client's IP in src range", func() {
						BeforeEach(func() {
							srcIPRange = []string{externalClient.IP + "/32"}
							testSvc = k8sCreateLBServiceWithEndPoints(k8sClient, testSvcName, clusterIP, w[0][0], 80, tgtPort,
								testOpts.protocol, externalIP, srcIPRange)
							ip = testSvc.Spec.ExternalIPs
							port = uint16(testSvc.Spec.Ports[0].Port)
						})
						It("should have connectivity from external Client via external IP to workload 0", func() {
							cc.ExpectSome(externalClient, TargetIP(ip[0]), port)
							cc.CheckConnectivity()
						})
					})
				})

				Context("Test Service type transitions", func() {
					if testOpts.protocol != "tcp" {
						// Skip tests for UDP, UDP-Unconnected
						return
					}

					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)
					testSvcName := "test-service"
					tgtPort := 8055
					externalIP := []string{extIP}

					// Create a service of type clusterIP
					BeforeEach(func() {
						testSvc = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol)
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
						tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
						tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
					})

					It("should have connectivity from all workloads via a service to workload 0", func() {
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						w00Expects := []ExpectationOption{ExpectWithPorts(port)}
						hostW0SrcIP := ExpectWithSrcIPs(felixIP(0))
						if testOpts.ipv6 {
							hostW0SrcIP = ExpectWithSrcIPs(felixIP(0))
							switch testOpts.tunnel {
							case "vxlan":
								hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
							case "wireguard":
								hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
							}
						}
						switch testOpts.tunnel {
						case "ipip":
							hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
						}

						if !testOpts.connTimeEnabled {
							w00Expects = append(w00Expects, hostW0SrcIP)
						}

						cc.Expect(Some, w[0][0], TargetIP(ip), w00Expects...)
						cc.ExpectSome(w[0][1], TargetIP(ip), port)
						cc.ExpectSome(w[1][0], TargetIP(ip), port)
						cc.ExpectSome(w[1][1], TargetIP(ip), port)
						cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
					})

					/* Below Context handles the following transitions.
					   Cluster IP -> External IP
					   External IP -> LoadBalancer
					   External IP -> NodePort
					   External IP -> Cluster IP
					*/
					Context("change service from cluster IP to external IP", func() {
						var testSvcWithExtIP *v1.Service
						BeforeEach(func() {
							testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol, externalIP)
							k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
						})

						It("should have connectivity from all workloads via external IP to workload 0", func() {
							ip := testSvcWithExtIP.Spec.ExternalIPs
							port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
							cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
							cc.ExpectSome(w[0][1], TargetIP(ip[0]), port)
							cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)
							cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
						})
						Context("change service type from external IP to LoadBalancer", func() {
							srcIPRange := []string{}
							var testSvcLB *v1.Service
							BeforeEach(func() {
								testSvcLB = k8sLBService(testSvcName, clusterIP, w[0][0].Name, 80, tgtPort, testOpts.protocol,
									externalIP, srcIPRange)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
							})
							It("should have connectivity from workload 0 to service via external IP", func() {
								ip := testSvcLB.Spec.ExternalIPs
								port := uint16(testSvcLB.Spec.Ports[0].Port)
								cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)
								cc.ExpectSome(w[0][1], TargetIP(ip[0]), port)
								cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
							})
						})

						Context("change Service type from external IP to nodeport", func() {
							var testSvcNodePort *v1.Service
							npPort := uint16(30333)
							BeforeEach(func() {
								testSvcNodePort = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, int32(npPort), testOpts.protocol)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
							})
							It("should have connectivity via the node port to workload 0", func() {
								node1IP := felixIP(1)
								cc.ExpectSome(w[0][1], TargetIP(node1IP), npPort)
								cc.ExpectSome(w[1][0], TargetIP(node1IP), npPort)
								cc.ExpectSome(w[1][1], TargetIP(node1IP), npPort)

								ip := testSvcWithExtIP.Spec.ExternalIPs
								port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
								cc.ExpectNone(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectNone(w[0][1], TargetIP(ip[0]), port)
								cc.ExpectNone(w[1][1], TargetIP(ip[0]), port)
								cc.CheckConnectivity()
							})
						})
						Context("change service from external IP to cluster IP", func() {
							var testSvcWithoutExtIP *v1.Service
							BeforeEach(func() {
								testSvcWithoutExtIP = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithoutExtIP)
							})
							It("should not have connectivity to workload 0 via external IP", func() {
								ip := testSvcWithExtIP.Spec.ExternalIPs
								port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
								cc.ExpectNone(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectNone(w[1][1], TargetIP(ip[0]), port)
								cc.ExpectNone(w[0][1], TargetIP(ip[0]), port)

								clusterIP = testSvcWithoutExtIP.Spec.ClusterIP
								cc.ExpectSome(w[0][1], TargetIP(clusterIP), port)
								cc.ExpectSome(w[1][0], TargetIP(clusterIP), port)
								cc.ExpectSome(w[1][1], TargetIP(clusterIP), port)
								cc.CheckConnectivity()
							})
						})
					})

					/* Below Context handles the following transitions.
					   Cluster IP -> LoadBalancer
					   LoadBalancer -> External IP
					   LoadBalancer -> NodePort
					   LoadBalancer -> Cluster IP
					*/
					Context("change service type to LoadBalancer", func() {
						srcIPRange := []string{}
						var testSvcLB *v1.Service
						BeforeEach(func() {
							testSvcLB = k8sLBService(testSvcName, clusterIP, w[0][0].Name, 80, tgtPort, testOpts.protocol,
								externalIP, srcIPRange)
							k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
						})
						It("should have connectivity from workload 0 to service via external IP", func() {
							ip := testSvcLB.Spec.ExternalIPs
							port := uint16(testSvcLB.Spec.Ports[0].Port)
							cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
							cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)
							cc.ExpectSome(w[0][1], TargetIP(ip[0]), port)
							cc.CheckConnectivity()
						})

						Context("change service from Loadbalancer to external IP", func() {
							var testSvcWithExtIP *v1.Service
							BeforeEach(func() {
								testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol, externalIP)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
							})

							It("should have connectivity from all workloads via external IP to workload 0", func() {
								ip := testSvcWithExtIP.Spec.ExternalIPs
								port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
								cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectSome(w[0][1], TargetIP(ip[0]), port)
								cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)
								cc.CheckConnectivity()
							})
						})

						Context("change Service type from Loadbalancer to nodeport", func() {
							var testSvcNodePort *v1.Service
							npPort := uint16(30333)
							BeforeEach(func() {
								testSvcNodePort = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, int32(npPort), testOpts.protocol)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
							})
							It("should have connectivity via the node port to workload 0 and not via external IP", func() {
								ip := testSvcLB.Spec.ExternalIPs
								port := uint16(testSvcLB.Spec.Ports[0].Port)
								cc.ExpectNone(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectNone(w[1][1], TargetIP(ip[0]), port)
								cc.ExpectNone(w[0][1], TargetIP(ip[0]), port)
								node1IP := felixIP(1)
								cc.ExpectSome(w[0][1], TargetIP(node1IP), npPort)
								cc.ExpectSome(w[1][0], TargetIP(node1IP), npPort)
								cc.ExpectSome(w[1][1], TargetIP(node1IP), npPort)
								cc.CheckConnectivity()
							})
						})
						Context("Change service type from LoadBalancer to cluster IP", func() {
							var testSvcClusterIP *v1.Service
							BeforeEach(func() {
								testSvcClusterIP = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcClusterIP)
							})
							It("should have connectivity to workload 0 via cluster IP and not external IP", func() {
								ip := testSvcLB.Spec.ExternalIPs
								port := uint16(testSvcLB.Spec.Ports[0].Port)
								cc.ExpectNone(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectNone(w[1][1], TargetIP(ip[0]), port)
								cc.ExpectNone(w[0][1], TargetIP(ip[0]), port)

								clusterIP = testSvcClusterIP.Spec.ClusterIP

								cc.ExpectSome(w[0][1], TargetIP(clusterIP), port)
								cc.ExpectSome(w[1][0], TargetIP(clusterIP), port)
								cc.ExpectSome(w[1][1], TargetIP(clusterIP), port)
								cc.CheckConnectivity()
							})

						})
					})

					/* Below Context handles the following transitions.
					   Cluster IP -> NodePort
					   NodePort -> External IP
					   NodePort -> LoadBalancer
					   NodePort -> Cluster IP
					*/
					Context("change Service type to nodeport", func() {
						var testSvcNodePort *v1.Service
						npPort := uint16(30333)
						BeforeEach(func() {
							testSvcNodePort = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, int32(npPort), testOpts.protocol)
							k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
						})
						It("should have connectivity via the node port to workload 0", func() {
							node1IP := felixIP(1)
							node1IPExt := tc.Felixes[1].ExternalIP
							cc.ExpectSome(w[0][1], TargetIP(node1IP), npPort)
							cc.ExpectSome(w[1][0], TargetIP(node1IP), npPort)
							cc.ExpectSome(w[1][1], TargetIP(node1IP), npPort)
							cc.ExpectSome(w[0][1], TargetIP(node1IPExt), npPort)
							cc.ExpectSome(w[1][0], TargetIP(node1IPExt), npPort)
							cc.ExpectSome(w[1][1], TargetIP(node1IPExt), npPort)
							cc.CheckConnectivity()
						})

						Context("change service type from nodeport to external IP", func() {
							var testSvcWithExtIP *v1.Service
							BeforeEach(func() {
								testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol, externalIP)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
							})
							It("should have connectivity via external IP to workload 0 and not node port", func() {
								ip := testSvcWithExtIP.Spec.ExternalIPs
								port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
								cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectSome(w[0][1], TargetIP(ip[0]), port)
								cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)

								node1IP := felixIP(1)
								cc.ExpectNone(w[0][1], TargetIP(node1IP), npPort)
								cc.ExpectNone(w[1][0], TargetIP(node1IP), npPort)
								cc.ExpectNone(w[1][1], TargetIP(node1IP), npPort)
								cc.CheckConnectivity()
							})
						})
						Context("change service type from nodeport to LoadBalancer", func() {
							srcIPRange := []string{}
							var testSvcLB *v1.Service
							BeforeEach(func() {
								testSvcLB = k8sLBService(testSvcName, clusterIP, w[0][0].Name, 80, tgtPort, testOpts.protocol,
									externalIP, srcIPRange)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
							})
							It("should have connectivity from workload 0 to service via external IP and via nodeport", func() {
								node1IP := felixIP(1)

								// Note: the behaviour expected here changed around k8s v1.20.  Previously, the API
								// server would allocate a new node port when we applied the load balancer update.
								// Now, it merges the two so the service keeps its existing NodePort.
								cc.ExpectSome(w[0][1], TargetIP(node1IP), npPort)
								cc.ExpectSome(w[1][0], TargetIP(node1IP), npPort)
								cc.ExpectSome(w[1][1], TargetIP(node1IP), npPort)

								// Either way, we expect the load balancer to show up.
								ip := testSvcLB.Spec.ExternalIPs
								port := uint16(testSvcLB.Spec.Ports[0].Port)
								cc.ExpectSome(w[1][0], TargetIP(ip[0]), port)
								cc.ExpectSome(w[1][1], TargetIP(ip[0]), port)
								cc.ExpectSome(w[0][1], TargetIP(ip[0]), port)
								cc.CheckConnectivity()
							})
						})
						Context("Change service type from nodeport to cluster IP", func() {
							var testSvcClusterIP *v1.Service
							BeforeEach(func() {
								testSvcClusterIP = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol)
								k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcClusterIP)
							})
							It("should have connectivity to workload 0 via cluster IP and not via nodeport", func() {
								node1IP := felixIP(1)
								cc.ExpectNone(w[0][1], TargetIP(node1IP), npPort)
								cc.ExpectNone(w[1][0], TargetIP(node1IP), npPort)
								cc.ExpectNone(w[1][1], TargetIP(node1IP), npPort)

								clusterIP = testSvcClusterIP.Spec.ClusterIP
								port := uint16(testSvcClusterIP.Spec.Ports[0].Port)
								cc.ExpectSome(w[0][1], TargetIP(clusterIP), port)
								cc.ExpectSome(w[1][0], TargetIP(clusterIP), port)
								cc.ExpectSome(w[1][1], TargetIP(clusterIP), port)
								cc.CheckConnectivity()
							})

						})

					})
				})

				Context("with test-service configured "+clusterIP+":80 -> w[0][0].IP:8055", func() {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)

					testSvcName := "test-service"
					tgtPort := 8055

					BeforeEach(func() {
						testSvc = k8sService(testSvcName, clusterIP, w[0][0], 80, tgtPort, 0, testOpts.protocol)
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					It("should have connectivity from all workloads via a service to workload 0", func() {
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						w00Expects := []ExpectationOption{ExpectWithPorts(port)}
						hostW0SrcIP := ExpectWithSrcIPs(felixIP(0))
						if testOpts.ipv6 {
							hostW0SrcIP = ExpectWithSrcIPs(felixIP(0))
							switch testOpts.tunnel {
							case "vxlan":
								hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
							case "wireguard":
								hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
							}
						}
						switch testOpts.tunnel {
						case "ipip":
							hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
						}

						if !testOpts.connTimeEnabled {
							w00Expects = append(w00Expects, hostW0SrcIP)
						}

						cc.Expect(Some, w[0][0], TargetIP(ip), w00Expects...)
						cc.Expect(Some, w[0][1], TargetIP(ip), ExpectWithPorts(port))
						cc.Expect(Some, w[1][0], TargetIP(ip), ExpectWithPorts(port))
						cc.Expect(Some, w[1][1], TargetIP(ip), ExpectWithPorts(port))
						cc.CheckConnectivity()
					})

					It("should only have connectivity from the local host via a service to workload 0", func() {
						// Local host is always allowed (for kubelet health checks).
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(tc.Felixes[0], TargetIP(ip), port)
						cc.ExpectNone(tc.Felixes[1], TargetIP(ip), port)
						cc.CheckConnectivity()
					})

					Describe("after updating the policy to allow traffic from hosts", func() {
						BeforeEach(func() {
							pol.Spec.Ingress = []api.Rule{
								{
									Action: "Allow",
									Source: api.EntityRule{
										Selector: "ep-type == 'host'",
									},
								},
							}
							pol = updatePolicy(pol)
						})

						It("should have connectivity from the hosts via a service to workload 0", func() {
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectSome(tc.Felixes[0], TargetIP(ip), port)
							cc.ExpectSome(tc.Felixes[1], TargetIP(ip), port)
							cc.ExpectNone(w[0][1], TargetIP(ip), port)
							cc.ExpectNone(w[1][0], TargetIP(ip), port)
							cc.CheckConnectivity()
						})
					})

					It("should have connectivity from workload via a service IP to a host-process listening on that IP", func() {
						By("Setting up a dummy service " + excludeSvcIP)
						svc := k8sService("dummy-service", excludeSvcIP, w[0][0] /* unimportant */, 8066, 8077, 0, testOpts.protocol)
						svc.ObjectMeta.Annotations = map[string]string{
							proxy.ExcludeServiceAnnotation: "true",
						}
						_, err := k8sClient.CoreV1().Services(testSvc.ObjectMeta.Namespace).
							Create(context.Background(), svc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())

						natFtKey := fmt.Sprintf("%s port %d proto %d", excludeSvcIP, 8066, numericProto)
						Eventually(func() map[string][]string {
							return tc.Felixes[0].BPFNATDump(testOpts.ipv6)
						}, "5s", "300ms").Should(HaveKey(natFtKey))

						By("Adding the service IP to the host")
						// Sort of what node-local-dns does
						tc.Felixes[0].Exec("ip", "link", "add", "dummy1", "type", "dummy")
						tc.Felixes[0].Exec("ip", "link", "set", "dummy1", "up")
						tc.Felixes[0].Exec("ip", "addr", "add", excludeSvcIP+"/"+ipMask(), "dev", "dummy1")

						By("Starting host workload")
						hostW := workload.Run(tc.Felixes[0], "dummy", "default",
							excludeSvcIP, "8066", testOpts.protocol, workload.WithHostNetworked())
						defer hostW.Stop()

						cc.Expect(Some, w[0][0], TargetIP(excludeSvcIP), ExpectWithPorts(8066))
						cc.CheckConnectivity()
					})

					It("should create sane conntrack entries and clean them up", func() {
						By("Generating some traffic")
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], TargetIP(ip), port)
						cc.ExpectSome(w[1][0], TargetIP(ip), port)
						cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)

						By("Checking timestamps on conntrack entries are sane")
						// This test verifies that we correctly interpret conntrack entry timestamps by reading them back
						// and checking that they're (a) in the past and (b) sensibly recent.
						var (
							err    error
							ctDump string
						)

						if testOpts.ipv6 {
							ctDump, err = tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "-6", "dump")
						} else {
							ctDump, err = tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
						}
						Expect(err).NotTo(HaveOccurred())
						re := regexp.MustCompile(`LastSeen:\s*(\d+)`)
						matches := re.FindAllStringSubmatch(ctDump, -1)
						Expect(matches).ToNot(BeEmpty(), "didn't find any conntrack entries")
						for _, match := range matches {
							lastSeenNanos, err := strconv.ParseInt(match[1], 10, 64)
							Expect(err).NotTo(HaveOccurred())
							nowNanos := bpf.KTimeNanos()
							age := time.Duration(nowNanos - lastSeenNanos)
							Expect(age).To(BeNumerically(">", 0))
							Expect(age).To(BeNumerically("<", 60*time.Second))
						}

						By("Checking conntrack entries are cleaned up")
						// We have UTs that check that all kinds of entries eventually get cleaned up.  This
						// test is mainly to check that the cleanup code actually runs and is able to actually delete
						// entries.
						numWl0ConntrackEntries := func() int {
							if testOpts.ipv6 {
								ctDump, err = tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "-6", "dump")
							} else {
								ctDump, err = tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
							}
							Expect(err).NotTo(HaveOccurred())
							return strings.Count(ctDump, w[0][0].IP)
						}

						startingCTEntries := numWl0ConntrackEntries()
						Expect(startingCTEntries).To(BeNumerically(">", 0))

						// TODO reduce timeouts just for this test.
						Eventually(numWl0ConntrackEntries, "180s", "5s").Should(BeNumerically("<", startingCTEntries))
					})

					Context("with test-service port updated", func() {

						var (
							testSvcUpdated      *v1.Service
							natBackBeforeUpdate []map[nat.BackendKey]nat.BackendValueInterface
							natBeforeUpdate     []map[nat.FrontendKeyInterface]nat.FrontendValue
						)

						BeforeEach(func() {
							family := 4

							var oldK nat.FrontendKeyInterface

							ip := testSvc.Spec.ClusterIP
							portOld := uint16(testSvc.Spec.Ports[0].Port)

							if testOpts.ipv6 {
								family = 6
								ipv6 := net.ParseIP(ip)
								oldK = nat.NewNATKeyV6(ipv6, portOld, numericProto)
							} else {
								ipv4 := net.ParseIP(ip)
								oldK = nat.NewNATKey(ipv4, portOld, numericProto)
							}

							// Wait for the NAT maps to converge...
							log.Info("Waiting for NAT maps to converge...")
							startTime := time.Now()
							for {
								if time.Since(startTime) > 5*time.Second {
									Fail("NAT maps failed to converge")
								}
								natBeforeUpdate, natBackBeforeUpdate = dumpNATmapsAny(family, tc.Felixes)
								for i, m := range natBeforeUpdate {
									if natV, ok := m[oldK]; !ok {
										goto retry
									} else {
										bckCnt := natV.Count()
										if bckCnt != 1 {
											log.Debugf("Expected single backend, not %d; retrying...", bckCnt)
											goto retry
										}
										bckID := natV.ID()
										bckK := nat.NewNATBackendKey(bckID, 0)
										if _, ok := natBackBeforeUpdate[i][bckK]; !ok {
											log.Debugf("Backend not found %v; retrying...", bckK)
											goto retry
										}
									}
								}

								log.Infof("NAT maps converge took %v", time.Since(startTime))
								break
							retry:
								time.Sleep(100 * time.Millisecond)
								log.Info("NAT maps converge retry")
							}
							log.Info("NAT maps converged.")

							testSvcUpdated = k8sService(testSvcName, clusterIP, w[0][0], 88, 8055, 0, testOpts.protocol)

							svc, err := k8sClient.CoreV1().
								Services(testSvcNamespace).
								Get(context.Background(), testSvcName, metav1.GetOptions{})

							testSvcUpdated.ObjectMeta.ResourceVersion = svc.ObjectMeta.ResourceVersion

							_, err = k8sClient.CoreV1().Services(testSvcNamespace).Update(context.Background(), testSvcUpdated, metav1.UpdateOptions{})
							Expect(err).NotTo(HaveOccurred())
							Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
								"Service endpoints didn't get created? Is controller-manager happy?")
						})

						It("should have connectivity from all workloads via the new port", func() {
							ip := testSvcUpdated.Spec.ClusterIP
							port := uint16(testSvcUpdated.Spec.Ports[0].Port)

							cc.ExpectSome(w[0][1], TargetIP(ip), port)
							cc.ExpectSome(w[1][0], TargetIP(ip), port)
							cc.ExpectSome(w[1][1], TargetIP(ip), port)
							cc.CheckConnectivity()
						})

						It("should not have connectivity from all workloads via the old port", func() {
							family := 4

							var (
								oldK, natK nat.FrontendKeyInterface
							)

							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectNone(w[0][1], TargetIP(ip), port)
							cc.ExpectNone(w[1][0], TargetIP(ip), port)
							cc.ExpectNone(w[1][1], TargetIP(ip), port)
							cc.CheckConnectivity()

							portOld := uint16(testSvc.Spec.Ports[0].Port)
							portNew := uint16(testSvcUpdated.Spec.Ports[0].Port)

							if testOpts.ipv6 {
								family = 6
								ipv6 := net.ParseIP(ip)
								oldK = nat.NewNATKeyV6(ipv6, portOld, numericProto)
								natK = nat.NewNATKeyV6(ipv6, portNew, numericProto)
							} else {
								ipv4 := net.ParseIP(ip)
								oldK = nat.NewNATKey(ipv4, portOld, numericProto)
								natK = nat.NewNATKey(ipv4, portNew, numericProto)
							}

							natmaps, natbacks := dumpNATmapsAny(family, tc.Felixes)

							for i := range tc.Felixes {
								Expect(natmaps[i]).To(HaveKey(natK))
								Expect(natmaps[i]).NotTo(HaveKey(oldK))

								Expect(natBeforeUpdate[i]).To(HaveKey(oldK))
								oldV := natBeforeUpdate[i][oldK]

								natV := natmaps[i][natK]
								bckCnt := natV.Count()
								bckID := natV.ID()

								log.WithField("backCnt", bckCnt).Debug("Backend count.")
								for ord := uint32(0); ord < uint32(bckCnt); ord++ {
									bckK := nat.NewNATBackendKey(bckID, ord)
									oldBckK := nat.NewNATBackendKey(oldV.ID(), ord)
									Expect(natbacks[i]).To(HaveKey(bckK))
									Expect(natBackBeforeUpdate[i]).To(HaveKey(oldBckK))
									Expect(natBackBeforeUpdate[i][oldBckK]).To(Equal(natbacks[i][bckK]))
								}

							}
						})

						It("after removing service, should not have connectivity from workloads via a service to workload 0", func() {
							var natK nat.FrontendKeyInterface

							ip := testSvcUpdated.Spec.ClusterIP
							port := uint16(testSvcUpdated.Spec.Ports[0].Port)

							family := 4
							if testOpts.ipv6 {
								family = 6
								natK = nat.NewNATKeyV6(net.ParseIP(ip), port, numericProto)
							} else {
								natK = nat.NewNATKey(net.ParseIP(ip), port, numericProto)
							}

							var prevBpfsvcs []map[nat.FrontendKeyInterface]nat.FrontendValue

							Eventually(func() bool {
								prevBpfsvcs, _ = dumpNATmapsAny(family, tc.Felixes)
								for _, m := range prevBpfsvcs {
									if _, ok := m[natK]; !ok {
										return false
									}
								}
								return true
							}, "5s").Should(BeTrue(), "service NAT key didn't show up")

							err := k8sClient.CoreV1().
								Services(testSvcNamespace).
								Delete(context.Background(), testSvcName, metav1.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
							Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(0))

							cc.ExpectNone(w[0][1], TargetIP(ip), port)
							cc.ExpectNone(w[1][0], TargetIP(ip), port)
							cc.ExpectNone(w[1][1], TargetIP(ip), port)
							cc.CheckConnectivity()

							for i, f := range tc.Felixes {
								natV := prevBpfsvcs[i][natK]
								bckCnt := natV.Count()
								bckID := natV.ID()

								Eventually(func() bool {
									svcs, eps := dumpNATMapsAny(family, f)

									if _, ok := svcs[natK]; ok {
										return false
									}

									for ord := uint32(0); ord < uint32(bckCnt); ord++ {
										bckK := nat.NewNATBackendKey(bckID, ord)
										if _, ok := eps[bckK]; ok {
											return false
										}
									}

									return true
								}, "5s").Should(BeTrue(), "service NAT key wasn't removed correctly")
							}
						})
					})
				})

				Context("with test-service configured "+clusterIP+":80 -> w[*][0].IP:8055", func() {
					testMultiBackends := func(setAffinity bool) {
						var (
							testSvc          *v1.Service
							testSvcNamespace string
						)

						testSvcName := "test-service"

						BeforeEach(func() {
							testSvc = k8sService(testSvcName, clusterIP, w[0][0], 80, 8055, 0, testOpts.protocol)
							testSvcNamespace = testSvc.ObjectMeta.Namespace
							// select all pods with port 8055
							testSvc.Spec.Selector = map[string]string{"port": "8055"}
							if setAffinity {
								testSvc.Spec.SessionAffinity = "ClientIP"
							}
							_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
							Expect(err).NotTo(HaveOccurred())
							Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
								"Service endpoints didn't get created? Is controller-manager happy?")
						})

						// Since the affinity map is shared by cgroup programs on
						// all nodes, we must be careful to use only client(s) on a
						// single node for the experiments.
						It("should have connectivity from a workload to a service with multiple backends", func() {

							affKV := func() (nat.AffinityKeyInterface, nat.AffinityValueInterface) {
								if testOpts.ipv6 {
									aff := dumpAffMapV6(tc.Felixes[0])
									ExpectWithOffset(1, aff).To(HaveLen(1))

									// get the only key
									for k, v := range aff {
										return k, v
									}
								} else {
									aff := dumpAffMap(tc.Felixes[0])
									ExpectWithOffset(1, aff).To(HaveLen(1))

									// get the only key
									for k, v := range aff {
										return k, v
									}
								}

								Fail("no value in aff map")
								return nil, nil
							}

							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							if setAffinity {
								// Sync with NAT tables to prevent creating extra entry when
								// CTLB misses but regular DNAT hits, but connection fails and
								// then CTLB succeeds.
								var (
									family   int
									natFtKey nat.FrontendKeyInterface
								)

								if testOpts.ipv6 {
									natFtKey = nat.NewNATKeyV6Intf(net.ParseIP(ip), port, numericProto)
									family = 6
								} else {
									natFtKey = nat.NewNATKeyIntf(net.ParseIP(ip), port, numericProto)
									family = 4
								}

								Eventually(func() bool {
									m, be := dumpNATMapsAny(family, tc.Felixes[0])

									v, ok := m[natFtKey]
									if !ok || v.Count() == 0 {
										return false
									}

									beKey := nat.NewNATBackendKey(v.ID(), 0)

									_, ok = be[beKey]
									return ok
								}, 5*time.Second).Should(BeTrue())
							}

							cc.ExpectSome(w[0][1], TargetIP(ip), port)
							cc.CheckConnectivity()

							_, val1 := affKV()

							cc.CheckConnectivity()

							_, v2 := affKV()

							// This should happen consistently, but that may take quite some time.
							Expect(val1.Backend()).To(Equal(v2.Backend()))

							cc.ResetExpectations()

							// N.B. Client must be on felix-0 to be subject to ctlb!
							cc.ExpectSome(w[0][1], TargetIP(ip), port)
							cc.ExpectSome(w[0][1], TargetIP(ip), port)
							cc.ExpectSome(w[0][1], TargetIP(ip), port)
							cc.CheckConnectivity()

							mkey, mVal := affKV()
							Expect(val1.Backend()).To(Equal(mVal.Backend()))

							netIP := net.ParseIP(ip)
							if testOpts.ipv6 {
								Expect(mkey.FrontendAffinityKey().AsBytes()).
									To(Equal(nat.NewNATKeyV6(netIP, port, numericProto).AsBytes()[4:24]))
							} else {
								Expect(mkey.FrontendAffinityKey().AsBytes()).
									To(Equal(nat.NewNATKey(netIP, port, numericProto).AsBytes()[4:12]))
							}

							Eventually(func() nat.BackendValueInterface {
								// Remove the affinity entry to emulate timer
								// expiring / no prior affinity.
								var m maps.Map
								if testOpts.ipv6 {
									m = nat.AffinityMapV6()
								} else {
									m = nat.AffinityMap()
								}
								cmd, err := maps.MapDeleteKeyCmd(m, mkey.AsBytes())
								Expect(err).NotTo(HaveOccurred())
								err = tc.Felixes[0].ExecMayFail(cmd...)
								if err != nil {
									Expect(err.Error()).To(ContainSubstring("No such file or directory"))
								}

								if testOpts.ipv6 {
									aff := dumpAffMapV6(tc.Felixes[0])
									Expect(aff).To(HaveLen(0))

									cc.CheckConnectivity()

									aff = dumpAffMapV6(tc.Felixes[0])
									Expect(aff).To(HaveLen(1))
									Expect(aff).To(HaveKey(mkey.(nat.AffinityKeyV6)))

									return aff[mkey.(nat.AffinityKeyV6)].Backend()
								}

								if testOpts.ipv6 {
									aff := dumpAffMapV6(tc.Felixes[0])
									Expect(aff).To(HaveLen(0))
								} else {
									aff := dumpAffMap(tc.Felixes[0])
									Expect(aff).To(HaveLen(0))
								}

								cc.CheckConnectivity()

								if testOpts.ipv6 {
									aff := dumpAffMapV6(tc.Felixes[0])
									Expect(aff).To(HaveLen(1))
									Expect(aff).To(HaveKey(mkey.(nat.AffinityKeyV6)))
									return aff[mkey.(nat.AffinityKeyV6)].Backend()
								}

								aff := dumpAffMap(tc.Felixes[0])
								Expect(aff).To(HaveLen(1))
								Expect(aff).To(HaveKey(mkey.(nat.AffinityKey)))
								return aff[mkey.(nat.AffinityKey)].Backend()
							}, 60*time.Second, time.Second).ShouldNot(Equal(mVal.Backend()))
						})
					}

					Context("with affinity", func() {
						testMultiBackends(true)
					})

					if testOpts.protocol == "udp" && testOpts.udpUnConnected && testOpts.connTimeEnabled {
						// We enforce affinity for unconnected UDP
						Context("without affinity", func() {
							testMultiBackends(false)
						})
					}

					It("should have connectivity with affinity after a backend is gone", func() {
						var (
							testSvc          *v1.Service
							testSvcNamespace string
							family           int
							natFtKey         nat.FrontendKeyInterface
						)

						testSvcName := "test-service"

						By("Setting up the service", func() {
							testSvc = k8sService(testSvcName, clusterIP, w[0][0], 80, 8055, 0, testOpts.protocol)
							testSvcNamespace = testSvc.ObjectMeta.Namespace
							// select all pods with port 8055
							testSvc.Spec.Selector = map[string]string{"port": "8055"}
							testSvc.Spec.SessionAffinity = "ClientIP"
							_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
							Expect(err).NotTo(HaveOccurred())
							Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
								"Service endpoints didn't get created? Is controller-manager happy?")
						})

						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						By("Syncing with NAT tables", func() {
							// Sync with NAT tables to prevent creating extra entry when
							// CTLB misses but regular DNAT hits, but connection fails and
							// then CTLB succeeds.
							if testOpts.ipv6 {
								natFtKey = nat.NewNATKeyV6(net.ParseIP(ip), port, numericProto)
								family = 6
							} else {
								natFtKey = nat.NewNATKey(net.ParseIP(ip), port, numericProto)
								family = 4
							}
							Eventually(func() bool {
								m, be := dumpNATMapsAny(family, tc.Felixes[0])
								v, ok := m[natFtKey]
								if !ok || v.Count() == 0 {
									return false
								}

								beKey := nat.NewNATBackendKey(v.ID(), 0)

								_, ok = be[beKey]
								return ok
							}, 5*time.Second).Should(BeTrue())
						})

						By("make connection to a service and set affinity")
						cc.ExpectSome(w[0][1], TargetIP(ip), port)
						cc.CheckConnectivity()

						By("checking that affinity was created")
						if testOpts.ipv6 {
							aff := dumpAffMapV6(tc.Felixes[0])
							Expect(aff).To(HaveLen(1))
						} else {
							aff := dumpAffMap(tc.Felixes[0])
							Expect(aff).To(HaveLen(1))
						}

						// Stop the original backends so that they are not
						// reachable with the set affinity.
						w[0][0].Stop()
						w[1][0].Stop()

						By("changing the service backend to completely different ones")
						testSvc8056 := k8sService(testSvcName, clusterIP, w[1][1], 80, 8056, 0, testOpts.protocol)
						testSvc8056.Spec.SessionAffinity = "ClientIP"
						k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvc8056)

						By("checking the affinity is cleaned up")
						Eventually(func() int {
							if testOpts.ipv6 {
								aff := dumpAffMapV6(tc.Felixes[0])
								return len(aff)
							} else {
								aff := dumpAffMap(tc.Felixes[0])
								return len(aff)
							}
						}).Should(Equal(0))

						By("making another connection to a new backend")
						ip = testSvc.Spec.ClusterIP
						port = uint16(testSvc.Spec.Ports[0].Port)

						cc.ResetExpectations()
						ip = testSvc8056.Spec.ClusterIP
						port = uint16(testSvc8056.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], TargetIP(ip), port)
						cc.CheckConnectivity()
					})

					ifUDPnoCTLB := func(desc string, body func()) {
						if testOpts.protocol != "udp" || testOpts.connTimeEnabled {
							return
						}
						It(desc, body)
					}

					ifUDPnoCTLB("should have connectivity after a backend is replaced by a new one", func() {

						var (
							testSvc          *v1.Service
							testSvcNamespace string
						)

						testSvcName := "test-service"

						By("Setting up the service", func() {
							testSvc = k8sService(testSvcName, clusterIP, w[0][0], 80, 8055, 0, testOpts.protocol)
							testSvcNamespace = testSvc.ObjectMeta.Namespace
							_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
							Expect(err).NotTo(HaveOccurred())
							Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
								"Service endpoints didn't get created? Is controller-manager happy?")
						})

						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						By("Syncing with NAT tables", func() {
							// Sync with NAT tables to prevent creating extra entry when
							// CTLB misses but regular DNAT hits, but connection fails and
							// then CTLB succeeds.
							var (
								natFtKey nat.FrontendKeyInterface
								family   int
							)

							if testOpts.ipv6 {
								natFtKey = nat.NewNATKeyV6(net.ParseIP(ip), port, numericProto)
								family = 6
							} else {
								natFtKey = nat.NewNATKey(net.ParseIP(ip), port, numericProto)
								family = 4
							}
							Eventually(func() bool {
								m, be := dumpNATMapsAny(family, tc.Felixes[1])

								v, ok := m[natFtKey]
								if !ok || v.Count() == 0 {
									return false
								}

								beKey := nat.NewNATBackendKey(v.ID(), 0)

								_, ok = be[beKey]
								return ok
							}, 5*time.Second).Should(BeTrue())
						})

						By("Making sure that backend is ready")
						cc.Expect(Some, w[1][1], w[0][0], ExpectWithPorts(8055))
						cc.CheckConnectivity()

						By("Starting a persistent connection to the service")
						pc := w[1][1].StartPersistentConnection(ip, int(port),
							workload.PersistentConnectionOpts{
								MonitorConnectivity: true,
								Timeout:             60 * time.Second,
							},
						)
						defer pc.Stop()

						By("Testing connectivity")
						prevCount := pc.PongCount()
						Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
							"Expected to see pong responses on the connection but didn't receive any")

						By("changing the service backend to completely different ones")
						testSvc2 := k8sService(testSvcName, clusterIP, w[1][0], 80, 8055, 0, testOpts.protocol)
						k8sUpdateService(k8sClient, testSvcNamespace, testSvcName, testSvc, testSvc2)

						By("Stoping the original backend to make sure it is not reachable")
						w[0][0].Stop()
						By("removing the old workload from infra")
						w[0][0].RemoveFromInfra(infra)

						By("Testing connectivity continues")
						prevCount = pc.PongCount()
						Eventually(pc.PongCount, "15s").Should(BeNumerically(">", prevCount),
							"Expected to see pong responses on the connection but didn't receive any")
					})
				})

				npPort := uint16(30333)

				nodePortsTest := func(extLocal, intLocal bool) {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
						feKey            nat.FrontendKeyInterface
						family           int
					)

					testSvcName := "test-service"
					testSvcExtIP0 := "10.123.0.0"
					testSvcExtIP1 := "10.123.0.1"
					if testOpts.ipv6 {
						testSvcExtIP0 = net.ParseIP("dead:beef::123:0:0:0").String()
						testSvcExtIP1 = net.ParseIP("dead:beef::123:0:0:1").String()
					}

					BeforeEach(func() {
						k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
						testSvc = k8sService(testSvcName, clusterIP,
							w[0][0], 80, 8055, int32(npPort), testOpts.protocol)
						testSvc.Spec.ExternalIPs = []string{testSvcExtIP0, testSvcExtIP1}
						if extLocal {
							testSvc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
						}
						if intLocal {
							internalLocal := v1.ServiceInternalTrafficPolicyLocal
							testSvc.Spec.InternalTrafficPolicy = &internalLocal
						}
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					It("should have connectivity from all workloads via a service to workload 0", func() {
						clusterIP := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						exp := Some
						if intLocal {
							exp = None
						}

						w00Expects := []ExpectationOption{ExpectWithPorts(port)}
						hostW0SrcIP := ExpectWithSrcIPs(felixIP(0))
						if testOpts.ipv6 {
							hostW0SrcIP = ExpectWithSrcIPs(felixIP(0))
							switch testOpts.tunnel {
							case "vxlan":
								hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
							case "wireguard":
								hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
							}
						}
						switch testOpts.tunnel {
						case "ipip":
							hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
						}

						if !testOpts.connTimeEnabled {
							w00Expects = append(w00Expects, hostW0SrcIP)
						}

						cc.Expect(Some, w[0][0], TargetIP(clusterIP), w00Expects...)
						cc.Expect(Some, w[0][1], TargetIP(clusterIP), ExpectWithPorts(port))
						cc.Expect(exp, w[1][0], TargetIP(clusterIP), ExpectWithPorts(port))
						cc.Expect(exp, w[1][1], TargetIP(clusterIP), ExpectWithPorts(port))
						cc.CheckConnectivity()
					})

					if intLocal {
						It("should not have connectivity from all workloads via a nodeport to non-local workload 0", func() {
							By("Checking connectivity")

							node0IP := felixIP(0)
							node1IP := felixIP(1)

							// Should work through the nodeport from a pod on the node where the backend is
							cc.ExpectSome(w[0][1], TargetIP(node0IP), npPort)

							// Should not work through the nodeport from a node where the backend is not.
							cc.ExpectNone(w[1][0], TargetIP(node0IP), npPort)
							cc.ExpectNone(w[1][1], TargetIP(node0IP), npPort)
							cc.ExpectNone(w[0][1], TargetIP(node1IP), npPort)
							cc.ExpectNone(w[1][0], TargetIP(node1IP), npPort)
							cc.ExpectNone(w[1][1], TargetIP(node1IP), npPort)

							cc.CheckConnectivity()

							// Enough to test for one protocol
							if testIfTCP {
								By("checking correct NAT entries for remote nodeports")

								ipOK := []string{"255.255.255.255", "10.101.0.1", "dead:beef::abcd:0:0:1", /* API server */
									testSvc.Spec.ClusterIP, testSvcExtIP0, testSvcExtIP1,
									felixIP(0), felixIP(1), felixIP(2)}

								if testOpts.tunnel == "ipip" {
									ipOK = append(ipOK, tc.Felixes[0].ExpectedIPIPTunnelAddr,
										tc.Felixes[1].ExpectedIPIPTunnelAddr, tc.Felixes[2].ExpectedIPIPTunnelAddr)
								}
								if testOpts.tunnel == "vxlan" {
									if testOpts.ipv6 {
										ipOK = append(ipOK, tc.Felixes[0].ExpectedVXLANV6TunnelAddr,
											tc.Felixes[1].ExpectedVXLANV6TunnelAddr, tc.Felixes[2].ExpectedVXLANV6TunnelAddr)
									} else {
										ipOK = append(ipOK, tc.Felixes[0].ExpectedVXLANTunnelAddr,
											tc.Felixes[1].ExpectedVXLANTunnelAddr, tc.Felixes[2].ExpectedVXLANTunnelAddr)
									}
								}
								if testOpts.tunnel == "wireguard" {
									if testOpts.ipv6 {
										ipOK = append(ipOK, tc.Felixes[0].ExpectedWireguardV6TunnelAddr,
											tc.Felixes[1].ExpectedWireguardV6TunnelAddr, tc.Felixes[2].ExpectedWireguardV6TunnelAddr)
									} else {
										ipOK = append(ipOK, tc.Felixes[0].ExpectedWireguardTunnelAddr,
											tc.Felixes[1].ExpectedWireguardTunnelAddr, tc.Felixes[2].ExpectedWireguardTunnelAddr)
									}
								}

								if testOpts.ipv6 {
									family = 6
									feKey = nat.NewNATKeyV6(net.ParseIP(felixIP(0)), npPort, 6)
								} else {
									family = 4
									feKey = nat.NewNATKey(net.ParseIP(felixIP(0)), npPort, 6)
								}

								for _, felix := range tc.Felixes {
									fe, _ := dumpNATMapsAny(family, felix)
									for key := range fe {
										Expect(key.Addr().String()).To(BeElementOf(ipOK))
									}
								}

								// RemoteNodeport on node 0
								fe, _ := dumpNATMapsAny(family, tc.Felixes[0])
								Expect(fe).To(HaveKey(feKey))
								be := fe[feKey]
								Expect(be.Count()).To(Equal(uint32(1)))
								Expect(be.LocalCount()).To(Equal(uint32(1)))

								// RemoteNodeport on node 1
								fe, _ = dumpNATMapsAny(family, tc.Felixes[1])
								Expect(fe).To(HaveKey(feKey))
								be = fe[feKey]
								Expect(be.Count()).To(Equal(uint32(1)))
								Expect(be.LocalCount()).To(Equal(uint32(0)))
							}
						})
					} else if !extLocal && !intLocal {
						It("should have connectivity from all workloads via a nodeport to workload 0", func() {
							node0IP := felixIP(0)
							node1IP := felixIP(1)

							cc.ExpectSome(w[0][1], TargetIP(node0IP), npPort)
							cc.ExpectSome(w[1][0], TargetIP(node0IP), npPort)
							cc.ExpectSome(w[1][1], TargetIP(node0IP), npPort)

							cc.ExpectSome(w[0][1], TargetIP(node1IP), npPort)
							cc.ExpectSome(w[1][0], TargetIP(node1IP), npPort)
							cc.ExpectSome(w[1][1], TargetIP(node1IP), npPort)

							cc.CheckConnectivity()
						})

						Describe("with policy enabling ingress to w[0][0] from host endpoints", func() {
							BeforeEach(func() {
								pol = api.NewGlobalNetworkPolicy()
								pol.Namespace = "fv"
								pol.Name = "policy-host-eps"
								pol.Spec.Ingress = []api.Rule{
									{
										Action: "Allow",
										Source: api.EntityRule{
											Selector: "ep-type=='host'",
										},
									},
									{
										Action: "Allow",
										Source: api.EntityRule{
											Nets: []string{testSvcExtIP0 + "/" + ipMask(), testSvcExtIP1 + "/" + ipMask()},
										},
									},
								}
								w00Selector := fmt.Sprintf("name=='%s'", w[0][0].Name)
								pol.Spec.Selector = w00Selector

								pol = createPolicy(pol)
							})

							It("should have connectivity from all host-networked workloads to workload 0 via nodeport", func() {
								node0IP := felixIP(0)
								node1IP := felixIP(1)

								hostW0SrcIP := ExpectWithSrcIPs(node0IP)
								hostW1SrcIP := ExpectWithSrcIPs(node1IP)

								if testOpts.ipv6 {
									switch testOpts.tunnel {
									case "wireguard":
										if testOpts.connTimeEnabled {
											hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
										}
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
									case "vxlan":
										if testOpts.connTimeEnabled {
											hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
										}
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
									}
								} else {
									switch testOpts.tunnel {
									case "ipip":
										if testOpts.connTimeEnabled {
											hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
										}
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
									case "wireguard":
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardTunnelAddr)
									case "vxlan":
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANTunnelAddr)
									}
								}

								ports := ExpectWithPorts(npPort)

								cc.Expect(Some, hostW[0], TargetIP(node0IP), ports, hostW0SrcIP)
								cc.Expect(Some, hostW[0], TargetIP(node1IP), ports, hostW0SrcIP)
								cc.Expect(Some, hostW[1], TargetIP(node0IP), ports, hostW1SrcIP)
								cc.Expect(Some, hostW[1], TargetIP(node1IP), ports, hostW1SrcIP)

								cc.CheckConnectivity()
							})

							It("should have connectivity from all host-networked workloads to workload 0 via ExternalIP", func() {
								if testOpts.connTimeEnabled {
									// not valid for CTLB as it is just and approx.
									return
								}
								// This test is primarily to make sure that the external
								// IPs do not interfere with the workaround and vise
								// versa.
								By("Setting ExternalIPs")
								tc.Felixes[0].Exec("ip", "addr", "add", testSvcExtIP0+"/"+ipMask(), "dev", "eth0")
								tc.Felixes[1].Exec("ip", "addr", "add", testSvcExtIP1+"/"+ipMask(), "dev", "eth0")

								ipRoute := []string{"ip"}
								if testOpts.ipv6 {
									ipRoute = append(ipRoute, "-6")
								}

								// The external IPs must be routable
								By("Setting routes for the ExternalIPs")
								cmd := append(ipRoute[:len(ipRoute):len(ipRoute)],
									"route", "add", testSvcExtIP1+"/"+ipMask(), "via", felixIP(1))
								tc.Felixes[0].Exec(cmd...)
								cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
									"route", "add", testSvcExtIP0+"/"+ipMask(), "via", felixIP(0))
								tc.Felixes[1].Exec(cmd...)
								cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
									"route", "add", testSvcExtIP1+"/"+ipMask(), "via", felixIP(1))
								externalClient.Exec(cmd...)
								cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
									"route", "add", testSvcExtIP0+"/"+ipMask(), "via", felixIP(0))
								externalClient.Exec(cmd...)

								By("Allow ingress from external client", func() {
									pol = api.NewGlobalNetworkPolicy()
									pol.Namespace = "fv"
									pol.Name = "policy-ext-client"
									pol.Spec.Ingress = []api.Rule{
										{
											Action: "Allow",
											Source: api.EntityRule{
												Nets: []string{containerIP(externalClient) + "/" + ipMask()},
											},
										},
									}
									w00Selector := fmt.Sprintf("name=='%s'", w[0][0].Name)
									pol.Spec.Selector = w00Selector

									pol = createPolicy(pol)
								})

								node0IP := felixIP(0)
								node1IP := felixIP(1)

								hostW0SrcIP := ExpectWithSrcIPs(node0IP)
								hostW1SrcIP := ExpectWithSrcIPs(node1IP)
								hostW11SrcIP := ExpectWithSrcIPs(testSvcExtIP1)

								if testOpts.ipv6 {
									switch testOpts.tunnel {
									case "none":
										hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
										hostW1SrcIP = ExpectWithSrcIPs(testSvcExtIP1)
									case "wireguard":
										hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
										hostW11SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
									case "vxlan":
										hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
										hostW11SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
									}
								} else {
									switch testOpts.tunnel {
									case "ipip":
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
										hostW11SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
									case "wireguard":
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardTunnelAddr)
										hostW11SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardTunnelAddr)
									case "vxlan":
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANTunnelAddr)
										hostW11SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANTunnelAddr)
									}
								}

								ports := ExpectWithPorts(80)

								cc.Expect(Some, hostW[0], TargetIP(testSvcExtIP0), ports, ExpectWithSrcIPs(testSvcExtIP0))
								cc.Expect(Some, hostW[1], TargetIP(testSvcExtIP0), ports, hostW1SrcIP)
								cc.Expect(Some, hostW[0], TargetIP(testSvcExtIP1), ports, hostW0SrcIP)
								cc.Expect(Some, hostW[1], TargetIP(testSvcExtIP1), ports, hostW11SrcIP)

								cc.Expect(Some, externalClient, TargetIP(testSvcExtIP0), ports)
								cc.Expect(Some, externalClient, TargetIP(testSvcExtIP1), ports)

								cc.CheckConnectivity()
							})

							_ = testIfNotUDPUConnected && // two app with two sockets cannot conflict
								Context("with conflict from host-networked workloads via clusterIP and directly", func() {
									JustBeforeEach(func() {
										for i, felix := range tc.Felixes {
											f := felix
											idx := i
											Eventually(func() bool {
												return checkServiceRoute(f, testSvc.Spec.ClusterIP)
											}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(),
												fmt.Sprintf("felix %d failed to sync with service", idx))

											if testOpts.ipv6 {
												felix.Exec("ip", "-6", "route")
											} else {
												felix.Exec("ip", "route")
											}
										}
									})
									if !testOpts.connTimeEnabled {
										It("should have connection when via clusterIP starts first", func() {
											node1IP := felixIP(1)

											hostW1SrcIP := ExpectWithSrcIPs(node1IP)

											switch testOpts.tunnel {
											case "ipip":
												hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
											case "wireguard":
												hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardTunnelAddr)
												if testOpts.ipv6 {
													hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
												}
											case "vxlan":
												hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANTunnelAddr)
												if testOpts.ipv6 {
													hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
												}
											}

											clusterIP := testSvc.Spec.ClusterIP
											port := uint16(testSvc.Spec.Ports[0].Port)

											By("syncing with service programming")
											ports := ExpectWithPorts(port)
											cc.Expect(Some, hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)
											cc.CheckConnectivity()
											cc.ResetExpectations()

											By("starting a persistent connection to cluster IP")
											pc := hostW[1].StartPersistentConnection(clusterIP, int(port),
												workload.PersistentConnectionOpts{
													SourcePort:          12345,
													MonitorConnectivity: true,
												},
											)
											defer pc.Stop()

											cc.Expect(Some, hostW[1], w[0][0], hostW1SrcIP, ExpectWithSrcPort(12345))
											cc.CheckConnectivity()

											prevCount := pc.PongCount()
											Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
												"Expected to see pong responses on the connection but didn't receive any")
										})

										It("should have connection when direct starts first", func() {
											node1IP := felixIP(1)

											hostW1SrcIP := ExpectWithSrcIPs(node1IP)

											switch testOpts.tunnel {
											case "ipip":
												hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
											case "wireguard":
												hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardTunnelAddr)
												if testOpts.ipv6 {
													hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
												}
											case "vxlan":
												hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANTunnelAddr)
												if testOpts.ipv6 {
													hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
												}
											}

											clusterIP := testSvc.Spec.ClusterIP
											port := uint16(testSvc.Spec.Ports[0].Port)

											By("syncing with service programming")
											ports := ExpectWithPorts(port)
											cc.Expect(Some, hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)
											cc.CheckConnectivity()
											cc.ResetExpectations()

											By("starting a persistent connection directly")
											pc := hostW[1].StartPersistentConnection(w[0][0].IP, 8055,
												workload.PersistentConnectionOpts{
													SourcePort:          12345,
													MonitorConnectivity: true,
												},
											)
											defer pc.Stop()

											cc.Expect(Some, hostW[1], TargetIP(clusterIP), ports,
												hostW1SrcIP, ExpectWithSrcPort(12345))
											cc.CheckConnectivity()

											prevCount := pc.PongCount()
											Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
												"Expected to see pong responses on the connection but didn't receive any")
										})
									}
								})

							It("should have connectivity from all host-networked workloads to workload 0 via clusterIP", func() {
								node0IP := felixIP(0)
								node1IP := felixIP(1)

								hostW0SrcIP := ExpectWithSrcIPs(node0IP)
								hostW1SrcIP := ExpectWithSrcIPs(node1IP)

								switch testOpts.tunnel {
								case "ipip":
									hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
									hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
								case "wireguard":
									if testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
										hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
									} else {
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedWireguardTunnelAddr)
									}
								case "vxlan":
									if testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
										hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
									} else {
										hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedVXLANTunnelAddr)
									}
								}

								clusterIP := testSvc.Spec.ClusterIP
								ports := ExpectWithPorts(uint16(testSvc.Spec.Ports[0].Port))

								tc.Felixes[0].Exec("sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0")
								tc.Felixes[1].Exec("sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0")

								// Also try host networked pods, both on a local and remote node.
								cc.Expect(Some, hostW[0], TargetIP(clusterIP), ports, hostW0SrcIP)
								cc.Expect(Some, hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)

								if testOpts.protocol == "tcp" && !testOpts.ipv6 {
									// Also excercise ipv4 as ipv6
									cc.Expect(Some, hostW[0], TargetIPv4AsIPv6(clusterIP), ports, hostW0SrcIP)
									cc.Expect(Some, hostW[1], TargetIPv4AsIPv6(clusterIP), ports, hostW1SrcIP)
								}

								cc.CheckConnectivity()
							})
						})
					}

					if intLocal {
						It("workload should have connectivity to self via local and not remote node", func() {
							w00Expects := []ExpectationOption{ExpectWithPorts(npPort)}
							hostW0SrcIP := ExpectWithSrcIPs("0.0.0.0")

							hostW0SrcIP = ExpectWithSrcIPs(felixIP(0))
							if testOpts.ipv6 {
								hostW0SrcIP = ExpectWithSrcIPs(felixIP(0))
								switch testOpts.tunnel {
								case "vxlan":
									hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
								case "wireguard":
									hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
								}
							}
							switch testOpts.tunnel {
							case "ipip":
								hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
							}

							if !testOpts.connTimeEnabled {
								w00Expects = append(w00Expects, hostW0SrcIP)
							}

							cc.Expect(None, w[0][0], TargetIP(felixIP(1)), w00Expects...)
							cc.Expect(Some, w[0][0], TargetIP(felixIP(0)), w00Expects...)
							cc.CheckConnectivity()
						})
					} else {
						It("should have connectivity from a workload via a nodeport on another node to workload 0", func() {
							ip := felixIP(1)

							cc.ExpectSome(w[2][1], TargetIP(ip), npPort)
							cc.CheckConnectivity()

						})

						It("workload should have connectivity to self via local/remote node", func() {
							w00Expects := []ExpectationOption{ExpectWithPorts(npPort)}
							hostW0SrcIP := ExpectWithSrcIPs(felixIP(0))
							if testOpts.ipv6 {
								switch testOpts.tunnel {
								case "wireguard":
									hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
								case "vxlan":
									hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
								}
							} else {
								switch testOpts.tunnel {
								case "ipip":
									hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
								}
							}

							if !testOpts.connTimeEnabled {
								w00Expects = append(w00Expects, hostW0SrcIP)
							}

							cc.Expect(Some, w[0][0], TargetIP(felixIP(1)), w00Expects...)
							cc.Expect(Some, w[0][0], TargetIP(felixIP(0)), w00Expects...)
							cc.CheckConnectivity()
						})
					}

					It("should not have connectivity from external to w[0] via local/remote node", func() {
						cc.ExpectNone(externalClient, TargetIP(felixIP(1)), npPort)
						cc.ExpectNone(externalClient, TargetIP(felixIP(0)), npPort)
						// Include a check that goes via the local nodeport to make sure the dataplane has converged.
						cc.ExpectSome(w[0][1], TargetIP(felixIP(0)), npPort)
						cc.CheckConnectivity()
					})

					Describe("after updating the policy to allow traffic from externalClient", func() {
						BeforeEach(func() {
							extClIP := externalClient.IP + "/32"
							if testOpts.ipv6 {
								extClIP = externalClient.IPv6 + "/128"
							}
							pol.Spec.Ingress = []api.Rule{
								{
									Action: "Allow",
									Source: api.EntityRule{
										Nets: []string{extClIP},
									},
								},
							}
							pol = updatePolicy(pol)
						})

						if extLocal && !testOpts.connTimeEnabled {
							It("should not have connectivity from external to w[0] via node1->node0 fwd", func() {
								cc.ExpectNone(externalClient, TargetIP(felixIP(1)), npPort)
								// Include a check that goes via the nodeport with a local backing pod to make sure the dataplane has converged.
								cc.ExpectSome(externalClient, TargetIP(felixIP(0)), npPort)
								cc.CheckConnectivity()
							})
						} else if !testOpts.connTimeEnabled && !intLocal /* irrelevant option for extClient */ {
							It("should have connectivity from external to w[0] via node1->node0 fwd", func() {
								By("checking the connectivity and thus populating the  neigh table", func() {
									cc.ExpectSome(externalClient, TargetIP(felixIP(1)), npPort)
									cc.CheckConnectivity()
								})

								// The test does not make sense in DSR mode as the neigh
								// table is not used on the return path.
								if !testOpts.dsr {
									var srcMAC, dstMAC string

									By("making sure that neigh table is populated", func() {
										var (
											out string
											err error
										)

										if testOpts.ipv6 {
											out, err = tc.Felixes[0].ExecOutput("calico-bpf", "-6", "arp", "dump")
										} else {
											out, err = tc.Felixes[0].ExecOutput("calico-bpf", "arp", "dump")
										}
										Expect(err).NotTo(HaveOccurred())

										arpRegexp := regexp.MustCompile(fmt.Sprintf(".*%s : (.*) -> (.*)", felixIP(1)))

										lines := strings.Split(out, "\n")
										for _, l := range lines {
											if strings.Contains(l, felixIP(1)) {
												MACs := arpRegexp.FindStringSubmatch(l)
												Expect(MACs).To(HaveLen(3))
												srcMAC = MACs[1]
												dstMAC = MACs[2]
											}
										}

										Expect(srcMAC).NotTo(Equal(""))
										Expect(dstMAC).NotTo(Equal(""))
									})

									// Since local-host networking ignores L2 addresses, we
									// need to make sure by other means that they are set
									// correctly.
									By("making sure that return VXLAN has the right MACs using tcpdump", func() {
										tcpdump := tc.Felixes[0].AttachTCPDump("eth0")
										tcpdump.SetLogEnabled(true)
										tcpdump.AddMatcher("MACs", regexp.MustCompile(fmt.Sprintf("%s > %s", srcMAC, dstMAC)))
										tcpdump.Start("-e", "udp", "and", "src", felixIP(0), "and", "port", "4789")
										defer tcpdump.Stop()

										cc.ExpectSome(externalClient, TargetIP(felixIP(1)), npPort)
										cc.CheckConnectivity()

										Eventually(func() int { return tcpdump.MatchCount("MACs") }).
											Should(BeNumerically(">", 0), "MACs do not match")
									})
								}
							})

							// Our unconnected test client cannot handle multiple streams. Two
							// clients cannot use the same local address. The connected case shows
							// that it works in principle.
							_ = testIfNotUDPUConnected && It("should not break connectivity with source port collision", func() {

								By("Synchronizing with policy and services")
								cc.Expect(Some, externalClient, TargetIP(felixIP(0)), ExpectWithPorts(npPort))
								cc.Expect(Some, externalClient, TargetIP(felixIP(1)), ExpectWithPorts(npPort))
								cc.CheckConnectivity()

								pc := &PersistentConnection{
									Runtime:             externalClient,
									RuntimeName:         externalClient.Name,
									IP:                  felixIP(0),
									Port:                int(npPort),
									SourcePort:          12345,
									Protocol:            testOpts.protocol,
									MonitorConnectivity: true,
								}

								err := pc.Start()
								Expect(err).NotTo(HaveOccurred())
								defer pc.Stop()

								Eventually(pc.PongCount, "5s").Should(
									BeNumerically(">", 0),
									"Expected to see pong responses on the connection but didn't receive any")
								log.Info("Pongs received within last 1s")

								cc.ResetExpectations()
								cc.Expect(Some, externalClient, TargetIP(felixIP(1)),
									ExpectWithPorts(npPort), ExpectWithSrcPort(12345))
								cc.CheckConnectivity()

								prevCount := pc.PongCount()

								Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
									"Expected to see pong responses on the connection but didn't receive any")
								log.Info("Pongs received within last 1s")
							})

							_ = testIfTCP && It("should survive conntrack cleanup sweep", func() {
								By("checking the connectivity and thus syncing with service creation", func() {
									cc.ExpectSome(externalClient, TargetIP(felixIP(1)), npPort)
									cc.CheckConnectivity()
								})

								By("monitoring a persistent connection", func() {
									pc := &PersistentConnection{
										Runtime:             externalClient,
										RuntimeName:         externalClient.Name,
										IP:                  felixIP(1),
										Port:                int(npPort),
										Protocol:            testOpts.protocol,
										MonitorConnectivity: true,
									}

									err := pc.Start()
									Expect(err).NotTo(HaveOccurred())
									defer pc.Stop()

									EventuallyWithOffset(1, pc.PongCount, "5s").Should(
										BeNumerically(">", 0),
										"Expected to see pong responses on the connection but didn't receive any")
									log.Info("Pongs received within last 1s")

									// We make sure that at least one iteration of the conntrack
									// cleanup executes and we periodically monitor the connection if
									// it is alive by checking that the number of PONGs keeps
									// increasing.
									start := time.Now()
									prevCount := pc.PongCount()
									for time.Since(start) < 2*conntrack.ScanPeriod {
										time.Sleep(time.Second)
										newCount := pc.PongCount()
										Expect(prevCount).Should(
											BeNumerically("<", newCount),
											"No new pongs since the last iteration. Connection broken?",
										)
										prevCount = newCount
									}
								})
							})

							if !testOpts.dsr {
								// When DSR is enabled, we need to have away how to pass the
								// original traffic back.
								//
								// felixes[0].Exec("ip", "route", "add", "192.168.20.0/24", "via", felixes[1].IP)
								//
								// This does not work since the other node would treat it as
								// DNAT due to the existing CT entries and NodePort traffix
								// otherwise :-/

								It("should have connectivity from external to w[0] via node1IP2 -> nodeIP1 -> node0 fwd", func() {
									// 192.168.20.1              +----------|---------+
									//      |                    |          |         |
									//      v                    |          |         V
									//    eth20                 eth0        |       eth0
									//  10.0.0.20:30333 --> felixes[1].IP   |   felixes[0].IP
									//                                      |        |
									//                                      |        V
									//                                      |     caliXYZ
									//                                      |    w[0][0].IP:8055
									//                                      |
									//                node1                 |      node0

									var (
										eth20                     *workload.Workload
										eth20IP, mask, eth20Route string
										eth20ExtIP                string
									)

									defer func() {
										if eth20 != nil {
											eth20.Stop()
										}
									}()
									if testOpts.ipv6 {
										eth20IP = "fd00::2001"
										eth20Route = "fd00::2000/120"
										eth20ExtIP = "1000::0020"
										mask = "128"

									} else {
										eth20IP = "192.168.20.1"
										eth20Route = "192.168.20.0/24"
										eth20ExtIP = "10.0.0.20"
										mask = "32"
									}

									By("setting up node's fake external iface", func() {
										// We name the iface eth20 since such ifaces are
										// treated by felix as external to the node
										//
										// Using a test-workload creates the namespaces and the
										// interfaces to emulate the host NICs
										eth20 = &workload.Workload{
											Name:          "eth20",
											C:             tc.Felixes[1].Container,
											IP:            eth20IP,
											Ports:         "57005", // 0xdead
											Protocol:      testOpts.protocol,
											InterfaceName: "eth20",
											MTU:           1500, // Need to match host MTU or felix will restart.
										}
										err := eth20.Start()
										Expect(err).NotTo(HaveOccurred())

										// assign address to eth20 and add route to the .20 network
										if testOpts.ipv6 {
											tc.Felixes[1].Exec("ip", "-6", "route", "add", eth20Route, "dev", "eth20")
											tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
											_, err = eth20.RunCmd("ip", "-6", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
											Expect(err).NotTo(HaveOccurred())
											// Add a route to felix[1] to be able to reach the nodeport
											_, err = eth20.RunCmd("ip", "-6", "route", "add", felixIP(1)+"/"+mask, "via", eth20ExtIP)
											Expect(err).NotTo(HaveOccurred())
										} else {
											tc.Felixes[1].Exec("ip", "route", "add", eth20Route, "dev", "eth20")
											tc.Felixes[1].Exec("ip", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
											_, err = eth20.RunCmd("ip", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
											Expect(err).NotTo(HaveOccurred())
											// Add a route to felix[1] to be able to reach the nodeport
											_, err = eth20.RunCmd("ip", "route", "add", felixIP(1)+"/"+mask, "via", eth20ExtIP)
											Expect(err).NotTo(HaveOccurred())
											// This multi-NIC scenario works only if the kernel's RPF check
											// is not strict so we need to override it for the test and must
											// be set properly when product is deployed. We reply on
											// iptables to do require check for us.
											tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
											tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf.eth20.rp_filter=2")
										}
									})

									By("setting up routes to .20 net on dest node to trigger RPF check", func() {
										if testOpts.ipv6 {
											// set up a dummy interface just for the routing purpose
											tc.Felixes[0].Exec("ip", "-6", "link", "add", "dummy1", "type", "dummy")
											tc.Felixes[0].Exec("ip", "-6", "link", "set", "dummy1", "up")
											// set up route to the .20 net through the dummy iface. This
											// makes the .20 a universally reachable external world from the
											// internal/private eth0 network
											tc.Felixes[0].Exec("ip", "-6", "route", "add", eth20Route, "dev", "dummy1")
										} else {
											// set up a dummy interface just for the routing purpose
											tc.Felixes[0].Exec("ip", "link", "add", "dummy1", "type", "dummy")
											tc.Felixes[0].Exec("ip", "link", "set", "dummy1", "up")
											// set up route to the .20 net through the dummy iface. This
											// makes the .20 a universally reachable external world from the
											// internal/private eth0 network
											tc.Felixes[0].Exec("ip", "route", "add", eth20Route, "dev", "dummy1")
											// This multi-NIC scenario works only if the kernel's RPF check
											// is not strict so we need to override it for the test and must
											// be set properly when product is deployed. We reply on
											// iptables to do require check for us.
											tc.Felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
											tc.Felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.dummy1.rp_filter=2")
										}
									})

									By("Allowing traffic from the eth20 network", func() {
										pol.Spec.Ingress = []api.Rule{
											{
												Action: "Allow",
												Source: api.EntityRule{
													Nets: []string{
														eth20.IP + "/" + ipMask(),
													},
												},
											},
										}
										pol = updatePolicy(pol)
									})

									By("Checking that there is connectivity from eth20 network", func() {

										cc.ExpectSome(eth20, TargetIP(felixIP(1)), npPort)
										cc.CheckConnectivity()
									})
								})
							}

							if testOpts.protocol == "tcp" {

								const (
									hostIfaceMTU = 1500
									podIfaceMTU  = 1450
									sendLen      = hostIfaceMTU
									recvLen      = podIfaceMTU
								)

								Context("with TCP, tx/rx close to MTU size on NP via node1->node0 ", func() {

									It("should not adjust MTU on client side if GRO off on nodes", func() {
										// force non-GSO packets on node ingress
										err := tc.Felixes[1].ExecMayFail("ethtool", "-K", "eth0", "gro", "off")
										Expect(err).NotTo(HaveOccurred())

										cc.Expect(Some, externalClient, TargetIP(felixIP(1)),
											ExpectWithPorts(npPort),
											ExpectWithSendLen(sendLen),
											ExpectWithRecvLen(recvLen),
											ExpectWithClientAdjustedMTU(hostIfaceMTU, hostIfaceMTU),
										)
										cc.CheckConnectivity()
									})
								})
							}
						}

						if !testOpts.connTimeEnabled {
							It("should have connectivity from external to w[0] via node0", func() {
								log.WithFields(log.Fields{
									"externalClientIP": containerIP(externalClient),
									"nodePortIP":       felixIP(1),
								}).Infof("external->nodeport connection")

								cc.ExpectSome(externalClient, TargetIP(felixIP(0)), npPort)
								cc.CheckConnectivity()
							})
						}
					})
				}

				Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort)), func() {
					nodePortsTest(false, false)
				})

				// FIXME connect time shares the same NAT table and it is a lottery which one it gets
				if !testOpts.connTimeEnabled {
					Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort))+
						" ExternalTrafficPolicy=local", func() {
						nodePortsTest(true, false)
					})
					Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort))+
						" InternalTrafficPolicy=local", func() {
						nodePortsTest(false, true)
					})
				}

				Context("with icmp blocked from workloads, external client", func() {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)

					testSvcName := "test-service"
					nets := []string{"0.0.0.0/0"}
					if testOpts.ipv6 {
						nets = []string{"::/0"}
					}

					BeforeEach(func() {
						icmpProto := numorstring.ProtocolFromString("icmp")
						if testOpts.ipv6 {
							icmpProto = numorstring.ProtocolFromString("icmpv6")
						}
						pol.Spec.Ingress = []api.Rule{
							{
								Action: "Allow",
								Source: api.EntityRule{
									Nets: nets,
								},
							},
						}
						pol.Spec.Egress = []api.Rule{
							{
								Action: "Allow",
								Source: api.EntityRule{
									Nets: nets,
								},
							},
							{
								Action:   "Deny",
								Protocol: &icmpProto,
							},
						}
						pol = updatePolicy(pol)
					})

					var tgtPort int
					var tgtWorkload *workload.Workload

					JustBeforeEach(func() {
						k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
						testSvc = k8sService(testSvcName, clusterIP,
							tgtWorkload, 80, tgtPort, int32(npPort), testOpts.protocol)
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")

						// Sync with all felixes because some fwd tests with "none"
						// connectivity need this to be set on all sides as they will not
						// retry when there is no connectivity.
						Eventually(func() bool {
							for _, flx := range tc.Felixes {
								var (
									family   int
									natFtKey nat.FrontendKeyInterface
								)

								if testOpts.ipv6 {
									natFtKey = nat.NewNATKeyV6Intf(net.ParseIP(containerIP(flx.Container)), npPort, numericProto)
									family = 6
								} else {
									natFtKey = nat.NewNATKeyIntf(net.ParseIP(containerIP(flx.Container)), npPort, numericProto)
									family = 4
								}

								m, be := dumpNATMapsAny(family, flx)
								v, ok := m[natFtKey]
								if !ok || v.Count() == 0 {
									return false
								}

								beKey := nat.NewNATBackendKey(v.ID(), 0)

								if _, ok := be[beKey]; !ok {
									return false
								}
							}
							return true
						}, 5*time.Second).Should(BeTrue())

						// Sync with policy
						cc.ExpectSome(w[1][0], w[0][0])
						cc.CheckConnectivity()
					})

					icmpProto := "icmp"
					if testOpts.ipv6 {
						icmpProto = "icmp6"
					}

					Describe("with dead workload", func() {
						if testOpts.connTimeEnabled {
							// FIXME externalClient also does conntime balancing
							return
						}

						BeforeEach(func() {
							deadWorkload.ConfigureInInfra(infra)
							tgtPort = 8057
							tgtWorkload = deadWorkload
						})

						It("should get host unreachable from nodeport via node1->node0 fwd", func() {
							err := tc.Felixes[0].ExecMayFail("ip", "route", "add", "unreachable", deadWorkload.IP)
							Expect(err).NotTo(HaveOccurred())

							tcpdump := externalClient.AttachTCPDump("any")
							tcpdump.SetLogEnabled(true)
							var matcher string
							if testOpts.ipv6 {
								matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable route %s",
									felixIP(1), containerIP(externalClient), felixIP(1))
							} else {
								matcher = fmt.Sprintf("IP %s > %s: ICMP host %s unreachable",
									felixIP(1), containerIP(externalClient), felixIP(1))
							}
							tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
							tcpdump.Start(testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)
							defer tcpdump.Stop()

							cc.ExpectNone(externalClient, TargetIP(felixIP(1)), npPort)
							cc.CheckConnectivity()

							Eventually(func() int { return tcpdump.MatchCount("ICMP") }).
								Should(BeNumerically(">", 0), matcher)
						})
					})

					Describe("with wrong target port", func() {
						// TCP would send RST instead of ICMP, it is enough to test one way of
						// triggering the ICMP message
						if testOpts.protocol != "udp" {
							return
						}

						BeforeEach(func() {
							tgtPort = 0xdead
							tgtWorkload = w[0][0]
						})

						if !testOpts.connTimeEnabled {
							It("should get port unreachable via node1->node0 fwd", func() {
								tcpdump := externalClient.AttachTCPDump("any")
								tcpdump.SetLogEnabled(true)
								matcher := fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
									felixIP(1), containerIP(externalClient), felixIP(1), npPort)
								tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
								tcpdump.Start(testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)
								defer tcpdump.Stop()

								cc.ExpectNone(externalClient, TargetIP(felixIP(1)), npPort)
								cc.CheckConnectivity()
								Eventually(func() int { return tcpdump.MatchCount("ICMP") }).
									Should(BeNumerically(">", 0), matcher)
							})
						}

						It("should get port unreachable workload to workload", func() {
							tcpdump := w[1][1].AttachTCPDump()
							tcpdump.SetLogEnabled(true)

							var matcher string

							if testOpts.ipv6 {
								matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
									tgtWorkload.IP, w[1][1].IP, tgtWorkload.IP, tgtPort)
							} else {
								matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
									tgtWorkload.IP, w[1][1].IP, tgtWorkload.IP, tgtPort)
							}
							tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
							tcpdump.Start(testOpts.protocol, "port", strconv.Itoa(tgtPort), "or", icmpProto)
							defer tcpdump.Stop()

							cc.ExpectNone(w[1][1], TargetIP(tgtWorkload.IP), uint16(tgtPort))
							cc.CheckConnectivity()
							Eventually(func() int { return tcpdump.MatchCount("ICMP") }).
								Should(BeNumerically(">", 0), matcher)
						})

						It("should get port unreachable workload to workload through NP", func() {
							tcpdump := w[1][1].AttachTCPDump()
							tcpdump.SetLogEnabled(true)

							var matcher string

							if testOpts.connTimeEnabled {
								if testOpts.ipv6 {
									matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
										tgtWorkload.IP, w[1][1].IP, w[0][0].IP, tgtPort)
								} else {
									matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
										tgtWorkload.IP, w[1][1].IP, w[0][0].IP, tgtPort)
								}
								tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
								tcpdump.Start(testOpts.protocol, "port", strconv.Itoa(tgtPort), "or", icmpProto)
							} else {
								if testOpts.ipv6 {
									matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
										tgtWorkload.IP, w[1][1].IP, felixIP(1), npPort)
								} else {
									matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
										tgtWorkload.IP, w[1][1].IP, felixIP(1), npPort)
								}
								tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
								tcpdump.Start(testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", "icmp")
							}
							defer tcpdump.Stop()

							cc.ExpectNone(w[1][1], TargetIP(felixIP(1)), npPort)
							cc.CheckConnectivity()
							Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
								Should(BeNumerically(">", 0), matcher)
						})
					})
				})

				Context("with CT tables full", func() {
					It("should still allow host -> host", func() {
						// XXX as long as there is no HEP policy
						// using hostW as a sink

						By("waiting for everything to come up", func() {
							cc.Expect(Some, tc.Felixes[0], hostW[1])
							cc.Expect(Some, tc.Felixes[1], hostW[0])
							cc.CheckConnectivity()
						})

						By("filling up the CT tables", func() {
							now := time.Duration(timeshim.RealTime().KTimeNanos())
							leg := conntrack.Leg{SynSeen: true, AckSeen: true, Opener: true}

							if testOpts.ipv6 {
								srcIP := net.ParseIP("dead:beef::123:123:123:123")
								dstIP := net.ParseIP("dead:beef::121:121:121:121")

								val := conntrack.NewValueV6Normal(now, now, 0, leg, leg)
								val64 := base64.StdEncoding.EncodeToString(val[:])

								key := conntrack.NewKeyV6(6 /* TCP */, srcIP, 0, dstIP, 0)
								key64 := base64.StdEncoding.EncodeToString(key[:])

								_, err := tc.Felixes[0].ExecCombinedOutput("calico-bpf", "-6", "conntrack", "fill", key64, val64)
								Expect(err).NotTo(HaveOccurred())
							} else {
								srcIP := net.IPv4(123, 123, 123, 123)
								dstIP := net.IPv4(121, 121, 121, 121)

								val := conntrack.NewValueNormal(now, now, 0, leg, leg)
								val64 := base64.StdEncoding.EncodeToString(val[:])

								key := conntrack.NewKey(6 /* TCP */, srcIP, 0, dstIP, 0)
								key64 := base64.StdEncoding.EncodeToString(key[:])

								_, err := tc.Felixes[0].ExecCombinedOutput("calico-bpf", "conntrack", "fill", key64, val64)
								Expect(err).NotTo(HaveOccurred())
							}
						})

						By("checking host-host connectivity works", func() {
							cc.ResetExpectations()
							cc.Expect(Some, tc.Felixes[0], hostW[1])
							cc.Expect(Some, tc.Felixes[1], hostW[0])
							cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
						})

						By("checking pod-pod connectivity fails", func() {
							cc.ResetExpectations()
							cc.Expect(None, w[0][1], w[0][0])
							cc.Expect(None, w[1][0], w[0][0])
							cc.Expect(None, w[1][1], w[0][0])
							cc.CheckConnectivity()
						})

						By("cleaning up the CT maps", func() {
							if testOpts.ipv6 {
								_, err := tc.Felixes[0].ExecOutput("calico-bpf", "-6", "conntrack", "clean")
								Expect(err).NotTo(HaveOccurred())
							} else {
								_, err := tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "clean")
								Expect(err).NotTo(HaveOccurred())
							}
						})

						By("checking pod-pod connectivity works again", func() {
							cc.ResetExpectations()
							cc.Expect(Some, w[0][1], w[0][0])
							cc.Expect(Some, w[1][0], w[0][0])
							cc.Expect(Some, w[1][1], w[0][0])
							cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
						})
					})
				})
			})

			It("should have connectivity when DNAT redirects to-host traffic to a local pod.", func() {
				protocol := "tcp"
				if testOpts.protocol == "udp" {
					protocol = "udp"
				}

				hostIP0 := TargetIP(felixIP(0))
				hostPort := uint16(8080)
				var (
					target string
					tool   string
				)

				if testOpts.ipv6 {
					target = fmt.Sprintf("[%s]:8055", w[0][0].IP)
					tool = "ip6tables"
				} else {
					target = fmt.Sprintf("%s:8055", w[0][0].IP)
					tool = "iptables"
				}

				policy := api.NewNetworkPolicy()
				policy.Name = "allow-all"
				policy.Namespace = "default"
				one := float64(1)
				policy.Spec.Order = &one
				policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
				policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
				policy.Spec.Selector = "all()"
				_, err := calicoClient.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				expectNormalConnectivity := func() {
					cc.ResetExpectations()
					cc.ExpectNone(tc.Felixes[1], hostIP0, hostPort)
					cc.ExpectNone(externalClient, hostIP0, hostPort)
					cc.ExpectNone(w[1][0], hostIP0, hostPort)
					cc.CheckConnectivity()
					cc.ResetExpectations()
				}

				By("checking initial connectivity", func() {
					expectNormalConnectivity()
				})

				By("installing 3rd party DNAT rules", func() {
					// Install a DNAT in first felix
					tc.Felixes[0].Exec(
						tool, "-w", "10", "-W", "100000", "-t", "nat", "-A", "PREROUTING", "-p", protocol, "-m", protocol,
						"--dport", fmt.Sprintf("%d", hostPort), "-j", "DNAT", "--to-destination", target)

					cc.ResetExpectations()
					cc.ExpectSome(tc.Felixes[1], hostIP0, hostPort)
					cc.ExpectSome(externalClient, hostIP0, hostPort)
					cc.ExpectSome(w[1][0], hostIP0, hostPort)
					cc.CheckConnectivity()
					cc.ResetExpectations()
				})

				By("removing 3rd party rules and check connectivity is back to normal again", func() {
					tc.Felixes[0].Exec(
						tool, "-w", "10", "-W", "100000", "-t", "nat", "-D", "PREROUTING", "-p", protocol, "-m", protocol,
						"--dport", fmt.Sprintf("%d", hostPort), "-j", "DNAT", "--to-destination", target)

					expectNormalConnectivity()
				})
			})

			It("should have connectivity from host-networked pods via service to host-networked backend", func() {
				By("Setting up the service")
				hostW[0].ConfigureInInfra(infra)
				testSvc := k8sService("host-svc", clusterIP, hostW[0], 80, 8055, 0, testOpts.protocol)
				testSvcNamespace := testSvc.ObjectMeta.Namespace
				k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
					"Service endpoints didn't get created? Is controller-manager happy?")

				By("Testing connectivity")
				port := uint16(testSvc.Spec.Ports[0].Port)

				hostW0SrcIP := ExpectWithSrcIPs(felixIP(0))
				hostW1SrcIP := ExpectWithSrcIPs(felixIP(1))
				if !testOpts.connTimeEnabled {
					switch testOpts.tunnel {
					case "ipip":
						hostW0SrcIP = ExpectWithSrcIPs(tc.Felixes[0].ExpectedIPIPTunnelAddr)
						hostW1SrcIP = ExpectWithSrcIPs(tc.Felixes[1].ExpectedIPIPTunnelAddr)
					}
				}

				cc.Expect(Some, hostW[0], TargetIP(clusterIP), ExpectWithPorts(port), hostW0SrcIP)
				cc.Expect(Some, hostW[1], TargetIP(clusterIP), ExpectWithPorts(port), hostW1SrcIP)
				cc.CheckConnectivity()
			})

		})

		Describe("with BPF disabled to begin with", func() {
			var pc *PersistentConnection

			BeforeEach(func() {
				options.TestManagesBPF = true
				setupCluster()

				// Default to Allow...
				pol := api.NewGlobalNetworkPolicy()
				pol.Namespace = "fv"
				pol.Name = "policy-1"
				pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
				pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
				pol.Spec.Selector = "all()"
				pol = createPolicy(pol)

				pc = nil
			})

			AfterEach(func() {
				if pc != nil {
					pc.Stop()
				}
			})

			enableBPF := func() {
				By("Enabling BPF")
				// Some tests start with a felix config pre-created, try to update it...
				fc, err := calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
				bpfEnabled := true
				if err == nil {
					fc.Spec.BPFEnabled = &bpfEnabled
					_, err := calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
					return
				}

				// Fall back on creating it...
				fc = api.NewFelixConfiguration()
				fc.Name = "default"
				fc.Spec.BPFEnabled = &bpfEnabled
				fc, err = calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Wait for BPF to be active.
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			}

			expectPongs := func() {
				count := pc.PongCount()
				EventuallyWithOffset(1, pc.PongCount, "60s").Should(
					BeNumerically(">", count),
					"Expected to see pong responses on the connection but didn't receive any")
				log.Info("Pongs received")
			}

			if testOpts.protocol == "tcp" && testOpts.dsr {
				verifyConnectivityWhileEnablingBPF := func(from, to *workload.Workload) {
					By("Starting persistent connection")
					pc = from.StartPersistentConnection(to.IP, 8055, workload.PersistentConnectionOpts{
						MonitorConnectivity: true,
						Timeout:             60 * time.Second,
					})

					By("having initial connectivity", expectPongs)
					By("enabling BPF mode", enableBPF) // Waits for BPF programs to be installed
					By("still having connectivity on the existing connection", expectPongs)
				}

				It("should keep a connection up between hosts when BPF is enabled", func() {
					verifyConnectivityWhileEnablingBPF(hostW[0], hostW[1])
				})

				It("should keep a connection up between workloads on different hosts when BPF is enabled", func() {
					verifyConnectivityWhileEnablingBPF(w[0][0], w[1][0])
				})

				It("should keep a connection up between hosts and remote workloads when BPF is enabled", func() {
					verifyConnectivityWhileEnablingBPF(hostW[0], w[1][0])
				})

				It("should keep a connection up between hosts and local workloads when BPF is enabled", func() {
					verifyConnectivityWhileEnablingBPF(hostW[0], w[0][0])
				})
			}
		})

		Describe("3rd party CNI", func() {
			// We do not use tunnel in such environments, no need to test.
			if testOpts.tunnel != "none" {
				return
			}

			BeforeEach(func() {
				// To mimic 3rd party CNI, we do not install IPPools and set the source to
				// learn routes to WorkloadIPs as IPAM/CNI is not going to provide either.
				options.UseIPPools = false
				options.ExtraEnvVars["FELIX_ROUTESOURCE"] = "WorkloadIPs"
				setupCluster()
			})

			Describe("CNI installs NAT outgoing iptable rules", func() {
				var extWorkload *workload.Workload
				BeforeEach(func() {
					c := infrastructure.RunExtClient("ext-workload")
					extWorkload = &workload.Workload{
						C:        c,
						Name:     "ext-workload",
						Ports:    "4321",
						Protocol: testOpts.protocol,
						IP:       containerIP(c),
					}

					err := extWorkload.Start()
					Expect(err).NotTo(HaveOccurred())

					tool := "iptables"
					if testOpts.ipv6 {
						tool = "ip6tables"
					}

					for _, felix := range tc.Felixes {
						felix.Exec(tool, "-t", "nat", "-A", "POSTROUTING", "-d", extWorkload.IP, "-j", "MASQUERADE")
					}
				})

				It("should have connectivity to external workload", func() {
					By("allowing any traffic", func() {
						pol := api.NewGlobalNetworkPolicy()
						pol.Namespace = "fv"
						pol.Name = "policy-1"
						pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
						pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
						pol.Spec.Selector = "all()"

						pol = createPolicy(pol)

						cc.ExpectSome(w[1][0], w[0][0])
						cc.ExpectSome(w[1][1], w[0][0])
						cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
						cc.ResetExpectations()
					})

					By("checking connectivity to the external workload", func() {
						cc.Expect(Some, w[0][0], extWorkload, ExpectWithPorts(4321), ExpectWithSrcIPs(felixIP(0)))
						cc.Expect(Some, w[1][0], extWorkload, ExpectWithPorts(4321), ExpectWithSrcIPs(felixIP(1)))
						cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
					})
				})

				AfterEach(func() {
					extWorkload.Stop()
				})
			})
		})

		Context("With BPFEnforceRPF=Strict", func() {
			BeforeEach(func() {
				options.ExtraEnvVars["FELIX_BPFEnforceRPF"] = "Strict"
				setupCluster()
			})

			// Test doesn't use services so ignore the runs with those turned on.
			if testOpts.protocol == "udp" && !testOpts.connTimeEnabled && !testOpts.dsr {
				It("should not be able to spoof UDP", func() {
					if !testOpts.ipv6 {
						By("Disabling dev RPF")
						setRPF(tc.Felixes, testOpts.tunnel, 0, 0)
						tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf."+w[1][0].InterfaceName+".rp_filter=0")
						tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf."+w[1][1].InterfaceName+".rp_filter=0")
					}

					By("allowing any traffic", func() {
						pol := api.NewGlobalNetworkPolicy()
						pol.Name = "allow-all"
						pol.Spec.Ingress = []api.Rule{{Action: api.Allow}}
						pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
						pol.Spec.Selector = "all()"

						pol = createPolicy(pol)

						cc.ExpectSome(w[1][0], w[0][0])
						cc.ExpectSome(w[1][1], w[0][0])
						cc.CheckConnectivity()
					})

					By("testing that packet sent by another workload is dropped", func() {
						tcpdump := w[0][0].AttachTCPDump()
						tcpdump.SetLogEnabled(true)
						ipVer := "IP"
						if testOpts.ipv6 {
							ipVer = "IP6"
						}

						matcher := fmt.Sprintf("%s %s\\.30444 > %s\\.30444: UDP", ipVer, w[1][0].IP, w[0][0].IP)
						tcpdump.AddMatcher("UDP-30444", regexp.MustCompile(matcher))
						tcpdump.Start(testOpts.protocol, "port", "30444", "or", "port", "30445")
						defer tcpdump.Stop()

						// send a packet from the correct workload to create a conntrack entry
						_, err := w[1][0].RunCmd("pktgen", w[1][0].IP, w[0][0].IP, "udp",
							"--port-src", "30444", "--port-dst", "30444")
						Expect(err).NotTo(HaveOccurred())

						// We must eventually see the packet at the target
						Eventually(func() int { return tcpdump.MatchCount("UDP-30444") }).
							Should(BeNumerically("==", 1), matcher)

						// Send a spoofed packet from a different pod. Since we hit the
						// conntrack we would not do the WEP only RPF check.
						_, err = w[1][1].RunCmd("pktgen", w[1][0].IP, w[0][0].IP, "udp",
							"--port-src", "30444", "--port-dst", "30444")
						Expect(err).NotTo(HaveOccurred())

						// Since the packet will get dropped, we would not see it at the dest.
						// So we send another good packet from the spoofing workload, that we
						// will see at the dest.
						matcher2 := fmt.Sprintf("%s %s\\.30445 > %s\\.30445: UDP", ipVer, w[1][1].IP, w[0][0].IP)
						tcpdump.AddMatcher("UDP-30445", regexp.MustCompile(matcher2))

						_, err = w[1][1].RunCmd("pktgen", w[1][1].IP, w[0][0].IP, "udp",
							"--port-src", "30445", "--port-dst", "30445")
						Expect(err).NotTo(HaveOccurred())

						// Wait for the good packet from the bad workload
						Eventually(func() int { return tcpdump.MatchCount("UDP-30445") }).
							Should(BeNumerically("==", 1), matcher2)

						// Check that we have not seen the spoofed packet. If there was not
						// packet reordering, which in our setup is guaranteed not to happen,
						// we know that the spoofed packet was dropped.
						Expect(tcpdump.MatchCount("UDP-30444")).To(BeNumerically("==", 1), matcher)
					})

					var (
						eth20, eth30                           *workload.Workload
						eth20IP, eth30IP, ipVer                string
						eth20ExtIP, eth30ExtIP, fakeWorkloadIP string
						eth20Route, eth30Route, mask           string
						family                                 int
					)

					defer func() {
						if eth20 != nil {
							eth20.Stop()
						}
						if eth30 != nil {
							eth30.Stop()
						}
					}()

					// Now, set up a topology that mimics two host NICs by creating one workload per fake NIC.
					// We then move a route between the two NICs to pretend that there's a workload behind
					// one or other of them.
					//
					//      eth20 = workload used as a NIC
					//         - eth20 ------ movable fake workload 10.65.15.15
					//       192.168.20.1
					//       /
					//    10.0.0.20
					// Felix
					//    10.0.0.30
					//       \
					//       192.168.30.1
					//         - eth30 ------ movable fake workload 10.65.15.15
					//      eth30 = workload used as a NIC
					//

					By("setting up node's fake external ifaces", func() {
						// We name the ifaces ethXY since such ifaces are
						// treated by felix as external to the node
						//
						// Using a test-workload creates the namespaces and the
						// interfaces to emulate the host NICs

						if testOpts.ipv6 {
							eth20IP = "fd00::2001"
							eth30IP = "fd00::3001"
							eth20ExtIP = "1000::0020"
							eth30ExtIP = "1000::0030"
							eth20Route = "fd00::2000/120"
							eth30Route = "fd00::3000/120"
							mask = "128"
							ipVer = "IP6"
							fakeWorkloadIP = "dead:beef::15:15"
							family = 6
						} else {
							eth20IP = "192.168.20.1"
							eth30IP = "192.168.30.1"
							eth20ExtIP = "10.0.0.20"
							eth30ExtIP = "10.0.0.30"
							eth20Route = "192.168.20.0/24"
							eth30Route = "192.168.30.0/24"
							mask = "32"
							ipVer = "IP"
							fakeWorkloadIP = "10.65.15.15"
							family = 4
						}

						eth20 = &workload.Workload{
							Name:          "eth20",
							C:             tc.Felixes[1].Container,
							IP:            eth20IP,
							Ports:         "57005", // 0xdead
							Protocol:      testOpts.protocol,
							InterfaceName: "eth20",
							MTU:           1500, // Need to match host MTU or felix will restart.
						}
						err := eth20.Start()
						Expect(err).NotTo(HaveOccurred())

						// assign address to eth20 and add route to the .20 network
						if testOpts.ipv6 {
							tc.Felixes[1].Exec("ip", "-6", "route", "add", eth20Route, "dev", "eth20")
							tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
							_, err = eth20.RunCmd("ip", "-6", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
							Expect(err).NotTo(HaveOccurred())
							// Add a route to the test workload to the fake external
							// client emulated by the test-workload
							_, err = eth20.RunCmd("ip", "-6", "route", "add", w[1][1].IP+"/"+mask, "via", eth20ExtIP)
							Expect(err).NotTo(HaveOccurred())
						} else {
							tc.Felixes[1].Exec("ip", "route", "add", eth20Route, "dev", "eth20")
							tc.Felixes[1].Exec("ip", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
							_, err = eth20.RunCmd("ip", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
							Expect(err).NotTo(HaveOccurred())
							// Add a route to the test workload to the fake external
							// client emulated by the test-workload
							_, err = eth20.RunCmd("ip", "route", "add", w[1][1].IP+"/"+mask, "via", eth20ExtIP)
							Expect(err).NotTo(HaveOccurred())
						}

						eth30 = &workload.Workload{
							Name:          "eth30",
							C:             tc.Felixes[1].Container,
							IP:            eth30IP,
							Ports:         "57005", // 0xdead
							Protocol:      testOpts.protocol,
							InterfaceName: "eth30",
							MTU:           1500, // Need to match host MTU or felix will restart.
						}
						err = eth30.Start()
						Expect(err).NotTo(HaveOccurred())

						// assign address to eth30 and add route to the .30 network
						if testOpts.ipv6 {
							tc.Felixes[1].Exec("ip", "-6", "route", "add", eth30Route, "dev", "eth30")
							tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth30ExtIP+"/"+mask, "dev", "eth30")
							_, err = eth30.RunCmd("ip", "-6", "route", "add", eth30ExtIP+"/"+mask, "dev", "eth0")
							Expect(err).NotTo(HaveOccurred())
							// Add a route to the test workload to the fake external
							// client emulated by the test-workload
							_, err = eth30.RunCmd("ip", "-6", "route", "add", w[1][1].IP+"/"+mask, "via", eth30ExtIP)
							Expect(err).NotTo(HaveOccurred())
						} else {
							tc.Felixes[1].Exec("ip", "route", "add", eth30Route, "dev", "eth30")
							tc.Felixes[1].Exec("ip", "addr", "add", eth30ExtIP+"/"+mask, "dev", "eth30")
							_, err = eth30.RunCmd("ip", "route", "add", eth30ExtIP+"/"+mask, "dev", "eth0")
							Expect(err).NotTo(HaveOccurred())
							// Add a route to the test workload to the fake external
							// client emulated by the test-workload
							_, err = eth30.RunCmd("ip", "route", "add", w[1][1].IP+"/"+mask, "via", eth30ExtIP)
							Expect(err).NotTo(HaveOccurred())
						}

						// Make sure Felix adds a BPF program before we run the test, otherwise the conntrack
						// may be crated in the reverse direction.  Since we're pretending to be a host interface
						// Felix doesn't block traffic by default.
						Eventually(tc.Felixes[1].NumTCBPFProgsFn("eth20"), "30s", "200ms").Should(Equal(2))
						Eventually(tc.Felixes[1].NumTCBPFProgsFn("eth30"), "30s", "200ms").Should(Equal(2))

						// Make sure that networking with the .20 and .30 networks works
						cc.ResetExpectations()
						cc.ExpectSome(w[1][1], TargetIP(eth20.IP), 0xdead)
						cc.ExpectSome(w[1][1], TargetIP(eth30.IP), 0xdead)
						cc.CheckConnectivity()
					})

					By("testing that external traffic updates the RPF check if routing changes", func() {
						// set the route to the fake workload to .20 network
						if testOpts.ipv6 {
							tc.Felixes[1].Exec("ip", "-6", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth20")
						} else {
							tc.Felixes[1].Exec("ip", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth20")
						}

						tcpdump := w[1][1].AttachTCPDump()
						tcpdump.SetLogEnabled(true)
						matcher := fmt.Sprintf("%s %s\\.30446 > %s\\.30446: UDP", ipVer, fakeWorkloadIP, w[1][1].IP)
						tcpdump.AddMatcher("UDP-30446", regexp.MustCompile(matcher))
						tcpdump.Start()
						defer tcpdump.Stop()

						_, err := eth20.RunCmd("pktgen", fakeWorkloadIP, w[1][1].IP, "udp",
							"--port-src", "30446", "--port-dst", "30446")
						Expect(err).NotTo(HaveOccurred())

						// Expect to receive the packet from the .20 as the routing is correct
						Eventually(func() int { return tcpdump.MatchCount("UDP-30446") }).
							Should(BeNumerically("==", 1), matcher)

						ctBefore := dumpCTMapsAny(family, tc.Felixes[1])

						var k conntrack.KeyInterface
						if testOpts.ipv6 {
							k = conntrack.NewKeyV6(17, net.ParseIP(w[1][1].IP).To16(), 30446,
								net.ParseIP(fakeWorkloadIP).To16(), 30446)
						} else {
							k = conntrack.NewKey(17, net.ParseIP(w[1][1].IP).To4(), 30446,
								net.ParseIP(fakeWorkloadIP).To4(), 30446)
						}
						Expect(ctBefore).To(HaveKey(k))

						// XXX Since the same code is used to do the drop of spoofed
						// packet between pods, we do not repeat it here as it is not 100%
						// bulletproof.
						//
						// We should perhaps compare the iptables counter and see if the
						// packet was dropped by the RPF check.

						// Change the routing to be from the .30
						if testOpts.ipv6 {
							tc.Felixes[1].Exec("ip", "-6", "route", "del", fakeWorkloadIP+"/"+mask, "dev", "eth20")
							tc.Felixes[1].Exec("ip", "-6", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth30")
						} else {
							tc.Felixes[1].Exec("ip", "route", "del", fakeWorkloadIP+"/"+mask, "dev", "eth20")
							tc.Felixes[1].Exec("ip", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth30")
						}

						_, err = eth30.RunCmd("pktgen", fakeWorkloadIP, w[1][1].IP, "udp",
							"--port-src", "30446", "--port-dst", "30446")
						Expect(err).NotTo(HaveOccurred())

						// Expect the packet from the .30 to make it through as RPF will
						// allow it and we will update the expected interface
						Eventually(func() int { return tcpdump.MatchCount("UDP-30446") }).
							Should(BeNumerically("==", 2), matcher)

						ctAfter := dumpCTMapsAny(family, tc.Felixes[1])
						Expect(ctAfter).To(HaveKey(k))

						// Ifindex must have changed
						// B2A because of IPA > IPB - deterministic
						Expect(ctBefore[k].Data().B2A.Ifindex).NotTo(BeNumerically("==", 0),
							"Expected 'before' conntrack B2A ifindex to be set")
						Expect(ctAfter[k].Data().B2A.Ifindex).NotTo(BeNumerically("==", 0),
							"Expected 'after' conntrack B2A ifindex to be set")
						Expect(ctBefore[k].Data().B2A.Ifindex).
							NotTo(BeNumerically("==", ctAfter[k].Data().B2A.Ifindex))
					})
				})
			}
		})
	})
}

func typeMetaV1(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       kind,
		APIVersion: "v1",
	}
}

func objectMetaV1(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: "default",
	}
}

func dumpNATmaps(felixes []*infrastructure.Felix) ([]nat.MapMem, []nat.BackendMapMem) {
	bpfsvcs := make([]nat.MapMem, len(felixes))
	bpfeps := make([]nat.BackendMapMem, len(felixes))

	// Felixes are independent, we can dump the maps  concurrently
	var wg sync.WaitGroup

	for i := range felixes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer GinkgoRecover()
			bpfsvcs[i], bpfeps[i] = dumpNATMaps(felixes[i])
		}(i)
	}

	wg.Wait()

	return bpfsvcs, bpfeps
}

func dumpNATmapsAny(family int, felixes []*infrastructure.Felix) (
	[]map[nat.FrontendKeyInterface]nat.FrontendValue, []map[nat.BackendKey]nat.BackendValueInterface) {

	bpfsvcs := make([]map[nat.FrontendKeyInterface]nat.FrontendValue, len(felixes))
	bpfeps := make([]map[nat.BackendKey]nat.BackendValueInterface, len(felixes))

	// Felixes are independent, we can dump the maps  concurrently
	var wg sync.WaitGroup

	for i := range felixes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer GinkgoRecover()
			bpfsvcs[i], bpfeps[i] = dumpNATMapsAny(family, felixes[i])
		}(i)
	}

	wg.Wait()

	return bpfsvcs, bpfeps
}

func dumpNATmapsV6(felixes []*infrastructure.Felix) ([]nat.MapMemV6, []nat.BackendMapMemV6) {
	bpfsvcs := make([]nat.MapMemV6, len(felixes))
	bpfeps := make([]nat.BackendMapMemV6, len(felixes))

	// Felixes are independent, we can dump the maps  concurrently
	var wg sync.WaitGroup

	for i := range felixes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer GinkgoRecover()
			bpfsvcs[i], bpfeps[i] = dumpNATMapsV6(felixes[i])
		}(i)
	}

	wg.Wait()

	return bpfsvcs, bpfeps
}

func dumpNATMaps(felix *infrastructure.Felix) (nat.MapMem, nat.BackendMapMem) {
	return dumpNATMap(felix), dumpEPMap(felix)
}

func dumpNATMapsV6(felix *infrastructure.Felix) (nat.MapMemV6, nat.BackendMapMemV6) {
	return dumpNATMapV6(felix), dumpEPMapV6(felix)
}

func dumpNATMapsAny(family int, felix *infrastructure.Felix) (
	map[nat.FrontendKeyInterface]nat.FrontendValue,
	map[nat.BackendKey]nat.BackendValueInterface) {

	f := make(map[nat.FrontendKeyInterface]nat.FrontendValue)
	b := make(map[nat.BackendKey]nat.BackendValueInterface)

	if family == 6 {
		f6, b6 := dumpNATMapsV6(felix)
		for k, v := range f6 {
			f[k] = v
		}
		for k, v := range b6 {
			b[k] = v
		}
	} else {
		f4, b4 := dumpNATMaps(felix)
		for k, v := range f4 {
			f[k] = v
		}
		for k, v := range b4 {
			b[k] = v
		}
	}

	return f, b
}

func dumpCTMapsAny(family int, felix *infrastructure.Felix) map[conntrack.KeyInterface]conntrack.ValueInterface {
	m := make(map[conntrack.KeyInterface]conntrack.ValueInterface)

	if family == 4 {
		ctMap := dumpCTMap(felix)
		for k, v := range ctMap {
			m[k] = v
		}
	} else {
		ctMap := dumpCTMapV6(felix)
		for k, v := range ctMap {
			m[k] = v
		}
	}
	return m
}

func dumpBPFMap(felix *infrastructure.Felix, m maps.Map, iter func(k, v []byte)) {
	// Wait for the map to exist before trying to access it.  Otherwise, we
	// might fail a test that was retrying this dump anyway.
	Eventually(func() bool {
		return felix.FileExists(m.Path())
	}, "10s", "300ms").Should(BeTrue(), fmt.Sprintf("dumpBPFMap: map %s didn't show up inside container", m.Path()))
	cmd, err := maps.DumpMapCmd(m)
	Expect(err).NotTo(HaveOccurred(), "Failed to get BPF map dump command: "+m.Path())
	log.WithField("cmd", cmd).Debug("dumpBPFMap")
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred(), "Failed to get dump BPF map: "+m.Path())
	if strings.Contains(m.(*maps.PinnedMap).Type, "percpu") {
		err = bpf.IterPerCpuMapCmdOutput([]byte(out), iter)
	} else {
		err = bpf.IterMapCmdOutput([]byte(out), iter)
	}
	Expect(err).NotTo(HaveOccurred(), "Failed to parse BPF map dump: "+m.Path())
}

func dumpNATMap(felix *infrastructure.Felix) nat.MapMem {
	bm := nat.FrontendMap()
	m := make(nat.MapMem)
	dumpBPFMap(felix, bm, nat.MapMemIter(m))
	return m
}

func dumpEPMap(felix *infrastructure.Felix) nat.BackendMapMem {
	bm := nat.BackendMap()
	m := make(nat.BackendMapMem)
	dumpBPFMap(felix, bm, nat.BackendMapMemIter(m))
	return m
}

func dumpNATMapV6(felix *infrastructure.Felix) nat.MapMemV6 {
	bm := nat.FrontendMapV6()
	m := make(nat.MapMemV6)
	dumpBPFMap(felix, bm, nat.MapMemV6Iter(m))
	return m
}

func dumpEPMapV6(felix *infrastructure.Felix) nat.BackendMapMemV6 {
	bm := nat.BackendMapV6()
	m := make(nat.BackendMapMemV6)
	dumpBPFMap(felix, bm, nat.BackendMapMemV6Iter(m))
	return m
}

func dumpAffMap(felix *infrastructure.Felix) nat.AffinityMapMem {
	bm := nat.AffinityMap()
	m := make(nat.AffinityMapMem)
	dumpBPFMap(felix, bm, nat.AffinityMapMemIter(m))
	return m
}

func dumpAffMapV6(felix *infrastructure.Felix) nat.AffinityMapMemV6 {
	bm := nat.AffinityMapV6()
	m := make(nat.AffinityMapMemV6)
	dumpBPFMap(felix, bm, nat.AffinityMapMemV6Iter(m))
	return m
}

func dumpCTMap(felix *infrastructure.Felix) conntrack.MapMem {
	bm := conntrack.Map()
	m := make(conntrack.MapMem)
	dumpBPFMap(felix, bm, conntrack.MapMemIter(m))
	return m
}

func dumpCTMapV6(felix *infrastructure.Felix) conntrack.MapMemV6 {
	bm := conntrack.MapV6()
	m := make(conntrack.MapMemV6)
	dumpBPFMap(felix, bm, conntrack.MapMemIterV6(m))
	return m
}

func dumpSendRecvMap(felix *infrastructure.Felix) nat.SendRecvMsgMapMem {
	bm := nat.SendRecvMsgMap()
	m := make(nat.SendRecvMsgMapMem)
	dumpBPFMap(felix, bm, nat.SendRecvMsgMapMemIter(m))
	return m
}

func dumpSendRecvMapV6(felix *infrastructure.Felix) nat.SendRecvMsgMapMemV6 {
	bm := nat.SendRecvMsgMapV6()
	m := make(nat.SendRecvMsgMapMemV6)
	dumpBPFMap(felix, bm, nat.SendRecvMsgMapMemV6Iter(m))
	return m
}

func dumpIfStateMap(felix *infrastructure.Felix) ifstate.MapMem {
	im := ifstate.Map()
	m := make(ifstate.MapMem)
	dumpBPFMap(felix, im, ifstate.MapMemIter(m))
	return m
}

func ensureAllNodesBPFProgramsAttached(felixes []*infrastructure.Felix) {
	for _, felix := range felixes {
		ensureBPFProgramsAttachedOffset(2, felix)
	}
}

func ensureBPFProgramsAttached(felix *infrastructure.Felix, ifacesExtra ...string) {
	ensureBPFProgramsAttachedOffset(2, felix, ifacesExtra...)
}

func ensureBPFProgramsAttachedOffset(offset int, felix *infrastructure.Felix, ifacesExtra ...string) {
	expectedIfaces := []string{"eth0"}
	if felix.ExpectedIPIPTunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "tunl0")
	}
	if felix.ExpectedVXLANTunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "vxlan.calico")
	}
	if felix.ExpectedVXLANV6TunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "vxlan-v6.calico")
	}
	if felix.ExpectedWireguardTunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "wireguard.cali")
	}
	if felix.ExpectedWireguardV6TunnelAddr != "" {
		expectedIfaces = append(expectedIfaces, "wg-v6.cali")
	}

	for _, w := range felix.Workloads {
		if w.Runs() {
			if iface := w.GetInterfaceName(); iface != "" {
				expectedIfaces = append(expectedIfaces, iface)
			}
			if iface := w.GetSpoofInterfaceName(); iface != "" {
				expectedIfaces = append(expectedIfaces, iface)
			}
		}
	}

	expectedIfaces = append(expectedIfaces, ifacesExtra...)
	ensureBPFProgramsAttachedOffsetWithIPVersion(offset+1, felix,
		true, felix.TopologyOptions.EnableIPv6,
		expectedIfaces...)
}

func ensureBPFProgramsAttachedOffsetWithIPVersion(offset int, felix *infrastructure.Felix, v4, v6 bool, ifaces ...string) {
	var expFlgs uint32

	if v4 {
		expFlgs |= ifstate.FlgIPv4Ready
	}
	if v6 {
		expFlgs |= ifstate.FlgIPv6Ready
	}

	EventuallyWithOffset(offset, func() []string {
		prog := []string{}
		m := dumpIfStateMap(felix)
		for _, v := range m {
			flags := v.Flags()
			if (flags & (ifstate.FlgIPv6Ready | ifstate.FlgIPv4Ready)) == expFlgs {
				prog = append(prog, v.IfName())
			}
		}
		return prog
	}, "1m", "1s").Should(ContainElements(ifaces))
}

func k8sService(name, clusterIP string, w *workload.Workload, port,
	tgtPort int, nodePort int32, protocol string) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	svcType := v1.ServiceTypeClusterIP
	if nodePort != 0 {
		svcType = v1.ServiceTypeNodePort
	}

	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP: clusterIP,
			Type:      svcType,
			Selector: map[string]string{
				"name": w.Name,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
					NodePort:   nodePort,
					Name:       fmt.Sprintf("port-%d", tgtPort),
					TargetPort: intstr.FromInt(tgtPort),
				},
			},
		},
	}
}

func k8sLBService(name, clusterIP string, wname string, port,
	tgtPort int, protocol string, externalIPs, srcRange []string) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	svcType := v1.ServiceTypeLoadBalancer
	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP:                clusterIP,
			Type:                     svcType,
			LoadBalancerSourceRanges: srcRange,
			ExternalIPs:              externalIPs,
			Selector: map[string]string{
				"name": wname,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
					Name:       fmt.Sprintf("port-%d", tgtPort),
					TargetPort: intstr.FromInt(tgtPort),
				},
			},
		},
	}
}

func k8sServiceWithExtIP(name, clusterIP string, w *workload.Workload, port,
	tgtPort int, nodePort int32, protocol string, externalIPs []string) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	svcType := v1.ServiceTypeClusterIP
	if nodePort != 0 {
		svcType = v1.ServiceTypeNodePort
	}
	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP:   clusterIP,
			Type:        svcType,
			ExternalIPs: externalIPs,
			Selector: map[string]string{
				"name": w.Name,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
					NodePort:   nodePort,
					Name:       fmt.Sprintf("port-%d", tgtPort),
					TargetPort: intstr.FromInt(tgtPort),
				},
			},
		},
	}
}

func k8sGetEpsForService(k8s kubernetes.Interface, svc *v1.Service) []v1.EndpointSubset {
	ep, _ := k8s.CoreV1().
		Endpoints(svc.ObjectMeta.Namespace).
		Get(context.Background(), svc.ObjectMeta.Name, metav1.GetOptions{})
	log.WithField("endpoints",
		spew.Sprint(ep)).Infof("Got endpoints for %s", svc.ObjectMeta.Name)
	return ep.Subsets
}

func k8sGetEpsForServiceFunc(k8s kubernetes.Interface, svc *v1.Service) func() []v1.EndpointSubset {
	return func() []v1.EndpointSubset {
		return k8sGetEpsForService(k8s, svc)
	}
}

func k8sUpdateService(k8sClient kubernetes.Interface, nameSpace, svcName string, oldsvc, newsvc *v1.Service) {
	svc, err := k8sClient.CoreV1().
		Services(nameSpace).
		Get(context.Background(), svcName, metav1.GetOptions{})
	log.WithField("origSvc", svc).Info("Read original service before updating it")
	newsvc.ObjectMeta.ResourceVersion = svc.ObjectMeta.ResourceVersion
	_, err = k8sClient.CoreV1().Services(nameSpace).Update(context.Background(), newsvc, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
	Eventually(k8sGetEpsForServiceFunc(k8sClient, oldsvc), "10s").Should(HaveLen(1),
		"Service endpoints didn't get created? Is controller-manager happy?")

	updatedSvc, err := k8sClient.CoreV1().Services(nameSpace).Get(context.Background(), svcName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	log.WithField("updatedSvc", updatedSvc).Info("Read back updated Service")
}

func k8sCreateLBServiceWithEndPoints(k8sClient kubernetes.Interface, name, clusterIP string, w *workload.Workload, port,
	tgtPort int, protocol string, externalIPs, srcRange []string) *v1.Service {
	var (
		testSvc          *v1.Service
		testSvcNamespace string
		epslen           int
	)
	if w != nil {
		testSvc = k8sLBService(name, clusterIP, w.Name, port, tgtPort, protocol, externalIPs, srcRange)
		epslen = 1
	} else {
		testSvc = k8sLBService(name, clusterIP, "nobackend", port, tgtPort, protocol, externalIPs, srcRange)
		epslen = 0
	}
	testSvcNamespace = testSvc.ObjectMeta.Namespace
	_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(epslen),
		"Service endpoints didn't get created? Is controller-manager happy?")
	return testSvc
}

func checkNodeConntrack(felixes []*infrastructure.Felix) error {

	for i, felix := range felixes {
		conntrackOut, err := felix.ExecOutput("conntrack", "-L")
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "conntrack -L failed")
		lines := strings.Split(conntrackOut, "\n")
	lineLoop:
		for _, line := range lines {
			line = strings.Trim(line, " ")
			if strings.Contains(line, "src=") {
				// Whether traffic is generated in host namespace, or involves NAT, each
				// conntrack entry should be related to node's address
				if strings.Contains(line, felix.GetIP()) {
					continue lineLoop
				}
				if strings.Contains(line, felix.IPv6) {
					continue lineLoop
				}
				if felix.ExpectedIPIPTunnelAddr != "" && strings.Contains(line, felix.ExpectedIPIPTunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedVXLANTunnelAddr != "" && strings.Contains(line, felix.ExpectedVXLANTunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedWireguardTunnelAddr != "" && strings.Contains(line, felix.ExpectedWireguardTunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedVXLANV6TunnelAddr != "" && strings.Contains(line, felix.ExpectedVXLANV6TunnelAddr) {
					continue lineLoop
				}
				if felix.ExpectedWireguardV6TunnelAddr != "" && strings.Contains(line, felix.ExpectedWireguardV6TunnelAddr) {
					continue lineLoop
				}
				// Ignore DHCP
				if strings.Contains(line, "sport=67 dport=68") {
					continue lineLoop
				}
				// Ignore any flows that come from the host itself.  For example, some programs send
				// broadcast probe packets on all interfaces they can see. (Spotify, for example.)
				myAddrs, err := net.InterfaceAddrs()
				Expect(err).NotTo(HaveOccurred())
				for _, a := range myAddrs {
					if strings.Contains(line, a.String()) {
						continue lineLoop
					}
				}
				return fmt.Errorf("unexpected conntrack not from host (felix[%d]): %s", i, line)
			}
		}
	}

	return nil
}

func conntrackCheck(felixes []*infrastructure.Felix) func() error {
	return func() error {
		return checkNodeConntrack(felixes)
	}
}

func conntrackFlushWorkloadEntries(felixes []*infrastructure.Felix) func() {
	return func() {
		for _, felix := range felixes {
			for _, w := range felix.Workloads {
				wIP := w.GetIP()
				if wIP == felix.GetIP() || wIP == felix.GetIPv6() {
					continue // Skip host-networked workloads.
				}
				for _, dirn := range []string{"--orig-src", "--orig-dst", "--reply-dst", "--reply-src"} {
					err := felix.ExecMayFail("conntrack", "-D", dirn, w.GetIP())
					if err != nil && strings.Contains(err.Error(), "0 flow entries have been deleted") {
						// Expected "error" when there are no matching flows.
						continue
					}
					ExpectWithOffset(1, err).NotTo(HaveOccurred(), "conntrack -D failed")
				}
			}
		}
	}
}

func conntrackChecks(felixes []*infrastructure.Felix) []interface{} {
	return []interface{}{
		CheckWithInit(conntrackFlushWorkloadEntries(felixes)),
		CheckWithFinalTest(conntrackCheck(felixes)),
		CheckWithBeforeRetry(conntrackFlushWorkloadEntries(felixes)),
	}
}

func setRPF(felixes []*infrastructure.Felix, tunnel string, all, main int) {
	allStr := strconv.Itoa(all)
	mainStr := strconv.Itoa(main)

	var wg sync.WaitGroup

	for _, felix := range felixes {
		wg.Add(1)
		go func(felix *infrastructure.Felix) {
			defer wg.Done()
			Eventually(func() error {
				// N.B. we only support environment with not so strict RPF - can be
				// strict per iface, but not for all.
				if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.all.rp_filter="+allStr); err != nil {
					return err
				}
				switch tunnel {
				case "none":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter="+mainStr); err != nil {
						return err
					}
				case "ipip":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.tunl0.rp_filter="+mainStr); err != nil {
						return err
					}
				case "wireguard":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.wireguard/cali.rp_filter="+mainStr); err != nil {
						return err
					}
				case "vxlan":
					if err := felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.vxlan/calico.rp_filter="+mainStr); err != nil {
						return err
					}
				}

				return nil
			}, "5s", "200ms").Should(Succeed())
		}(felix)
	}

	wg.Wait()
}

func checkServiceRoute(felix *infrastructure.Felix, ip string) bool {
	var (
		out string
		err error
	)

	if felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("ip", "-6", "route")
	} else {
		out, err = felix.ExecOutput("ip", "route")
	}
	Expect(err).NotTo(HaveOccurred())

	lines := strings.Split(out, "\n")
	rtRE := regexp.MustCompile(ip + " .* dev bpfin.cali")

	for _, l := range lines {
		if rtRE.MatchString(l) {
			return true
		}
	}

	return false
}

func bpfCheckIfPolicyProgrammed(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool) bool {
	startStr := fmt.Sprintf("Start of policy %s", polName)
	endStr := fmt.Sprintf("End of policy %s", polName)
	actionStr := fmt.Sprintf("Start of rule action:\"%s\"", action)
	var policyDbg bpf.PolicyDebugInfo
	out, err := felix.ExecOutput("cat", bpf.PolicyDebugJSONFileName(iface, hook, proto.IPVersion_IPV4))
	if err != nil {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	err = dec.Decode(&policyDbg)
	if err != nil {
		return false
	}

	hookStr := "tc ingress"
	if isWorkload {
		if hook == "ingress" {
			hookStr = "tc egress"
		}
	} else {
		if hook == "egress" {
			hookStr = "tc egress"
		}
	}
	if policyDbg.IfaceName != iface || policyDbg.Hook != hookStr || policyDbg.Error != "" {
		return false
	}

	startOfPolicy := false
	endOfPolicy := false
	actionMatch := false
	for _, insn := range policyDbg.PolicyInfo {
		for _, comment := range insn.Comments {
			if strings.Contains(comment, startStr) {
				startOfPolicy = true
			}
			if strings.Contains(comment, actionStr) && startOfPolicy && !endOfPolicy {
				actionMatch = true
			}
			if startOfPolicy && strings.Contains(comment, endStr) {
				endOfPolicy = true
			}
		}
	}

	return (startOfPolicy && endOfPolicy && actionMatch)
}

func bpfDumpPolicy(felix *infrastructure.Felix, iface, hook string) string {
	var (
		out string
		err error
	)

	if felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("calico-bpf", "-6", "policy", "dump", iface, hook, "--asm")
	} else {
		out, err = felix.ExecOutput("calico-bpf", "policy", "dump", iface, hook, "--asm")
	}
	Expect(err).NotTo(HaveOccurred())
	return out
}

func bpfWaitForPolicy(felix *infrastructure.Felix, iface, hook, policy string) string {
	search := fmt.Sprintf("Start of policy %s", policy)
	out := ""
	EventuallyWithOffset(1, func() string {
		out = bpfDumpPolicy(felix, iface, hook)
		return out
	}, "5s", "200ms").Should(ContainSubstring(search))

	return out
}

func bpfDumpRoutes(felix *infrastructure.Felix) string {
	var (
		out string
		err error
	)

	if felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("calico-bpf", "-6", "routes", "dump")
	} else {
		out, err = felix.ExecOutput("calico-bpf", "routes", "dump")
	}
	Expect(err).NotTo(HaveOccurred())
	return out
}
