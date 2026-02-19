// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf/nat"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/tcpdump"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
)

// We run with and without connection-time load balancing for a couple of reasons:
//   - We can only test the non-connection time NAT logic (and node ports) with it disabled.
//   - Since the connection time program applies to the whole host, the different felix nodes actually share the
//     connection-time program.  This is a bit of a broken test but it's better than nothing since all felix nodes
//     should be programming the same NAT mappings.
var (
	_ = describeBPFTests(withProto("tcp"), withConnTimeLoadBalancingEnabled(), withNonProtocolDependentTests())
	_ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled())
	_ = describeBPFTests(withProto("tcp"), withConnTimeLoadBalancingEnabled(), withNonProtocolDependentTests(), withIPFamily(6))
	_ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled(), withIPFamily(6))
	_ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled(), withUDPUnConnected())
	_ = describeBPFTests(withProto("tcp"))
	_ = describeBPFTests(withProto("tcp"), withIPFamily(6))
	_ = describeBPFTests(withProto("udp"))
	_ = describeBPFTests(withProto("udp"), withUDPUnConnected())
	_ = describeBPFTests(withProto("udp"), withUDPConnectedRecvMsg(), withConnTimeLoadBalancingEnabled())
	_ = describeBPFTests(withTunnel("ipip"), withProto("tcp"), withConnTimeLoadBalancingEnabled())
	_ = describeBPFTests(withTunnel("ipip"), withProto("udp"), withConnTimeLoadBalancingEnabled())
	_ = describeBPFTests(withTunnel("ipip"), withProto("tcp"))
	_ = describeBPFTests(withTunnel("ipip"), withProto("udp"))
	_ = describeBPFTests(withProto("tcp"), withDSR())
	_ = describeBPFTests(withProto("udp"), withDSR())
	_ = describeBPFTests(withTunnel("ipip"), withProto("tcp"), withDSR())
	_ = describeBPFTests(withTunnel("ipip"), withProto("udp"), withDSR())
	_ = describeBPFTests(withTunnel("wireguard"), withProto("tcp"))
	_ = describeBPFTests(withTunnel("wireguard"), withProto("tcp"), withConnTimeLoadBalancingEnabled())
	_ = describeBPFTests(withTunnel("vxlan"), withProto("tcp"))
	_ = describeBPFTests(withTunnel("vxlan"), withProto("tcp"), withConnTimeLoadBalancingEnabled())
	_ = describeBPFTests(withTunnel("vxlan"), withProto("tcp"), withConnTimeLoadBalancingEnabled(), withIPFamily(6))
)

// Run a stripe of tests with BPF logging disabled since the compiler tends to optimise the code differently
// with debug disabled and that can lead to verifier issues.
var _ = describeBPFTests(withProto("tcp"),
	withConnTimeLoadBalancingEnabled(),
	withBPFLogLevel("off"))

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
FELIX_0/32: local host idx -
FELIX_1/32: remote host
FELIX_2/32: remote host`

const expectedRouteDumpV6 = `111:222::1/128: local host
111:222::1:1/128: remote host
111:222::2:1/128: remote host
FELIX_0/128: local host idx -
FELIX_1/128: remote host
FELIX_2/128: remote host
dead:beef::/64: remote in-pool nat-out
dead:beef::1:0/122: remote workload in-pool nat-out nh FELIX_1
dead:beef::2/128: local workload in-pool nat-out idx -
dead:beef::2:0/122: remote workload in-pool nat-out nh FELIX_2
dead:beef::3/128: local workload in-pool nat-out idx -`

const expectedRouteDumpV6DSR = `111:222::1/128: local host
111:222::1:1/128: remote host
111:222::2:1/128: remote host
FELIX_0/128: local host idx -
FELIX_1/128: remote host
FELIX_2/128: remote host
beaf::/64: remote no-dsr
dead:beef::/64: remote in-pool nat-out
dead:beef::1:0/122: remote workload in-pool nat-out nh FELIX_1
dead:beef::2/128: local workload in-pool nat-out idx -
dead:beef::2:0/122: remote workload in-pool nat-out nh FELIX_2
dead:beef::3/128: local workload in-pool nat-out idx -`

const expectedRouteDumpWithTunnelAddr = `10.65.0.0/16: remote in-pool nat-out
10.65.0.2/32: local workload in-pool nat-out idx -
10.65.0.3/32: local workload in-pool nat-out idx -
10.65.1.0/26: remote workload in-pool nat-out tunneled nh FELIX_1
10.65.2.0/26: remote workload in-pool nat-out tunneled nh FELIX_2
111.222.0.1/32: local host
111.222.1.1/32: remote host
111.222.2.1/32: remote host
FELIX_0/32: local host idx -
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
FELIX_0/32: local host idx -
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
FELIX_0/32: local host idx -
FELIX_0_TNL/32: local host
FELIX_1/32: remote host
FELIX_1_TNL/32: remote host in-pool nat-out tunneled
FELIX_2/32: remote host
FELIX_2_TNL/32: remote host in-pool nat-out tunneled`

func BPFMode() bool {
	return os.Getenv("FELIX_FV_ENABLE_BPF") == "true"
}

func BPFAttachType() string {
	return strings.ToLower(os.Getenv("FELIX_FV_BPFATTACHTYPE"))
}

const numNodes = 3

// bpfTestContext holds the shared state for BPF tests, replacing closure variables.
type bpfTestContext struct {
	testOpts       bpfTestOptions
	infra          infrastructure.DatastoreInfra
	tc             infrastructure.TopologyContainers
	calicoClient   client.Interface
	cc             *Checker
	externalClient *containers.Container
	deadWorkload   *workload.Workload
	options        infrastructure.TopologyOptions
	numericProto   uint8
	w              [numNodes][2]*workload.Workload
	hostW          [numNodes]*workload.Workload
	getInfra       infrastructure.InfraFactory

	// Set up inside the policy Context's BeforeEach
	pol       *api.GlobalNetworkPolicy
	k8sClient *kubernetes.Clientset

	// Derived convenience fields
	testIfTCP              bool
	testIfNotUDPUConnected bool
	family                 string
}

func (s *bpfTestContext) containerIP(c *containers.Container) string {
	if s.testOpts.ipv6 {
		return c.IPv6
	}
	return c.IP
}

func (s *bpfTestContext) felixIP(f int) string {
	return s.containerIP(s.tc.Felixes[f].Container)
}

func (s *bpfTestContext) ipMask() string {
	if s.testOpts.ipv6 {
		return "128"
	}
	return "32"
}

func (s *bpfTestContext) createPolicy(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
	log.WithField("policy", dumpResource(policy)).Info("Creating policy")
	policy, err := s.calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
	Expect(err).NotTo(HaveOccurred())
	return policy
}

func (s *bpfTestContext) updatePolicy(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
	log.WithField("policy", dumpResource(policy)).Info("Updating policy")
	policy, err := s.calicoClient.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
	Expect(err).NotTo(HaveOccurred())
	return policy
}

func (s *bpfTestContext) setupCluster() {
	s.tc, s.calicoClient = infrastructure.StartNNodeTopology(numNodes, s.options, s.infra)

	addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
		if labels == nil {
			labels = make(map[string]string)
		}

		wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
		if s.testOpts.ipv6 {
			wIP = net.ParseIP(fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)).String()
		}
		wName := fmt.Sprintf("w%d%d", ii, wi)

		if s.options.UseIPPools {
			infrastructure.AssignIP(wName, wIP, s.tc.Felixes[ii].Hostname, s.calicoClient)
		}
		w := workload.New(s.tc.Felixes[ii], wName, "default",
			wIP, strconv.Itoa(port), s.testOpts.protocol)

		labels["name"] = w.Name
		labels["workload"] = "regular"

		w.WorkloadEndpoint.Labels = labels
		if run {
			err := w.Start(s.infra)
			Expect(err).NotTo(HaveOccurred())
			w.ConfigureInInfra(s.infra)
		}
		return w
	}

	// Start a host networked workload on each host for connectivity checks.
	for ii := range s.tc.Felixes {
		// We tell each host-networked workload to open:
		// TODO: Copied from another test
		// - its normal (uninteresting) port, 8055
		// - port 2379, which is both an inbound and an outbound failsafe port
		// - port 22, which is an inbound failsafe port.
		// This allows us to test the interaction between do-not-track policy and failsafe
		// ports.
		s.hostW[ii] = workload.Run(
			s.tc.Felixes[ii],
			fmt.Sprintf("host%d", ii),
			"default",
			s.felixIP(ii), // Same IP as felix means "run in the host's namespace"
			"8055",
			s.testOpts.protocol)

		s.hostW[ii].WorkloadEndpoint.Labels = map[string]string{"name": s.hostW[ii].Name}
		s.hostW[ii].ConfigureInInfra(s.infra)

		// Two workloads on each host so we can check the same host and other host cases.
		s.w[ii][0] = addWorkload(true, ii, 0, 8055, map[string]string{"port": "8055"})
		s.w[ii][1] = addWorkload(true, ii, 1, 8056, nil)
	}

	// Create a workload on node 0 that does not run, but we can use it to set up paths
	s.deadWorkload = addWorkload(false, 0, 2, 8057, nil)

	// We will use this container to model an external client trying to connect into
	// workloads on a host.  Create a route in the container for the workload CIDR.
	// TODO: Copied from another test
	s.externalClient = infrastructure.RunExtClientWithOpts(s.infra, "ext-client", infrastructure.ExtClientOpts{
		IPv6Enabled: s.testOpts.ipv6,
	})
	_ = s.externalClient

	err := s.infra.AddDefaultDeny()
	Expect(err).NotTo(HaveOccurred())
	if !s.options.TestManagesBPF {
		ensureAllNodesBPFProgramsAttached(s.tc.Felixes)
		for _, f := range s.tc.Felixes {
			felixReady := func() int {
				return healthStatus(s.containerIP(f.Container), "9099", "readiness")
			}
			Eventually(felixReady, "10s", "500ms").Should(BeGood())
		}
	}
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
		s := &bpfTestContext{
			testOpts:               testOpts,
			testIfTCP:              testIfTCP,
			testIfNotUDPUConnected: testIfNotUDPUConnected,
			family:                 family,
			getInfra:               getInfra,
		}

		switch testOpts.protocol {
		case "tcp":
			s.numericProto = 6
		case "udp":
			s.numericProto = 17
		default:
			Fail("bad protocol option")
		}

		BeforeEach(func() {
			iOpts := []infrastructure.CreateOption{}
			if s.testOpts.ipv6 {
				iOpts = append(iOpts,
					infrastructure.K8sWithIPv6(),
					infrastructure.K8sWithAPIServerBindAddress("::"),
					infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112"),
				)
			}

			s.infra = s.getInfra(iOpts...)

			s.cc = &Checker{
				CheckSNAT: true,
			}
			s.cc.Protocol = s.testOpts.protocol
			if s.testOpts.protocol == "udp" && s.testOpts.udpUnConnected {
				s.cc.Protocol += "-noconn"
			}
			if s.testOpts.protocol == "udp" && s.testOpts.udpConnRecvMsg {
				s.cc.Protocol += "-recvmsg"
			}

			s.options = infrastructure.DefaultTopologyOptions()
			s.options.EnableIPv6 = s.testOpts.ipv6
			s.options.FelixLogSeverity = "Debug"
			s.options.NATOutgoingEnabled = true
			s.options.AutoHEPsEnabled = true
			// override IPIP being enabled by default
			s.options.IPIPMode = api.IPIPModeNever
			switch s.testOpts.tunnel {
			case "none":
				// Felix must program unencap routes.
			case "ipip":
				s.options.IPIPStrategy = infrastructure.NewDefaultTunnelStrategy(s.options.IPPoolCIDR, s.options.IPv6PoolCIDR)
				s.options.IPIPMode = api.IPIPModeAlways
				if s.testOpts.ipv6 {
					s.options.SimulateBIRDRoutes = true
					s.options.ExtraEnvVars["FELIX_ProgramClusterRoutes"] = "Disabled"
				}
			case "vxlan":
				s.options.VXLANMode = api.VXLANModeAlways
				s.options.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(s.options.IPPoolCIDR, s.options.IPv6PoolCIDR)
			case "wireguard":
				if s.testOpts.ipv6 {
					// Allocate tunnel address for Wireguard.
					s.options.WireguardEnabledV6 = true
					// Enable Wireguard.
					s.options.ExtraEnvVars["FELIX_WIREGUARDENABLEDV6"] = "true"
				} else {
					// Allocate tunnel address for Wireguard.
					s.options.WireguardEnabled = true
					// Enable Wireguard.
					s.options.ExtraEnvVars["FELIX_WIREGUARDENABLED"] = "true"
				}
			default:
				Fail("bad tunnel option")
			}
			if s.testOpts.tunnel != "none" {
				// Avoid felix restart mid-test, wait for the node resource to be created before starting Felix.
				s.options.DelayFelixStart = true
				s.options.TriggerDelayedFelixStart = true
			}
			s.options.ExtraEnvVars["FELIX_BPFMapSizeConntrackScaling"] = "Disabled"
			s.options.ExtraEnvVars["FELIX_BPFLogLevel"] = fmt.Sprint(s.testOpts.bpfLogLevel)
			s.options.ExtraEnvVars["FELIX_BPFConntrackLogLevel"] = fmt.Sprint(s.testOpts.bpfLogLevel)
			s.options.ExtraEnvVars["FELIX_BPFProfiling"] = "Enabled"
			s.options.ExtraEnvVars["FELIX_PrometheusMetricsEnabled"] = "true"
			s.options.ExtraEnvVars["FELIX_PrometheusMetricsHost"] = "0.0.0.0"
			if s.testOpts.dsr {
				s.options.ExtraEnvVars["FELIX_BPFExternalServiceMode"] = "dsr"
			}
			// ACCEPT is what is set by our manifests and operator by default.
			s.options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "ACCEPT"
			s.options.ExternalIPs = true
			s.options.ExtraEnvVars["FELIX_BPFExtToServiceConnmark"] = "0x80"
			s.options.ExtraEnvVars["FELIX_HEALTHENABLED"] = "true"
			s.options.ExtraEnvVars["FELIX_BPFDSROptoutCIDRs"] = "245.245.0.0/16,beaf::dead/64"
			if !s.testOpts.ipv6 {
				s.options.ExtraEnvVars["FELIX_HEALTHHOST"] = "0.0.0.0"
			} else {
				s.options.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
				s.options.ExtraEnvVars["FELIX_HEALTHHOST"] = "::"
			}

			if s.testOpts.protocol == "tcp" {
				filters := map[string]string{"all": "tcp or (udp port 4789)"}
				tcpResetTimeout := api.BPFConntrackTimeout("5s")
				felixConfig := api.NewFelixConfiguration()
				felixConfig.SetName("default")
				felixConfig.Spec = api.FelixConfigurationSpec{
					BPFLogFilters: &filters,
					BPFConntrackTimeouts: &api.BPFConntrackTimeouts{
						TCPResetSeen: &tcpResetTimeout,
					},
				}
				if s.testOpts.connTimeEnabled {
					felixConfig.Spec.BPFCTLBLogFilter = "all"
				}
				s.options.InitialFelixConfiguration = felixConfig
			}

			if !s.testOpts.connTimeEnabled {
				s.options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBDisabled)
				s.options.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)
				if s.testOpts.protocol == "udp" {
					s.options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBTCP)
				}
			} else {
				s.options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBEnabled)
				s.options.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATDisabled)
				if s.testOpts.protocol == "tcp" {
					s.options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBTCP)
				}
			}
			s.options.ExtraEnvVars["FELIX_BPFMaglevMaxServices"] = "50"
			s.options.ExtraEnvVars["FELIX_BPFMaglevMaxEndpointsPerService"] = "20"
		})

		JustAfterEach(func() {
			if CurrentSpecReport().Failed() {
				var (
					currBpfsvcs   []nat.MapMem
					currBpfeps    []nat.BackendMapMem
					currBpfsvcsV6 []nat.MapMemV6
					currBpfepsV6  []nat.BackendMapMemV6
				)

				if s.testOpts.ipv6 {
					currBpfsvcsV6, currBpfepsV6, _ = dumpNATmapsV6(s.tc.Felixes)
				} else {
					currBpfsvcs, currBpfeps, _ = dumpNATmaps(s.tc.Felixes)
				}

				for i, felix := range s.tc.Felixes {
					felix.Exec("conntrack", "-L")
					felix.Exec("calico-bpf", "policy", "dump", "cali8d1e69e5f89", "all", "--asm")
					if s.testOpts.ipv6 {
						felix.Exec("conntrack", "-L", "-f", "ipv6")
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
						felix.Exec("calico-bpf", "-6", "conntrack", "dump", "--raw")
						felix.Exec("calico-bpf", "-6", "arp", "dump")
					} else {
						if NFTMode() {
							logNFTDiags(felix)
						} else {
							felix.Exec("iptables-save", "-c")
						}
						felix.Exec("ip", "link")
						felix.Exec("ip", "-d", "link", "show", "vxlan.calico")
						felix.Exec("ip", "addr")
						felix.Exec("ip", "rule")
						felix.Exec("ip", "route")
						felix.Exec("ip", "neigh")
						felix.Exec("bridge", "fdb", "show", "dev", "vxlan.calico")
						felix.Exec("arp")
						felix.Exec("calico-bpf", "ipsets", "dump")
						felix.Exec("calico-bpf", "routes", "dump")
						felix.Exec("calico-bpf", "nat", "dump")
						felix.Exec("calico-bpf", "nat", "aff")
						felix.Exec("calico-bpf", "conntrack", "dump", "--raw")
						felix.Exec("calico-bpf", "arp", "dump")
					}
					felix.Exec("calico-bpf", "counters", "dump")
					felix.Exec("calico-bpf", "ifstate", "dump")
					if s.testOpts.ipv6 {
						log.Infof("[%d]FrontendMapV6: %+v", i, currBpfsvcsV6[i])
						log.Infof("[%d]NATBackendV6: %+v", i, currBpfepsV6[i])
						log.Infof("[%d]SendRecvMapV6: %+v", i, dumpSendRecvMapV6(felix))
					} else {
						log.Infof("[%d]FrontendMap: %+v", i, currBpfsvcs[i])
						log.Infof("[%d]NATBackend: %+v", i, currBpfeps[i])
						log.Infof("[%d]SendRecvMap: %+v", i, dumpSendRecvMap(felix))
					}
				}
				s.externalClient.Exec("ip", "route", "show", "cached")
			}
		})

		describeBPFSingleNodeTests(s)

		Describe(fmt.Sprintf("with a %d node cluster", numNodes), func() {
			BeforeEach(func() {
				s.setupCluster()
			})

			clusterIP := "10.101.0.10"
			extIP := "10.1.2.3"
			excludeSvcIP := "10.101.0.222"
			loIP := "5.6.5.6"

			if s.testOpts.ipv6 {
				clusterIP = "dead:beef::abcd:0:0:10"
				extIP = "dead:beef::abcd:1:2:3"
				excludeSvcIP = "dead:beef::abcd:0:0:222"
				loIP = "dead:beef::abcd:0:5656:5656"
			}

			if s.testOpts.protocol == "udp" && s.testOpts.udpUnConnected {
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
					_, err := s.calicoClient.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)

					// The hardest path to secure with BPF is packets to the newly-added workload.  We can't block
					// the traffic with BPF until we have a BPF program in place so we rely on iptables catch-alls.

					// Set up a workload but do not add it to the datastore.
					wlIP := "10.65.1.5"
					if s.testOpts.ipv6 {
						wlIP = "dead:beef::1:5"
					}
					dpOnlyWorkload := workload.New(s.tc.Felixes[1], "w-dp", "default", wlIP, "8057", s.testOpts.protocol)
					err = dpOnlyWorkload.Start(s.infra)
					Expect(err).NotTo(HaveOccurred())
					s.tc.Felixes[1].Exec("ip", "route", "add", dpOnlyWorkload.IP, "dev", dpOnlyWorkload.InterfaceName, "scope", "link")

					// Attach tcpdump to the workload so we can verify that we don't see any packets at all.  We need
					// to verify ingress and egress separately since a round-trip test would be blocked by either.
					tcpdump := dpOnlyWorkload.AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					pattern := fmt.Sprintf(`IP .* %s\.8057: UDP`, dpOnlyWorkload.IP)
					if s.testOpts.ipv6 {
						pattern = fmt.Sprintf(`IP6 .* %s\.8057: UDP`, dpOnlyWorkload.IP)
					}
					tcpdump.AddMatcher("UDP-8057", regexp.MustCompile(pattern))
					tcpdump.Start(s.infra)

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
							_, err = s.w[1][0].RunCmd("pktgen", s.w[1][0].IP, dpOnlyWorkload.IP, "udp",
								"--port-src", "30444", "--port-dst", "8057")
							Expect(err).NotTo(HaveOccurred())
							time.Sleep(100 * (time.Millisecond))
						}
					}()
					defer wg.Wait()

					Consistently(tcpdump.MatchCountFn("UDP-8057"), "5s", "200ms").Should(
						BeNumerically("==", 0),
						"Traffic to the workload should be blocked before datastore is configured")

					dpOnlyWorkload.ConfigureInInfra(s.infra)

					Eventually(tcpdump.MatchCountFn("UDP-8057"), "5s", "200ms").Should(
						BeNumerically(">", 0),
						"Traffic to the workload should be allowed after datastore is configured")
				})
			}

			_ = !s.testOpts.ipv6 && It("should have correct routes", func() {
				tunnelAddr := ""
				tunnelAddrFelix1 := ""
				tunnelAddrFelix2 := ""
				expectedRoutes := expectedRouteDump
				if s.testOpts.dsr {
					expectedRoutes = expectedRouteDumpDSR
				}
				if s.testOpts.ipv6 {
					switch {
					case s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr != "":
						tunnelAddr = s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr
						tunnelAddrFelix1 = s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr
						tunnelAddrFelix2 = s.tc.Felixes[2].ExpectedVXLANV6TunnelAddr
					case s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr != "":
						tunnelAddr = s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr
						tunnelAddrFelix1 = s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr
						tunnelAddrFelix2 = s.tc.Felixes[2].ExpectedWireguardV6TunnelAddr
					}
					expectedRoutes = expectedRouteDumpV6
					if s.testOpts.dsr {
						expectedRoutes = expectedRouteDumpV6DSR
					}
				} else {
					switch {
					case s.tc.Felixes[0].ExpectedIPIPTunnelAddr != "":
						tunnelAddr = s.tc.Felixes[0].ExpectedIPIPTunnelAddr
						tunnelAddrFelix1 = s.tc.Felixes[1].ExpectedIPIPTunnelAddr
						tunnelAddrFelix2 = s.tc.Felixes[2].ExpectedIPIPTunnelAddr
					case s.tc.Felixes[0].ExpectedVXLANTunnelAddr != "":
						tunnelAddr = s.tc.Felixes[0].ExpectedVXLANTunnelAddr
						tunnelAddrFelix1 = s.tc.Felixes[1].ExpectedVXLANTunnelAddr
						tunnelAddrFelix2 = s.tc.Felixes[2].ExpectedVXLANTunnelAddr
					case s.tc.Felixes[0].ExpectedWireguardTunnelAddr != "":
						tunnelAddr = s.tc.Felixes[0].ExpectedWireguardTunnelAddr
						tunnelAddrFelix1 = s.tc.Felixes[1].ExpectedWireguardTunnelAddr
						tunnelAddrFelix2 = s.tc.Felixes[2].ExpectedWireguardTunnelAddr
					}
				}

				if tunnelAddr != "" {
					expectedRoutes = expectedRouteDumpWithTunnelAddr
					if s.testOpts.dsr {
						expectedRoutes = expectedRouteDumpWithTunnelAddrDSR
					}
				}

				dumpRoutes := func() string {
					out := ""
					var err error
					if s.testOpts.ipv6 {
						out, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "routes", "-6", "dump")
					} else {
						out, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "routes", "dump")
					}
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
						l = strings.ReplaceAll(l, s.felixIP(0), "FELIX_0")
						l = strings.ReplaceAll(l, s.felixIP(1), "FELIX_1")
						l = strings.ReplaceAll(l, s.felixIP(2), "FELIX_2")
						l = idxRE.ReplaceAllLiteralString(l, "idx -")
						if tunnelAddr != "" {
							if s.testOpts.ipv6 {
								l = strings.ReplaceAll(l, tunnelAddr+"/128", "FELIX_0_TNL/128")
							} else {
								l = strings.ReplaceAll(l, tunnelAddr+"/32", "FELIX_0_TNL/32")
							}
						}
						if tunnelAddrFelix1 != "" {
							if s.testOpts.ipv6 {
								l = strings.ReplaceAll(l, tunnelAddrFelix1+"/128", "FELIX_1_TNL/128")
							} else {
								l = strings.ReplaceAll(l, tunnelAddrFelix1+"/32", "FELIX_1_TNL/32")
							}
						}
						if tunnelAddrFelix2 != "" {
							if s.testOpts.ipv6 {
								l = strings.ReplaceAll(l, tunnelAddrFelix2+"/128", "FELIX_2_TNL/128")
							} else {
								l = strings.ReplaceAll(l, tunnelAddrFelix2+"/32", "FELIX_2_TNL/32")
							}
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
				s.cc.ExpectNone(s.w[0][0], s.w[0][1])
				s.cc.ExpectNone(s.w[0][1], s.w[0][0])
				// Workloads on other host.
				s.cc.ExpectNone(s.w[0][0], s.w[1][0])
				s.cc.ExpectNone(s.w[1][0], s.w[0][0])
				// Hosts.
				s.cc.ExpectSome(s.tc.Felixes[0], s.w[0][0])
				s.cc.ExpectNone(s.tc.Felixes[1], s.w[0][0])
				s.cc.CheckConnectivity()
			})

			It("should allow host -> host", func() {
				// XXX as long as there is no HEP policy
				// using hostW as a sink
				s.cc.Expect(Some, s.tc.Felixes[0], s.hostW[0])
				s.cc.Expect(Some, s.tc.Felixes[0], s.hostW[1])
				s.cc.Expect(Some, s.tc.Felixes[1], s.hostW[0])
				s.cc.CheckConnectivity()
			})

			Context("with a policy allowing ingress to s.w[0][0] from all regular workloads", func() {
				BeforeEach(func() {
					s.pol = api.NewGlobalNetworkPolicy()
					s.pol.Namespace = "fv"
					s.pol.Name = "policy-1"
					s.pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "workload=='regular'",
							},
						},
					}
					s.pol.Spec.Egress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "workload=='regular'",
							},
						},
					}
					s.pol.Spec.Selector = "workload=='regular'"

					s.pol = s.createPolicy(s.pol)

					s.k8sClient = s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
					_ = s.k8sClient
				})

				Context("with both applyOnForward=true/false", func() {
					BeforeEach(func() {
						// The next two policies are to make sure that applyOnForward of a
						// global policy is applied correctly to a host endpoint. The deny
						// policy is not applied to forwarded traffic!

						By("global policy denies traffic to host 1 on host 0", func() {
							nets := []string{s.felixIP(1) + "/" + s.ipMask()}
							switch s.testOpts.tunnel {
							case "ipip":
								nets = append(nets, s.tc.Felixes[1].ExpectedIPIPTunnelAddr+"/32")
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
							pol.Spec.Selector = "node=='" + s.tc.Felixes[0].Name + "'"
							pol.Spec.ApplyOnForward = false

							pol = s.createPolicy(pol)
						})

						By("global policy allows forwarded traffic to host 1 on host 0", func() {
							nets := []string{s.felixIP(1) + "/" + s.ipMask()}
							switch s.testOpts.tunnel {
							case "ipip":
								nets = append(nets, s.tc.Felixes[1].ExpectedIPIPTunnelAddr+"/32")
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
							pol.Spec.Selector = "node=='" + s.tc.Felixes[0].Name + "'"
							pol.Spec.ApplyOnForward = true

							pol = s.createPolicy(pol)
						})

						bpfWaitForGlobalNetworkPolicy(s.tc.Felixes[0], "eth0", "egress", "host-0-1")
					})

					It("should handle NAT outgoing", func() {
						By("SNATting outgoing traffic with the flag set")
						s.cc.ExpectSNAT(s.w[0][0], s.felixIP(0), s.hostW[1])
						s.cc.Expect(Some, s.w[0][0], s.hostW[0]) // no snat
						s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)

						if s.testOpts.tunnel == "none" {
							By("Leaving traffic alone with the flag clear")
							poolName := infrastructure.DefaultIPPoolName
							if s.testOpts.ipv6 {
								poolName = infrastructure.DefaultIPv6PoolName
							}
							pool, err := s.calicoClient.IPPools().Get(context.TODO(), poolName, options2.GetOptions{})
							Expect(err).NotTo(HaveOccurred())
							pool.Spec.NATOutgoing = false
							pool, err = s.calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
							Expect(err).NotTo(HaveOccurred())

							// Wait for the pool change to take effect
							Eventually(func() string {
								return bpfDumpRoutes(s.tc.Felixes[0])
							}, "5s", "1s").ShouldNot(ContainSubstring("workload in-pool nat-out"))

							s.cc.ResetExpectations()
							s.cc.ExpectSNAT(s.w[0][0], s.w[0][0].IP, s.hostW[1])
							s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)

							By("SNATting again with the flag set")
							pool.Spec.NATOutgoing = true
							pool, err = s.calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
							Expect(err).NotTo(HaveOccurred())

							// Wait for the pool change to take effect
							Eventually(func() string {
								return bpfDumpRoutes(s.tc.Felixes[0])
							}, "5s", "1s").Should(ContainSubstring("workload in-pool nat-out"))

							s.cc.ResetExpectations()
							s.cc.ExpectSNAT(s.w[0][0], s.felixIP(0), s.hostW[1])
							s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
						}
					})
				})

				It("connectivity from all workloads via workload 0's main IP", func() {
					var tcpd *tcpdump.TCPDump

					if s.testOpts.tunnel == "vxlan" {
						tcpd = s.tc.Felixes[0].AttachTCPDump("eth0")
						tcpd.SetLogEnabled(true)
						tcpd.AddMatcher("eth0-vxlan", regexp.MustCompile("VXLAN,.* vni 4096"))
						tcpd.Start(s.infra, "-vvv", "udp", "port", "4789")
					}

					s.cc.ExpectSome(s.w[0][1], s.w[0][0])
					s.cc.ExpectSome(s.w[1][0], s.w[0][0])
					s.cc.ExpectSome(s.w[1][1], s.w[0][0])
					s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)

					if s.testOpts.tunnel == "vxlan" {
						Eventually(func() int { return tcpd.MatchCount("eth0-vxlan") }).Should(BeNumerically(">", 0))
					}
				})

				_ = !s.testOpts.ipv6 && !s.testOpts.dsr && s.testOpts.protocol == "udp" && s.testOpts.udpUnConnected && !s.testOpts.connTimeEnabled &&
					It("should handle fragmented UDP", func() {
						if s.testOpts.tunnel == "vxlan" && !utils.UbuntuReleaseGreater("22.04") {
							Skip("Ubuntu too old to handle frag on vxlan dev properly")
						}

						dev := "eth0"
						switch s.testOpts.tunnel {
						case "vxlan":
							dev = "vxlan.calico"
						case "ipip":
							dev = "tunl0"
						case "wireguard":
							dev = "wireguard.cali"
						}
						tcpdump1 := s.tc.Felixes[1].AttachTCPDump(dev)
						tcpdump1.SetLogEnabled(true)
						tcpdump1.AddMatcher("udp-frags", regexp.MustCompile(
							fmt.Sprintf("%s.* > %s.*", s.w[1][0].IP, s.w[0][0].IP)))
						tcpdump1.Start(s.infra, "-vvv", "src", "host", s.w[1][0].IP, "and", "dst", "host", s.w[0][0].IP)

						tcpdump0 := s.w[0][0].AttachTCPDump()
						tcpdump0.SetLogEnabled(true)
						tcpdump0.AddMatcher("udp-pod-frags", regexp.MustCompile(
							fmt.Sprintf("%s.* > %s.*", s.w[1][0].IP, s.w[0][0].IP)))
						tcpdump0.Start(s.infra, "-vvv", "src", "host", s.w[1][0].IP, "and", "dst", "host", s.w[0][0].IP)

						// Give tcpdump some time to start up!
						time.Sleep(time.Second)

						// Send a packet with large payload without the DNF flag
						// 16,000 bytes is the typical limit on the size of a
						// single skb, which in turn is the limit on the size
						// that a BPF program can grow a packet.
						_, err := s.w[1][0].RunCmd("pktgen", s.w[1][0].IP, s.w[0][0].IP, "udp",
							"--port-src", "30444", "--port-dst", "30444", "--ip-dnf=n", "--payload-size=16000", "--udp-sock")
						Expect(err).NotTo(HaveOccurred())

						// We should see two fragments on the host interface
						Eventually(func() int { return tcpdump1.MatchCount("udp-frags") }).Should(Equal(12))
						// We should see the fragments reach the workload.  We reassemble them in the middle but they
						// get fragmented again.
						Eventually(func() int { return tcpdump0.MatchCount("udp-pod-frags") }).Should(Equal(12))
						// Send another set of fragmented packets with the same source and destination ports. This
						// will result in the first fragment hitting the conntrack and bypass mark set. We should
						// still see the fragments reach the destination.
						By("Sending another set of fragmented packets")
						_, err = s.w[1][0].RunCmd("pktgen", s.w[1][0].IP, s.w[0][0].IP, "udp",
							"--port-src", "30444", "--port-dst", "30444", "--ip-dnf=n", "--payload-size=16000", "--udp-sock")
						Expect(err).NotTo(HaveOccurred())
						Eventually(func() int { return tcpdump1.MatchCount("udp-frags") }).Should(Equal(24))
					})

				if (s.testOpts.protocol == "tcp" || (s.testOpts.protocol == "udp" && !s.testOpts.udpUnConnected)) &&
					s.testOpts.connTimeEnabled && !s.testOpts.dsr {

					It("should fail connect if there is no backed or a service", func() {
						var (
							natK   nat.FrontendKeyInterface
							family int
						)

						By("setting up a service without backends")

						clusterIP1 := "10.101.0.111"
						if s.testOpts.ipv6 {
							clusterIP1 = "dead:beef::abcd:0:0:111"
						}
						testSvc := k8sService("svc-no-backends", clusterIP1, s.w[0][0], 80, 1234, 0, s.testOpts.protocol)
						testSvcNamespace := testSvc.Namespace
						testSvc.Spec.Selector = map[string]string{"somelabel": "somevalue"}
						_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(),
							testSvc, metav1.CreateOptions{})
						Expect(err).NotTo(HaveOccurred())

						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)
						if s.testOpts.ipv6 {
							natK = nat.NewNATKeyV6(net.ParseIP(ip), port, s.numericProto)
							family = 6
						} else {
							natK = nat.NewNATKey(net.ParseIP(ip), port, s.numericProto)
							family = 4
						}

						Eventually(func() bool {
							natmaps, _, _ := dumpNATMapsAny(family, s.tc.Felixes[0])
							if _, ok := natmaps[natK]; !ok {
								return false
							}
							return true
						}, "5s").Should(BeTrue(), "service NAT key didn't show up")

						By("starting tcpdump")
						tcpdump := s.w[0][0].AttachTCPDump()
						tcpdump.SetLogEnabled(true)

						var pattern string
						if s.testOpts.ipv6 {
							pattern = fmt.Sprintf(`IP6 %s.\d+ > %s\.80`, s.w[0][0].IP, testSvc.Spec.ClusterIP)
						} else {
							pattern = fmt.Sprintf(`IP %s.\d+ > %s\.80`, s.w[0][0].IP, testSvc.Spec.ClusterIP)
						}
						tcpdump.AddMatcher("no-backend", regexp.MustCompile(pattern))
						tcpdump.Start(s.infra)

						By("testing connectivity")

						s.cc.Expect(None, s.w[0][0], TargetIP(testSvc.Spec.ClusterIP), ExpectWithPorts(80))
						s.cc.CheckConnectivity()

						// If connect never succeeded, no packets were sent and
						// therefore we must see none.
						Expect(tcpdump.MatchCount("no-backend")).To(Equal(0))
					})
				}

				// Test doesn't use services so ignore the runs with those turned on.
				if s.testOpts.protocol == "tcp" && !s.testOpts.connTimeEnabled && !s.testOpts.dsr {
					spoofSetup := func() {
						if s.testOpts.ipv6 {
							// XXX the routing needs to be different and may not
							// apply to ipv6
							return
						}

						if !s.testOpts.ipv6 {
							By("Disabling dev RPF")
							setRPF(s.tc.Felixes, s.testOpts.tunnel, 0, 0)
						}
						// Make sure the workload is up and has configured its routes.
						By("Having basic connectivity")
						s.cc.Expect(Some, s.w[0][0], s.w[1][0])
						s.cc.CheckConnectivity()

						// Add a second interface to the workload, this will allow us to adjust the routes
						// inside the workload to move connections from one interface to the other.
						By("Having basic connectivity after setting up the spoof interface")
						s.w[0][0].AddSpoofInterface()
						// Check that the route manipulation succeeded.
						s.cc.CheckConnectivity()
						s.cc.ResetExpectations()
					}

					// Basic single-shot connectivity checks to check that the test infra
					// is basically doing what we want.  I.e. if felix and the workload disagree on
					// interface then new connections get dropped.
					It("should not be able to spoof new TCP connections", func() {
						spoofSetup()
						if s.testOpts.ipv6 {
							return
						}

						// Switch routes to use the spoofed interface, should fail.
						By("Workload using spoof0, felix expecting eth0, should fail")
						s.w[0][0].UseSpoofInterface(true)
						s.cc.Expect(None, s.w[0][0], s.w[1][0])
						s.cc.CheckConnectivity()
						s.cc.ResetExpectations()

						By("Workload using spoof0, felix expecting spoof0, should succeed")
						s.w[0][0].RemoveFromInfra(s.infra)
						s.w[0][0].ConfigureInInfraAsSpoofInterface(s.infra)
						s.cc.Expect(Some, s.w[0][0], s.w[1][0])
						s.cc.CheckConnectivity()
						s.cc.ResetExpectations()

						By("Both back to eth0, should succeed")
						s.w[0][0].RemoveSpoofWEPFromInfra(s.infra)
						s.w[0][0].ConfigureInInfra(s.infra)
						s.w[0][0].UseSpoofInterface(false)
						s.cc.Expect(Some, s.w[0][0], s.w[1][0])
						s.cc.CheckConnectivity()
						s.cc.ResetExpectations()
					})

					// Keep a connection up and move it from one interface to the other using the pod's
					// routes.  To the host this looks like one workload is spoofing the other.
					It("should not be able to spoof existing TCP connections", func() {
						spoofSetup()
						if s.testOpts.ipv6 {
							return
						}

						By("Starting permanent connection")
						pc := s.w[0][0].StartPersistentConnection(s.w[1][0].IP, 8055, workload.PersistentConnectionOpts{
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
						s.w[0][0].ConfigureOtherWEPInInfraAsSpoofInterface(s.infra)

						// Should get some pongs to start with...
						By("Should get pongs to start with")
						expectPongs()

						// Switch the route, should start dropping packets.
						s.w[0][0].UseSpoofInterface(true)
						By("Should no longer get pongs when using the spoof interface")
						expectNoPongs()

						// Switch the route back, should work.
						s.w[0][0].UseSpoofInterface(false)
						By("Should get pongs again after switching back")
						expectPongs()

						// Switch the route, should start dropping packets.
						s.w[0][0].UseSpoofInterface(true)
						By("Should no longer get pongs when using the spoof interface")
						expectNoPongs()

						// Move WEP to spoof interface
						s.w[0][0].RemoveFromInfra(s.infra)
						s.w[0][0].RemoveSpoofWEPFromInfra(s.infra)
						s.w[0][0].ConfigureInInfraAsSpoofInterface(s.infra)
						By("Should get pongs again after switching WEP to spoof iface")
						expectPongs()
					})
				}

				describeBPFServiceTests(s, clusterIP, extIP, excludeSvcIP, loIP)
				describeBPFNodePortTests(s, clusterIP, loIP)
			})

			It("should have connectivity when DNAT redirects to-host traffic to a local pod.", func() {
				protocol := "tcp"
				if s.testOpts.protocol == "udp" {
					protocol = "udp"
				}

				hostIP0 := TargetIP(s.felixIP(0))
				hostPort := uint16(8080)
				target := net.JoinHostPort(s.w[0][0].IP, "8055")

				var (
					tool      string
					nftFamily string
				)
				if s.testOpts.ipv6 {
					tool = "ip6tables"
					nftFamily = "ip6"
				} else {
					tool = "iptables"
					nftFamily = "ip"
				}

				policy := api.NewNetworkPolicy()
				policy.Name = "allow-all"
				policy.Namespace = "default"
				one := float64(1)
				policy.Spec.Order = &one
				policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
				policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
				policy.Spec.Selector = "all()"
				_, err := s.calicoClient.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				expectNormalConnectivity := func() {
					s.cc.ResetExpectations()
					s.cc.ExpectNone(s.tc.Felixes[1], hostIP0, hostPort)
					s.cc.ExpectNone(s.externalClient, hostIP0, hostPort)
					s.cc.ExpectNone(s.w[1][0], hostIP0, hostPort)
					s.cc.CheckConnectivity()
					s.cc.ResetExpectations()
				}

				By("checking initial connectivity", func() {
					expectNormalConnectivity()
				})

				By("installing 3rd party DNAT rules", func() {
					// Install a DNAT in first felix
					if NFTMode() {
						s.tc.Felixes[0].Exec("nft", "create", "table", nftFamily, "destnat")
						s.tc.Felixes[0].Exec("nft", "add", "chain", nftFamily, "destnat", "prerouting", "{ type nat hook prerouting priority dstnat; }")
						s.tc.Felixes[0].Exec("nft", "add", "rule", nftFamily, "destnat", "prerouting", protocol, "dport", fmt.Sprintf("%d", hostPort), "dnat", target)
					} else {
						s.tc.Felixes[0].Exec(
							tool, "-w", "10", "-W", "100000", "-t", "nat", "-A", "PREROUTING", "-p", protocol, "-m", protocol,
							"--dport", fmt.Sprintf("%d", hostPort), "-j", "DNAT", "--to-destination", target)

						s.cc.ResetExpectations()
						s.cc.ExpectSome(s.tc.Felixes[1], hostIP0, hostPort)
						s.cc.ExpectSome(s.externalClient, hostIP0, hostPort)
						s.cc.ExpectSome(s.w[1][0], hostIP0, hostPort)
						s.cc.CheckConnectivity()
						s.cc.ResetExpectations()
					}
				})

				By("removing 3rd party rules and check connectivity is back to normal again", func() {
					if NFTMode() {
						s.tc.Felixes[0].Exec("nft", "delete", "table", nftFamily, "destnat")
					} else {
						s.tc.Felixes[0].Exec(
							tool, "-w", "10", "-W", "100000", "-t", "nat", "-D", "PREROUTING", "-p", protocol, "-m", protocol,
							"--dport", fmt.Sprintf("%d", hostPort), "-j", "DNAT", "--to-destination", target)
					}

					expectNormalConnectivity()
				})
			})

			It("should have connectivity from host-networked pods via service to host-networked backend", func() {
				By("Setting up the service")
				testSvc := k8sService("host-svc", clusterIP, s.hostW[0], 80, 8055, 0, s.testOpts.protocol)
				testSvcNamespace := testSvc.Namespace
				s.k8sClient = s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
					"Service endpoints didn't get created? Is controller-manager happy?")

				By("Testing connectivity")
				port := uint16(testSvc.Spec.Ports[0].Port)

				hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
				hostW1SrcIP := ExpectWithSrcIPs(s.felixIP(1))

				s.cc.Expect(Some, s.hostW[0], TargetIP(clusterIP), ExpectWithPorts(port), hostW0SrcIP)
				s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ExpectWithPorts(port), hostW1SrcIP)
				s.cc.CheckConnectivity()
			})
		})

		describeBPFSpecialTests(s)
	})
}
