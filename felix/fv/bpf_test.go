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
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/proxy"
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

func describeBPFServiceTests(s *bpfTestContext, clusterIP, extIP, excludeSvcIP, loIP string) {
	Describe("Test advertised IP's with maglev enabled", func() {
		if s.testOpts.connTimeEnabled {
			// FIXME s.externalClient also does conntime balancing
			return
		}

		var (
			testSvc          *v1.Service
			testSvcNamespace string
			port             uint16
			proto            uint8
		)
		if numNodes < 3 {
			panic("need 3 nodes")
		}

		tgtPort := 8055
		externalIP := extIP
		testSvcName := "test-maglev-service"

		familyInt := 4
		if s.family == "ipv6" {
			familyInt = 6
		}

		felixWithMaglevBackend := 0
		initialIngressFelix := 1
		failoverIngressFelix := 2

		newConntrackKey := func(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, family string) conntrack.KeyInterface {
			var key conntrack.KeyInterface
			// cmp := bytes.Compare(srcIP, dstIP)
			// srcLTDst := cmp < 0 || (cmp == 0 && srcPort < dstPort)

			ipA, ipB := srcIP, dstIP
			portA, portB := uint16(srcPort), dstPort
			// if !srcLTDst {
			// 	ipB, ipA = srcIP, dstIP
			// 	portB, portA = uint16(srcPort), port
			// }
			switch family {
			case "ipv4":
				key = conntrack.NewKey(proto, ipA, portA, ipB, portB)
			case "ipv6":
				key = conntrack.NewKeyV6(proto, ipA, portA, ipB, portB)
			}
			return key
		}
		checkConntrackExists := func(f *infrastructure.Felix, ctK conntrack.KeyInterface) (conntrack.ValueInterface, bool) {
			ctMap := dumpCTMapsAny(familyInt, f)
			log.Infof("Dumping CT map for felix %s, searching for key: %s", f.Name, ctK.String())

			for k, v := range ctMap {
				log.Infof("key: %s\n\tval: %s", k.String(), v.String())
			}
			v, ok := ctMap[ctK]
			return v, ok
		}
		checkConntrackExistsAnyDirection := func(f *infrastructure.Felix, ipA net.IP, portA uint16, ipB net.IP, portB uint16, family string) (conntrack.ValueInterface, bool) {
			keyAB := newConntrackKey(ipA, portA, ipB, portB, family)
			keyBA := newConntrackKey(ipB, portB, ipA, portA, family)

			val, exists := checkConntrackExists(f, keyAB)
			if !exists {
				val, exists = checkConntrackExists(f, keyBA)
			}

			return val, exists
		}
		maglevMapAnySearch := func(val nat.BackendValueInterface, family string, felix *infrastructure.Felix) nat.BackendValueInterface {
			Expect(family).To(Or(Equal("ipv4"), Equal("ipv6")))

			switch family {
			case "ipv4":
				vType := nat.BackendValue{}
				Expect(val).To(BeAssignableToTypeOf(vType))
				kvs := dumpMaglevMap(felix)
				valParsed, _ := val.(nat.BackendValue)

				for _, v := range kvs {
					if v.Addr().Equal(valParsed.Addr()) && v.Port() == valParsed.Port() {
						return v
					}
				}

			case "ipv6":
				vType := nat.BackendValueV6{}
				Expect(val).To(BeAssignableToTypeOf(vType))
				kvs := dumpMaglevMapV6(felix)
				valParsed, _ := val.(nat.BackendValueV6)

				for _, v := range kvs {
					if v.Addr().Equal(valParsed.Addr()) && v.Port() == valParsed.Port() {
						return v
					}
				}
			}
			return nil
		}
		maglevMapAnySearchFunc := func(val nat.BackendValueInterface, family string, felix *infrastructure.Felix) func() nat.BackendValueInterface {
			return func() nat.BackendValueInterface {
				return maglevMapAnySearch(val, family, felix)
			}
		}

		probeMaglevConntrackMetric := func(metricName string, felixes ...*infrastructure.Felix) []int {
			counts := make([]int, 0)
			for _, f := range felixes {
				ctCount, err := f.PromMetric(metricName).Int()
				if err != nil {
					log.WithError(err).WithField("felix", f.Name).Warn("Error while probing Felix metric. Skipping this felix")
					continue
				}
				counts = append(counts, ctCount)
			}
			return counts
		}

		BeforeEach(func() {
			switch s.testOpts.protocol {
			case "udp":
				proto = 17
			case "tcp":
				proto = 6
			case "sctp":
				proto = 132
			default:
				log.WithField("protocol", s.testOpts.protocol).Panic("unknown test protocol")
			}
			log.WithFields(log.Fields{"number": proto, "name": s.testOpts.protocol}).Info("parsed protocol")

			pTCP := numorstring.ProtocolFromString("tcp")
			promPinhole := api.Rule{
				Action:   "Allow",
				Protocol: &pTCP,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{
						{MinPort: 9091, MaxPort: 9091},
					},
					Nets: []string{},
				},
			}

			// Create policy allowing ingress from external client
			allowIngressFromExtClient := api.NewGlobalNetworkPolicy()
			allowIngressFromExtClient.Namespace = "fv"
			allowIngressFromExtClient.Name = "policy-ext-client"
			allowIngressFromExtClient.Spec.Ingress = []api.Rule{
				promPinhole,
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.containerIP(s.externalClient) + "/" + s.ipMask(),
						},
					},
				},
			}

			allowIngressFromExtClientSelector := "all()"
			allowIngressFromExtClient.Spec.Selector = allowIngressFromExtClientSelector
			allowIngressFromExtClient = s.createPolicy(allowIngressFromExtClient)

			// Create service with maglev annotation
			testSvc = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[felixWithMaglevBackend][0], 80, tgtPort, 0,
				s.testOpts.protocol, []string{externalIP})
			testSvc.Annotations = map[string]string{
				"lb.projectcalico.org/external-traffic-strategy": "maglev",
			}

			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoint didn't get created. Is controller-manager happy?")
			Expect(k8sGetEpsForService(s.k8sClient, testSvc)[0].Endpoints[0].Addresses).Should(HaveLen(1),
				"Service endpoint didn't have the expected number of addresses.")

			Expect(testSvc.Spec.ExternalIPs).To(HaveLen(1))
			Expect(testSvc.Spec.ExternalIPs[0]).To(Equal(externalIP))
			Expect(testSvc.Spec.Ports).To(HaveLen(1))
			port = uint16(testSvc.Spec.Ports[0].Port)

			conntrackFlushWorkloadEntries(s.tc.Felixes)

			eps := k8sGetEpsForService(s.k8sClient, testSvc)
			Expect(eps).NotTo(HaveLen(0), "Expected endpoints for the service")
			Expect(eps[0].Endpoints).NotTo(HaveLen(0), "Endpointslice had no endpoints")
			Expect(eps[0].Endpoints[0].Addresses).NotTo(BeEmpty(), "No addresses in endpointslice item")
			Expect(net.ParseIP(eps[0].Endpoints[0].Addresses[0])).NotTo(BeNil(), "Endpoint address was not parseable as an IP")

			var testMaglevMapVal nat.BackendValueInterface
			switch s.family {
			case "ipv4":
				testMaglevMapVal = nat.NewNATBackendValue(net.ParseIP(eps[0].Endpoints[0].Addresses[0]), uint16(tgtPort))
			case "ipv6":
				testMaglevMapVal = nat.NewNATBackendValueV6(net.ParseIP(eps[0].Endpoints[0].Addresses[0]), uint16(tgtPort))
			default:
				log.Panicf("Unexpected IP family %s", s.family)
			}

			log.Info("Waiting for Maglev map to converge...")
			Eventually(maglevMapAnySearchFunc(testMaglevMapVal, s.family, s.tc.Felixes[0]), "10s").ShouldNot(BeNil(), "A maglev map entry never showed up (Felix[0]). Looked for backend: %v", testMaglevMapVal)
			Eventually(maglevMapAnySearchFunc(testMaglevMapVal, s.family, s.tc.Felixes[1]), "10s").ShouldNot(BeNil(), "A maglev map entry never showed up (Felix[1]). Looked for backend: %v", testMaglevMapVal)
			Eventually(maglevMapAnySearchFunc(testMaglevMapVal, s.family, s.tc.Felixes[2]), "10s").ShouldNot(BeNil(), "A maglev map entry never showed up (Felix[2]). Looked for backend: %v", testMaglevMapVal)

			Expect(maglevMapAnySearch(testMaglevMapVal, s.family, s.tc.Felixes[1]).Addr().String()).Should(Equal(s.w[0][0].IP))

			// Configure routes on external client and Felix nodes.
			// Use Felix[1] as a middlebox initially.
			ipRoute := []string{"ip"}
			if s.testOpts.ipv6 {
				ipRoute = append(ipRoute, "-6")
			}

			cmdCleanRt := append(ipRoute, "route", "del", clusterIP)
			_ = s.externalClient.ExecMayFail(strings.Join(cmdCleanRt, ""))
			cmdCleanRt = append(ipRoute, "route", "del", externalIP)
			_ = s.externalClient.ExecMayFail(strings.Join(cmdCleanRt, ""))

			cmdCIP := append(ipRoute, "route", "add", clusterIP, "via", s.felixIP(initialIngressFelix))
			s.externalClient.Exec(cmdCIP...)
			cmdEIP := append(ipRoute, "route", "add", externalIP, "via", s.felixIP(initialIngressFelix))
			s.externalClient.Exec(cmdEIP...)
		})

		It("should have connectivity from external client to maglev backend via cluster IP and external IP", func() {
			probeMaglevLocalConntrackMetricFunc := func(felixes ...*infrastructure.Felix) func() []int {
				return func() []int {
					return probeMaglevConntrackMetric(fmt.Sprintf("felix_bpf_conntrack_maglev_entries_total{destination=\"local\",ip_family=\"%d\"}", familyInt), felixes...)
				}
			}
			probeMaglevRemoteConntrackMetricFunc := func(felixes ...*infrastructure.Felix) func() []int {
				return func() []int {
					return probeMaglevConntrackMetric(fmt.Sprintf("felix_bpf_conntrack_maglev_entries_total{destination=\"remote\",ip_family=\"%d\"}", familyInt), felixes...)
				}
			}

			Eventually(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes...), "10s", "1s").Should(Equal([]int{0, 0, 0}), "Expected maglev local-conntrack metric to start at 0 for all Felixes")
			Eventually(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes...), "10s", "1s").Should(Equal([]int{0, 0, 0}), "Expected maglev remote-conntrack metric to start at 0 for all Felixes")

			s.cc.ExpectSome(s.externalClient, TargetIP(clusterIP), port)
			s.cc.ExpectSome(s.externalClient, TargetIP(externalIP), port)
			s.cc.CheckConnectivity()

			// There is a 10-second interval between iterations of Felix's conntrack scanner (where we export the maglev conntrack metrics).
			// This means we must be very pessimistic about timeouts when searching for the prom values we're after.
			Eventually(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes[initialIngressFelix]), "12s", "1s").Should(Equal([]int{2}), "Expected maglev-ingress felix to increment the remote-conntracks metric")
			Eventually(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes[felixWithMaglevBackend]), "12s", "1s").Should(Equal([]int{2}), "Expected felix with maglev backend to increment the local-conntracks metric")
			Consistently(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes[initialIngressFelix])).Should(Equal([]int{0}), "Expected ingress-felix to only have remote maglev conntracks, but saw metric for local maglev conntracks go up")
			Consistently(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes[felixWithMaglevBackend])).Should(Equal([]int{0}), "Expected backing felix to only have local maglev conntracks, but saw metric for remote maglev conntracks go up")
			Consistently(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes[failoverIngressFelix])).Should(Equal([]int{0}), "No failover occurred, but an unrelated Felix's local maglev prom metrics went up")
			Consistently(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes[failoverIngressFelix])).Should(Equal([]int{0}), "No failover occurred, but an unrelated Felix's remote maglev prom metrics went up")
		})

		testFailover := func(serviceIP string) {
			By("making a connection over a loadbalancer and then switching off routing to it")
			pc := &PersistentConnection{
				Runtime:              s.externalClient,
				RuntimeName:          s.externalClient.Name,
				IP:                   serviceIP,
				Port:                 int(port),
				SourcePort:           50000,
				Protocol:             s.testOpts.protocol,
				MonitorConnectivity:  true,
				ProbeLoopFileTimeout: 15 * time.Second,
			}
			err := pc.Start()
			Expect(err).NotTo(HaveOccurred())
			defer pc.Stop()

			Eventually(pc.PongCount, "5s", "100ms").Should(BeNumerically(">", 0), "Connection failed")

			backingPodIPAddr := net.ParseIP(s.w[0][0].IP)
			clientIPAddr := net.ParseIP(s.containerIP(s.externalClient))

			ctVal, ctExists := checkConntrackExistsAnyDirection(s.tc.Felixes[1], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
			Expect(ctExists).To(BeTrue(), "No conntrack (src->dst / dst->src) existed for the connection on Felix[1]")
			Expect(ctVal.OrigIP().String()).To(Equal(serviceIP), "Unexpected OrigIP on loadbalancer Felix service connection")

			ctVal, ctExists = checkConntrackExistsAnyDirection(s.tc.Felixes[2], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
			Expect(ctExists).To(BeFalse(), "Conntrack existed for the connection on Felix[2] before Felix[2] should have handled the connection: %v", ctVal)

			// Traffic is flowing over LB 1. Change ExtClient's serviceIP route to go via LB 2.
			ipRoute := []string{"ip"}
			if s.testOpts.ipv6 {
				ipRoute = append(ipRoute, "-6")
			}
			ipRouteReplace := append(ipRoute, "route", "replace", serviceIP, "via", s.felixIP(2))
			s.externalClient.Exec(ipRouteReplace...)

			lastPongCount := pc.PongCount()

			checkCTExistsFn := func() bool {
				_, ctExists = checkConntrackExistsAnyDirection(s.tc.Felixes[2], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
				return ctExists
			}
			Eventually(checkCTExistsFn, "10s").Should(BeTrue(), "Conntrack didn't exist on Felix[2] for failover traffic. Did the failover actually occur?")

			// Check the backing node updated conntrack tun_ip to the new loadbalancer node.
			ctVal, ctExists = checkConntrackExistsAnyDirection(s.tc.Felixes[0], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
			Expect(ctExists).To(BeTrue(), "Conntrack didn't exist on backing Felix[0].")
			Expect(ctVal.Data().TunIP.String()).To(Equal(s.felixIP(2)), "Backing node did not update its conntrack tun_ip to the new loadbalancer IP")

			// Connection should persist after the changeover.
			Eventually(pc.PongCount, "5s", "100ms").Should(BeNumerically(">", lastPongCount), "Connection is no longer ponging after route failover")
		}

		It("should maintain connections to a cluster IP across loadbalancer failover using maglev", func() { testFailover(clusterIP) })
		It("should maintain connections to an external IP across loadbalancer failover using maglev", func() { testFailover(externalIP) })
	})

	Describe("Test Load balancer service with external IP", func() {
		if s.testOpts.connTimeEnabled {
			// FIXME s.externalClient also does conntime balancing
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
			s.externalClient.Exec("ip", "route", "add", extIP, "via", s.felixIP(0))
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)
			// when we point Load Balancer to a node in GCE it adds local routes to the external IP on the hosts.
			// Similarity add local routes for externalIP on testContainers.Felix[0], testContainers.Felix[1]
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			ip = testSvc.Spec.ExternalIPs
			port = uint16(testSvc.Spec.Ports[0].Port)
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.containerIP(s.externalClient) + "/" + s.ipMask(),
							s.w[0][1].IP + "/" + s.ipMask(),
							s.w[1][0].IP + "/" + s.ipMask(),
							s.w[1][1].IP + "/" + s.ipMask(),
						},
					},
				},
			}
			s.pol = s.updatePolicy(s.pol)
		})

		It("should have connectivity from workloads[1][0],[1][1], [0][1] and external client via external IP to workload 0", func() {
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()
		})

		It("should handle temporary overlap of external IPs", func() {
			By("Having connectivity to external IP initially")
			s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()

			By("Adding second service with same external IP")
			clusterIP2 := "10.101.0.11"

			if s.testOpts.ipv6 {
				clusterIP2 = "dead:beef::abcd:0:0:11"
			}
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName+"-2", clusterIP2, s.w[0][0], 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)

			By("Deleting first service")
			err := s.k8sClient.CoreV1().Services(testSvc.Namespace).Delete(context.Background(), testSvcName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Sleeping")
			time.Sleep(20 * time.Second)
			By("And still having connectivity...")
			s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()
		})
	})

	Context("Test load balancer service with src ranges", func() {
		var testSvc *v1.Service
		tgtPort := 8055
		externalIP := []string{extIP}
		srcIPRange := []string{"10.65.1.3/24"}
		if s.testOpts.ipv6 {
			srcIPRange = []string{"dead:beef::1:3/120"}
		}
		testSvcName := "test-lb-service-extip"
		var ip []string
		var port uint16
		BeforeEach(func() {
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			ip = testSvc.Spec.ExternalIPs
			port = uint16(testSvc.Spec.Ports[0].Port)
		})
		It("should have connectivity from workloads[1][0],[1][1] via external IP to workload 0", func() {
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
			s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()
		})
	})

	Context("Test load balancer service with no backend", func() {
		if s.testOpts.connTimeEnabled || s.testOpts.udpUnConnected {
			// Skip UDP unconnected, connecttime load balancing cases as s.externalClient also does conntime balancing
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
			s.externalClient.Exec("ip", "route", "add", extIP, "via", s.felixIP(0))
			// create a service workload as nil, so that the service has no backend
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, nil, 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			ip = testSvc.Spec.ExternalIPs
			port = uint16(testSvc.Spec.Ports[0].Port)
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.externalClient.IP + "/32",
						},
					},
				},
			}
			s.pol = s.updatePolicy(s.pol)
		})

		It("should not have connectivity from external client, and return connection refused", func() {
			icmpProto := "icmp"
			if s.testOpts.ipv6 {
				icmpProto = "icmp6"
			}

			tcpdump := s.externalClient.AttachTCPDump("any")
			tcpdump.SetLogEnabled(true)
			if s.testOpts.ipv6 {
				tcpdump.AddMatcher("unreach", regexp.MustCompile(`destination unreachable`))
				tcpdump.AddMatcher("bad csum", regexp.MustCompile(`bad icmp6 cksum`))
			} else {
				tcpdump.AddMatcher("unreach", regexp.MustCompile(`port \d+ unreachable`))
				tcpdump.AddMatcher("bad csum", regexp.MustCompile(`wrong icmp cksum`))
			}

			tcpdump.Start(s.infra, "-vv", s.testOpts.protocol, "port", strconv.Itoa(int(port)), "or", icmpProto)

			s.cc.Expect(None, s.externalClient, TargetIP(ip[0]),
				ExpectWithPorts(port),
				ExpectNoneWithError("connection refused"),
			)
			s.cc.CheckConnectivity()

			Eventually(func() int { return tcpdump.MatchCount("unreach") }, "5s", "300ms").
				Should(BeNumerically(">", 0))
			// XXX
			// Expect(tcpdump.MatchCount("bad csum")).To(Equal(0))
		})
	})

	Describe("Test load balancer service with external Client,src ranges", func() {
		if s.testOpts.connTimeEnabled {
			// FIXME s.externalClient also does conntime balancing
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
			if s.testOpts.ipv6 {
				ipRoute = append(ipRoute, "-6")
				srcIPRange = []string{"dead:beef::1:3/120"}
			}

			cmd := append(ipRoute[:len(ipRoute):len(ipRoute)],
				"route", "add", extIP, "via", s.felixIP(0))
			s.externalClient.Exec(cmd...)
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.containerIP(s.externalClient) + "/" + s.ipMask(),
						},
					},
				},
			}
			s.pol = s.updatePolicy(s.pol)
			cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
				"route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[1].Exec(cmd...)
			s.tc.Felixes[0].Exec(cmd...)
		})
		Context("Test LB-service with external Client's IP not in src range", func() {
			BeforeEach(func() {
				testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
					s.testOpts.protocol, externalIP, srcIPRange)
				ip = testSvc.Spec.ExternalIPs
				port = uint16(testSvc.Spec.Ports[0].Port)
			})
			It("should not have connectivity from external Client via external IP to workload 0", func() {
				s.cc.ExpectNone(s.externalClient, TargetIP(ip[0]), port)
				s.cc.CheckConnectivity()
			})
		})
		Context("Test LB-service with external Client's IP in src range", func() {
			BeforeEach(func() {
				srcIPRange = []string{s.externalClient.IP + "/32"}
				testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
					s.testOpts.protocol, externalIP, srcIPRange)
				ip = testSvc.Spec.ExternalIPs
				port = uint16(testSvc.Spec.Ports[0].Port)
			})
			It("should have connectivity from external Client via external IP to workload 0", func() {
				s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
				s.cc.CheckConnectivity()
			})
		})
	})

	Context("Test Service type transitions", func() {
		if s.testOpts.protocol != "tcp" {
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
			testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoints didn't get created. Is controller-manager happy?")
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
		})

		It("should have connectivity from all workloads via a service to workload 0", func() {
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			w00Expects := []ExpectationOption{ExpectWithPorts(port)}
			hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
			if s.testOpts.ipv6 {
				hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
				switch s.testOpts.tunnel {
				case "vxlan":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
				case "wireguard":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
				}
			}
			switch s.testOpts.tunnel {
			case "ipip":
				hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
			}

			if !s.testOpts.connTimeEnabled {
				w00Expects = append(w00Expects, hostW0SrcIP)
			}

			s.cc.Expect(Some, s.w[0][0], TargetIP(ip), w00Expects...)
			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip), port)
			s.cc.ExpectSome(s.w[1][1], TargetIP(ip), port)
			s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
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
				testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol, externalIP)
				k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
			})

			It("should have connectivity from all workloads via external IP to workload 0", func() {
				ip := testSvcWithExtIP.Spec.ExternalIPs
				port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
				s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
				s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
			})
			Context("change service type from external IP to LoadBalancer", func() {
				srcIPRange := []string{}
				var testSvcLB *v1.Service
				BeforeEach(func() {
					testSvcLB = k8sLBService(testSvcName, clusterIP, s.w[0][0].Name, 80, tgtPort, s.testOpts.protocol,
						externalIP, srcIPRange)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
				})
				It("should have connectivity from workload 0 to service via external IP", func() {
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
				})
			})

			Context("change Service type from external IP to nodeport", func() {
				var testSvcNodePort *v1.Service
				npPort := uint16(30333)
				BeforeEach(func() {
					testSvcNodePort = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, int32(npPort), s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
				})
				It("should have connectivity via the node port to workload 0", func() {
					node1IP := s.felixIP(1)
					s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)

					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity()
				})
			})
			Context("change service from external IP to cluster IP", func() {
				var testSvcWithoutExtIP *v1.Service
				BeforeEach(func() {
					testSvcWithoutExtIP = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithoutExtIP)
				})
				It("should not have connectivity to workload 0 via external IP", func() {
					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)

					clusterIP = testSvcWithoutExtIP.Spec.ClusterIP
					s.cc.ExpectSome(s.w[0][1], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(clusterIP), port)
					s.cc.CheckConnectivity()
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
				testSvcLB = k8sLBService(testSvcName, clusterIP, s.w[0][0].Name, 80, tgtPort, s.testOpts.protocol,
					externalIP, srcIPRange)
				k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
			})
			It("should have connectivity from workload 0 to service via external IP", func() {
				ip := testSvcLB.Spec.ExternalIPs
				port := uint16(testSvcLB.Spec.Ports[0].Port)
				s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
				s.cc.CheckConnectivity()
			})

			Context("change service from Loadbalancer to external IP", func() {
				var testSvcWithExtIP *v1.Service
				BeforeEach(func() {
					testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol, externalIP)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
				})

				It("should have connectivity from all workloads via external IP to workload 0", func() {
					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity()
				})
			})

			Context("change Service type from Loadbalancer to nodeport", func() {
				var testSvcNodePort *v1.Service
				npPort := uint16(30333)
				BeforeEach(func() {
					testSvcNodePort = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, int32(npPort), s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
				})
				It("should have connectivity via the node port to workload 0 and not via external IP", func() {
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)
					node1IP := s.felixIP(1)
					s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)
					s.cc.CheckConnectivity()
				})
			})
			Context("Change service type from LoadBalancer to cluster IP", func() {
				var testSvcClusterIP *v1.Service
				BeforeEach(func() {
					testSvcClusterIP = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcClusterIP)
				})
				It("should have connectivity to workload 0 via cluster IP and not external IP", func() {
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)

					clusterIP = testSvcClusterIP.Spec.ClusterIP

					s.cc.ExpectSome(s.w[0][1], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(clusterIP), port)
					s.cc.CheckConnectivity()
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
				testSvcNodePort = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, int32(npPort), s.testOpts.protocol)
				k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
			})
			It("should have connectivity via the node port to workload 0", func() {
				node1IP := s.felixIP(1)
				node1IPExt := s.tc.Felixes[1].ExternalIP
				s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[0][1], TargetIP(node1IPExt), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node1IPExt), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node1IPExt), npPort)
				s.cc.CheckConnectivity()
			})

			Context("change service type from nodeport to external IP", func() {
				var testSvcWithExtIP *v1.Service
				BeforeEach(func() {
					testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol, externalIP)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
				})
				It("should have connectivity via external IP to workload 0 and not node port", func() {
					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)

					node1IP := s.felixIP(1)
					s.cc.ExpectNone(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][1], TargetIP(node1IP), npPort)
					s.cc.CheckConnectivity()
				})
			})
			Context("change service type from nodeport to LoadBalancer", func() {
				srcIPRange := []string{}
				var testSvcLB *v1.Service
				BeforeEach(func() {
					testSvcLB = k8sLBService(testSvcName, clusterIP, s.w[0][0].Name, 80, tgtPort, s.testOpts.protocol,
						externalIP, srcIPRange)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
				})
				It("should have connectivity from workload 0 to service via external IP and via nodeport", func() {
					node1IP := s.felixIP(1)

					// Note: the behaviour expected here changed around k8s v1.20.  Previously, the API
					// server would allocate a new node port when we applied the load balancer update.
					// Now, it merges the two so the service keeps its existing NodePort.
					s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)

					// Either way, we expect the load balancer to show up.
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity()
				})
			})
			Context("Change service type from nodeport to cluster IP", func() {
				var testSvcClusterIP *v1.Service
				BeforeEach(func() {
					testSvcClusterIP = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcClusterIP)
				})
				It("should have connectivity to workload 0 via cluster IP and not via nodeport", func() {
					node1IP := s.felixIP(1)
					s.cc.ExpectNone(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][1], TargetIP(node1IP), npPort)

					clusterIP = testSvcClusterIP.Spec.ClusterIP
					port := uint16(testSvcClusterIP.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(clusterIP), port)
					s.cc.CheckConnectivity()
				})
			})
		})
	})

	Context("with test-service configured "+clusterIP+":80 -> s.w[0][0].IP:8055", func() {
		var (
			testSvc          *v1.Service
			testSvcNamespace string
		)

		testSvcName := "test-service"
		tgtPort := 8055

		BeforeEach(func() {
			testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoints didn't get created. Is controller-manager happy?")
		})

		It("should have connectivity from all workloads via a service to workload 0", func() {
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			w00Expects := []ExpectationOption{ExpectWithPorts(port)}
			hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
			if s.testOpts.ipv6 {
				hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
				switch s.testOpts.tunnel {
				case "vxlan":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
				case "wireguard":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
				}
			}
			switch s.testOpts.tunnel {
			case "ipip":
				hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
			}

			if !s.testOpts.connTimeEnabled {
				w00Expects = append(w00Expects, hostW0SrcIP)
			}

			s.cc.Expect(Some, s.w[0][0], TargetIP(ip), w00Expects...)
			s.cc.Expect(Some, s.w[0][1], TargetIP(ip), ExpectWithPorts(port))
			s.cc.Expect(Some, s.w[1][0], TargetIP(ip), ExpectWithPorts(port))
			s.cc.Expect(Some, s.w[1][1], TargetIP(ip), ExpectWithPorts(port))
			s.cc.CheckConnectivity()
		})

		It("should only have connectivity from the local host via a service to workload 0", func() {
			// Local host is always allowed (for kubelet health checks).
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			s.cc.ExpectSome(s.tc.Felixes[0], TargetIP(ip), port)
			s.cc.ExpectNone(s.tc.Felixes[1], TargetIP(ip), port)
			s.cc.CheckConnectivity()
		})

		Describe("after updating the policy to allow traffic from hosts", func() {
			BeforeEach(func() {
				s.pol.Spec.Ingress = []api.Rule{
					{
						Action: "Allow",
						Source: api.EntityRule{
							Selector: "ep-type == 'host'",
						},
					},
				}
				s.pol = s.updatePolicy(s.pol)
			})

			It("should have connectivity from the hosts via a service to workload 0", func() {
				ip := testSvc.Spec.ClusterIP
				port := uint16(testSvc.Spec.Ports[0].Port)

				s.cc.ExpectSome(s.tc.Felixes[0], TargetIP(ip), port)
				s.cc.ExpectSome(s.tc.Felixes[1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][0], TargetIP(ip), port)
				s.cc.CheckConnectivity()
			})
		})

		It("should have connectivity from workload via a service IP to a host-process listening on that IP", func() {
			By("Setting up a dummy service " + excludeSvcIP)
			svc := k8sService("dummy-service", excludeSvcIP, s.w[0][0] /* unimportant */, 8066, 8077, 0, s.testOpts.protocol)
			svc.Annotations = map[string]string{
				proxy.ExcludeServiceAnnotation: "true",
			}
			_, err := s.k8sClient.CoreV1().Services(testSvc.Namespace).
				Create(context.Background(), svc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			natFtKey := fmt.Sprintf("%s port %d proto %d", excludeSvcIP, 8066, s.numericProto)
			Eventually(func() map[string][]string {
				return s.tc.Felixes[0].BPFNATDump(s.testOpts.ipv6)
			}, "5s", "300ms").Should(HaveKey(natFtKey))

			By("Adding the service IP to the host")
			// Sort of what node-local-dns does
			s.tc.Felixes[0].Exec("ip", "link", "add", "dummy1", "type", "dummy")
			s.tc.Felixes[0].Exec("ip", "link", "set", "dummy1", "up")
			s.tc.Felixes[0].Exec("ip", "addr", "add", excludeSvcIP+"/"+s.ipMask(), "dev", "dummy1")

			By("Starting host workload")
			hostW := workload.Run(s.tc.Felixes[0], "dummy", "default",
				excludeSvcIP, "8066", s.testOpts.protocol, workload.WithHostNetworked())
			defer hostW.Stop()

			s.cc.Expect(Some, s.w[0][0], TargetIP(excludeSvcIP), ExpectWithPorts(8066))
			s.cc.CheckConnectivity()
		})

		It("should create sane conntrack entries and clean them up", func() {
			By("Generating some traffic")
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip), port)
			s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)

			By("Checking timestamps on conntrack entries are sane")
			// This test verifies that we correctly interpret conntrack entry timestamps by reading them back
			// and checking that they're (a) in the past and (b) sensibly recent.
			var (
				err    error
				ctDump string
			)

			if s.testOpts.ipv6 {
				ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "-6", "dump", "--raw")
			} else {
				ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump", "--raw")
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
				if s.testOpts.ipv6 {
					ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "-6", "dump", "--raw")
				} else {
					ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump", "--raw")
				}
				Expect(err).NotTo(HaveOccurred())
				return strings.Count(ctDump, s.w[0][0].IP)
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

				if s.testOpts.ipv6 {
					family = 6
					ipv6 := net.ParseIP(ip)
					oldK = nat.NewNATKeyV6(ipv6, portOld, s.numericProto)
				} else {
					ipv4 := net.ParseIP(ip)
					oldK = nat.NewNATKey(ipv4, portOld, s.numericProto)
				}

				// Wait for the NAT maps to converge...
				log.Info("Waiting for NAT maps to converge...")
				startTime := time.Now()
				for {
					if time.Since(startTime) > 5*time.Second {
						Fail("NAT maps failed to converge")
					}
					natBeforeUpdate, natBackBeforeUpdate, _ = dumpNATmapsAny(family, s.tc.Felixes)
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

				testSvcUpdated = k8sService(testSvcName, clusterIP, s.w[0][0], 88, 8055, 0, s.testOpts.protocol)

				svc, err := s.k8sClient.CoreV1().
					Services(testSvcNamespace).
					Get(context.Background(), testSvcName, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				testSvcUpdated.ResourceVersion = svc.ResourceVersion

				_, err = s.k8sClient.CoreV1().Services(testSvcNamespace).Update(context.Background(), testSvcUpdated, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
					"Service endpoints didn't get created. Is controller-manager happy?")
			})

			It("should have connectivity from all workloads via the new port", func() {
				ip := testSvcUpdated.Spec.ClusterIP
				port := uint16(testSvcUpdated.Spec.Ports[0].Port)

				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[1][0], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[1][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()
			})

			It("should not have connectivity from all workloads via the old port", func() {
				family := 4

				var oldK, natK nat.FrontendKeyInterface

				ip := testSvc.Spec.ClusterIP
				port := uint16(testSvc.Spec.Ports[0].Port)

				s.cc.ExpectNone(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][0], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				portOld := uint16(testSvc.Spec.Ports[0].Port)
				portNew := uint16(testSvcUpdated.Spec.Ports[0].Port)

				if s.testOpts.ipv6 {
					family = 6
					ipv6 := net.ParseIP(ip)
					oldK = nat.NewNATKeyV6(ipv6, portOld, s.numericProto)
					natK = nat.NewNATKeyV6(ipv6, portNew, s.numericProto)
				} else {
					ipv4 := net.ParseIP(ip)
					oldK = nat.NewNATKey(ipv4, portOld, s.numericProto)
					natK = nat.NewNATKey(ipv4, portNew, s.numericProto)
				}

				natmaps, natbacks, _ := dumpNATmapsAny(family, s.tc.Felixes)

				for i := range s.tc.Felixes {
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
				if s.testOpts.ipv6 {
					family = 6
					natK = nat.NewNATKeyV6(net.ParseIP(ip), port, s.numericProto)
				} else {
					natK = nat.NewNATKey(net.ParseIP(ip), port, s.numericProto)
				}

				var prevBpfsvcs []map[nat.FrontendKeyInterface]nat.FrontendValue

				Eventually(func() bool {
					prevBpfsvcs, _, _ = dumpNATmapsAny(family, s.tc.Felixes)
					for _, m := range prevBpfsvcs {
						if _, ok := m[natK]; !ok {
							return false
						}
					}
					return true
				}, "5s").Should(BeTrue(), "service NAT key didn't show up")

				err := s.k8sClient.CoreV1().
					Services(testSvcNamespace).
					Delete(context.Background(), testSvcName, metav1.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(0))

				s.cc.ExpectNone(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][0], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				for i, f := range s.tc.Felixes {
					natV := prevBpfsvcs[i][natK]
					bckCnt := natV.Count()
					bckID := natV.ID()

					Eventually(func() bool {
						svcs, eps, _ := dumpNATMapsAny(family, f)

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
				testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, 8055, 0, s.testOpts.protocol)
				testSvcNamespace = testSvc.Namespace
				// select all pods with port 8055
				testSvc.Spec.Selector = map[string]string{"port": "8055"}
				if setAffinity {
					testSvc.Spec.SessionAffinity = "ClientIP"
				}
				_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				// We have 3 backends all listening on port 8055.
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(3),
					"Service endpoints didn't get created? Is controller-manager happy?")
			})

			// Since the affinity map is shared by cgroup programs on
			// all nodes, we must be careful to use only client(s) on a
			// single node for the experiments.
			It("should have connectivity from a workload to a service with multiple backends", func() {
				affKV := func() (nat.AffinityKeyInterface, nat.AffinityValueInterface) {
					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						ExpectWithOffset(1, aff).To(HaveLen(1))

						// get the only key
						for k, v := range aff {
							return k, v
						}
					} else {
						aff := dumpAffMap(s.tc.Felixes[0])
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

					if s.testOpts.ipv6 {
						natFtKey = nat.NewNATKeyV6Intf(net.ParseIP(ip), port, s.numericProto)
						family = 6
					} else {
						natFtKey = nat.NewNATKeyIntf(net.ParseIP(ip), port, s.numericProto)
						family = 4
					}

					Eventually(func() bool {
						m, be, _ := dumpNATMapsAny(family, s.tc.Felixes[0])

						v, ok := m[natFtKey]
						if !ok || v.Count() == 0 {
							return false
						}

						beKey := nat.NewNATBackendKey(v.ID(), 0)

						_, ok = be[beKey]
						return ok
					}, 5*time.Second).Should(BeTrue())
				}

				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				_, val1 := affKV()

				s.cc.CheckConnectivity()

				_, v2 := affKV()

				// This should happen consistently, but that may take quite some time.
				Expect(val1.Backend()).To(Equal(v2.Backend()))

				s.cc.ResetExpectations()

				// N.B. Client must be on felix-0 to be subject to ctlb!
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				mkey, mVal := affKV()
				Expect(val1.Backend()).To(Equal(mVal.Backend()))

				netIP := net.ParseIP(ip)
				if s.testOpts.ipv6 {
					Expect(mkey.FrontendAffinityKey().AsBytes()).
						To(Equal(nat.NewNATKeyV6(netIP, port, s.numericProto).AsBytes()[4:24]))
				} else {
					Expect(mkey.FrontendAffinityKey().AsBytes()).
						To(Equal(nat.NewNATKey(netIP, port, s.numericProto).AsBytes()[4:12]))
				}

				Eventually(func() nat.BackendValueInterface {
					// Remove the affinity entry to emulate timer
					// expiring / no prior affinity.
					var m maps.Map
					if s.testOpts.ipv6 {
						m = nat.AffinityMapV6()
					} else {
						m = nat.AffinityMap()
					}
					cmd, err := maps.MapDeleteKeyCmd(m, mkey.AsBytes())
					Expect(err).NotTo(HaveOccurred())
					err = s.tc.Felixes[0].ExecMayFail(cmd...)
					if err != nil {
						Expect(err.Error()).To(ContainSubstring("No such file or directory"))
					}

					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(0))

						s.cc.CheckConnectivity()

						aff = dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(1))
						Expect(aff).To(HaveKey(mkey.(nat.AffinityKeyV6)))

						return aff[mkey.(nat.AffinityKeyV6)].Backend()
					}

					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(0))
					} else {
						aff := dumpAffMap(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(0))
					}

					s.cc.CheckConnectivity()

					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(1))
						Expect(aff).To(HaveKey(mkey.(nat.AffinityKeyV6)))
						return aff[mkey.(nat.AffinityKeyV6)].Backend()
					}

					aff := dumpAffMap(s.tc.Felixes[0])
					Expect(aff).To(HaveLen(1))
					Expect(aff).To(HaveKey(mkey.(nat.AffinityKey)))
					return aff[mkey.(nat.AffinityKey)].Backend()
				}, 60*time.Second, time.Second).ShouldNot(Equal(mVal.Backend()))
			})
		}

		Context("with affinity", func() {
			testMultiBackends(true)
		})

		if s.testOpts.protocol == "udp" && s.testOpts.udpUnConnected && s.testOpts.connTimeEnabled {
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
				testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, 8055, 0, s.testOpts.protocol)
				testSvcNamespace = testSvc.Namespace
				// select all pods with port 8055
				testSvc.Spec.Selector = map[string]string{"port": "8055"}
				testSvc.Spec.SessionAffinity = "ClientIP"
				_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(3),
					"Service endpoints didn't get created? Is controller-manager happy?")
			})

			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			By("Syncing with NAT tables", func() {
				// Sync with NAT tables to prevent creating extra entry when
				// CTLB misses but regular DNAT hits, but connection fails and
				// then CTLB succeeds.
				if s.testOpts.ipv6 {
					natFtKey = nat.NewNATKeyV6(net.ParseIP(ip), port, s.numericProto)
					family = 6
				} else {
					natFtKey = nat.NewNATKey(net.ParseIP(ip), port, s.numericProto)
					family = 4
				}
				Eventually(func() bool {
					m, be, _ := dumpNATMapsAny(family, s.tc.Felixes[0])
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
			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.CheckConnectivity()

			By("checking that affinity was created")
			if s.testOpts.ipv6 {
				aff := dumpAffMapV6(s.tc.Felixes[0])
				Expect(aff).To(HaveLen(1))
			} else {
				aff := dumpAffMap(s.tc.Felixes[0])
				Expect(aff).To(HaveLen(1))
			}

			// Stop the original backends so that they are not
			// reachable with the set affinity.
			s.w[0][0].Stop()
			s.w[1][0].Stop()

			By("changing the service backend to completely different ones")
			testSvc8056 := k8sService(testSvcName, clusterIP, s.w[1][1], 80, 8056, 0, s.testOpts.protocol)
			testSvc8056.Spec.SessionAffinity = "ClientIP"
			k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvc8056)

			By("checking the affinity is cleaned up")
			Eventually(func() int {
				if s.testOpts.ipv6 {
					aff := dumpAffMapV6(s.tc.Felixes[0])
					return len(aff)
				} else {
					aff := dumpAffMap(s.tc.Felixes[0])
					return len(aff)
				}
			}).Should(Equal(0))

			By("making another connection to a new backend")
			ip = testSvc.Spec.ClusterIP
			port = uint16(testSvc.Spec.Ports[0].Port)

			s.cc.ResetExpectations()
			ip = testSvc8056.Spec.ClusterIP
			port = uint16(testSvc8056.Spec.Ports[0].Port)

			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.CheckConnectivity()
		})

		It("should have connectivity after a backend is replaced by a new one", func() {
			if s.testOpts.protocol == "udp" && s.testOpts.connTimeEnabled {
				return
			}
			var (
				testSvc          *v1.Service
				testSvcNamespace string
			)

			testSvcName := "test-service"

			By("Setting up the service", func() {
				testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, 8055, 0, s.testOpts.protocol)
				testSvcNamespace = testSvc.Namespace
				_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
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

				if s.testOpts.ipv6 {
					natFtKey = nat.NewNATKeyV6(net.ParseIP(ip), port, s.numericProto)
					family = 6
				} else {
					natFtKey = nat.NewNATKey(net.ParseIP(ip), port, s.numericProto)
					family = 4
				}
				Eventually(func() bool {
					m, be, _ := dumpNATMapsAny(family, s.tc.Felixes[1])

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
			s.cc.Expect(Some, s.w[1][1], s.w[0][0], ExpectWithPorts(8055))
			s.cc.CheckConnectivity()

			By("Starting a persistent connection to the service")
			pc := s.w[1][1].StartPersistentConnection(ip, int(port),
				workload.PersistentConnectionOpts{
					MonitorConnectivity: true,
					Timeout:             60 * time.Second,
				},
			)
			if s.testOpts.protocol != "tcp" {
				defer pc.Stop()
			}

			By("Testing connectivity")
			prevCount := pc.PongCount()
			Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
				"Expected to see pong responses on the connection but didn't receive any")

			By("changing the service backend to completely different ones")
			testSvc2 := k8sService(testSvcName, clusterIP, s.w[1][0], 80, 8055, 0, s.testOpts.protocol)
			k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvc2)

			var tcpd *tcpdump.TCPDump
			if s.testOpts.protocol == "tcp" {
				iface := s.w[1][1].InterfaceName
				srcIP := clusterIP
				tcpdHost := s.tc.Felixes[1]
				if s.testOpts.connTimeEnabled {
					iface = "eth0"
					switch s.testOpts.tunnel {
					case "vxlan":
						iface = "vxlan.calico"
					case "wireguard":
						iface = "wireguard.cali"
						if s.testOpts.ipv6 {
							iface = "wireguard.cali-v6"
						}
					case "ipip":
						iface = "tunl0"
					}
					srcIP = s.w[0][0].IP
					tcpdHost = s.tc.Felixes[0]
				}
				tcpd = tcpdHost.AttachTCPDump(iface)
				tcpd.SetLogEnabled(true)

				ipRegex := "IP"
				if s.testOpts.ipv6 {
					ipRegex = "IP6"
				}
				tcpd.AddMatcher("tcp-rst",
					regexp.MustCompile(fmt.Sprintf(`%s %s\.\d+ > %s\.\d+: Flags \[[^\]]*R[^\]]*\]`, ipRegex, srcIP, s.w[1][1].IP)))
				tcpd.Start(s.infra)
			}

			By("Stopping the original backend to make sure it is not reachable")
			s.w[0][0].Stop()
			By("removing the old workload from infra")
			s.w[0][0].RemoveFromInfra(s.infra)

			By("Testing connectivity continues")
			if s.testOpts.protocol == "tcp" {
				Eventually(func() int { return tcpd.MatchCount("tcp-rst") }, "25s").ShouldNot(BeZero(),
					"Expected to see TCP RSTs on the connection after backend change")
				Expect(pc.IsConnectionReset()).To(BeTrue())
			} else {
				prevCount = pc.PongCount()
				Eventually(pc.PongCount, "15s").Should(BeNumerically(">", prevCount),
					"Expected to see pong responses on the connection but didn't receive any")
			}
		})
	})

}

func describeBPFNodePortTests(s *bpfTestContext, clusterIP, loIP string) {
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
		if s.testOpts.ipv6 {
			testSvcExtIP0 = net.ParseIP("dead:beef::123:0:0:0").String()
			testSvcExtIP1 = net.ParseIP("dead:beef::123:0:0:1").String()
		}

		BeforeEach(func() {
			s.k8sClient = s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			testSvc = k8sService(testSvcName, clusterIP,
				s.w[0][0], 80, 8055, int32(npPort), s.testOpts.protocol)
			testSvc.Spec.ExternalIPs = []string{testSvcExtIP0, testSvcExtIP1}
			if extLocal {
				testSvc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
			}
			if intLocal {
				internalLocal := v1.ServiceInternalTrafficPolicyLocal
				testSvc.Spec.InternalTrafficPolicy = &internalLocal
			}
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
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
			hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
			if s.testOpts.ipv6 {
				hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
				switch s.testOpts.tunnel {
				case "vxlan":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
				case "wireguard":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
				}
			}
			switch s.testOpts.tunnel {
			case "ipip":
				hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
			}

			if !s.testOpts.connTimeEnabled {
				w00Expects = append(w00Expects, hostW0SrcIP)
			}

			s.cc.Expect(Some, s.w[0][0], TargetIP(clusterIP), w00Expects...)
			s.cc.Expect(Some, s.w[0][1], TargetIP(clusterIP), ExpectWithPorts(port))
			s.cc.Expect(exp, s.w[1][0], TargetIP(clusterIP), ExpectWithPorts(port))
			s.cc.Expect(exp, s.w[1][1], TargetIP(clusterIP), ExpectWithPorts(port))
			s.cc.CheckConnectivity()
		})

		if intLocal {
			It("should not have connectivity from all workloads via a nodeport to non-local workload 0", func() {
				By("Checking connectivity")

				node0IP := s.felixIP(0)
				node1IP := s.felixIP(1)

				// Should work through the nodeport from a pod on the node where the backend is
				s.cc.ExpectSome(s.w[0][1], TargetIP(node0IP), npPort)

				// Should not work through the nodeport from a node where the backend is not.
				s.cc.ExpectNone(s.w[1][0], TargetIP(node0IP), npPort)
				s.cc.ExpectNone(s.w[1][1], TargetIP(node0IP), npPort)
				s.cc.ExpectNone(s.w[0][1], TargetIP(node1IP), npPort)
				s.cc.ExpectNone(s.w[1][0], TargetIP(node1IP), npPort)
				s.cc.ExpectNone(s.w[1][1], TargetIP(node1IP), npPort)

				s.cc.CheckConnectivity()

				// Enough to test for one protocol
				if s.testIfTCP {
					By("checking correct NAT entries for remote nodeports")

					ipOK := []string{
						"255.255.255.255", "10.101.0.1", "dead:beef::abcd:0:0:1", /* API server */
						testSvc.Spec.ClusterIP, testSvcExtIP0, testSvcExtIP1,
						s.felixIP(0), s.felixIP(1), s.felixIP(2),
					}

					if s.testOpts.tunnel == "ipip" {
						ipOK = append(ipOK, s.tc.Felixes[0].ExpectedIPIPTunnelAddr,
							s.tc.Felixes[1].ExpectedIPIPTunnelAddr, s.tc.Felixes[2].ExpectedIPIPTunnelAddr)
					}
					if s.testOpts.tunnel == "vxlan" {
						if s.testOpts.ipv6 {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr,
								s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr, s.tc.Felixes[2].ExpectedVXLANV6TunnelAddr)
						} else {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedVXLANTunnelAddr,
								s.tc.Felixes[1].ExpectedVXLANTunnelAddr, s.tc.Felixes[2].ExpectedVXLANTunnelAddr)
						}
					}
					if s.testOpts.tunnel == "wireguard" {
						if s.testOpts.ipv6 {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr,
								s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr, s.tc.Felixes[2].ExpectedWireguardV6TunnelAddr)
						} else {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedWireguardTunnelAddr,
								s.tc.Felixes[1].ExpectedWireguardTunnelAddr, s.tc.Felixes[2].ExpectedWireguardTunnelAddr)
						}
					}

					if s.testOpts.ipv6 {
						family = 6
						feKey = nat.NewNATKeyV6(net.ParseIP(s.felixIP(0)), npPort, 6)
					} else {
						family = 4
						feKey = nat.NewNATKey(net.ParseIP(s.felixIP(0)), npPort, 6)
					}

					for _, felix := range s.tc.Felixes {
						fe, _, _ := dumpNATMapsAny(family, felix)
						for key := range fe {
							Expect(key.Addr().String()).To(BeElementOf(ipOK))
						}
					}

					// RemoteNodeport on node 0
					fe, _, _ := dumpNATMapsAny(family, s.tc.Felixes[0])
					Expect(fe).To(HaveKey(feKey))
					be := fe[feKey]
					Expect(be.Count()).To(Equal(uint32(1)))
					Expect(be.LocalCount()).To(Equal(uint32(1)))

					// RemoteNodeport on node 1
					fe, _, _ = dumpNATMapsAny(family, s.tc.Felixes[1])
					Expect(fe).To(HaveKey(feKey))
					be = fe[feKey]
					Expect(be.Count()).To(Equal(uint32(1)))
					Expect(be.LocalCount()).To(Equal(uint32(0)))
				}
			})
		} else if !extLocal && !intLocal {
			It("should have connectivity from all workloads via a nodeport to workload 0", func() {
				node0IP := s.felixIP(0)
				node1IP := s.felixIP(1)

				s.cc.ExpectSome(s.w[0][1], TargetIP(node0IP), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node0IP), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node0IP), npPort)

				s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)

				s.cc.CheckConnectivity()
			})

			Describe("with policy enabling ingress to s.w[0][0] from host endpoints", func() {
				BeforeEach(func() {
					s.pol = api.NewGlobalNetworkPolicy()
					s.pol.Namespace = "fv"
					s.pol.Name = "policy-host-eps"
					s.pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "ep-type=='host'",
							},
						},
						{
							Action: "Allow",
							Source: api.EntityRule{
								Nets: []string{testSvcExtIP0 + "/" + s.ipMask(), testSvcExtIP1 + "/" + s.ipMask()},
							},
						},
					}
					w00Selector := fmt.Sprintf("name=='%s'", s.w[0][0].Name)
					s.pol.Spec.Selector = w00Selector

					s.pol = s.createPolicy(s.pol)
				})

				It("should have connectivity from all host-networked workloads to workload 0 via nodeport", func() {
					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)

					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)

					if s.testOpts.ipv6 {
						switch s.testOpts.tunnel {
						case "wireguard":
							if s.testOpts.connTimeEnabled {
								hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
							}
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
						case "vxlan":
							if s.testOpts.connTimeEnabled {
								hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
							}
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
						}
					} else {
						switch s.testOpts.tunnel {
						case "ipip":
							if s.testOpts.connTimeEnabled {
								hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
							}
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
						case "wireguard":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						case "vxlan":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}

					ports := ExpectWithPorts(npPort)

					s.cc.Expect(Some, s.hostW[0], TargetIP(node0IP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[0], TargetIP(node1IP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(node0IP), ports, hostW1SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(node1IP), ports, hostW1SrcIP)

					s.cc.CheckConnectivity()
				})

				It("should have connectivity from all host-networked workloads to workload 0 via ExternalIP", func() {
					if s.testOpts.connTimeEnabled {
						// not valid for CTLB as it is just and approx.
						return
					}
					// This test is primarily to make sure that the external
					// IPs do not interfere with the workaround and vise
					// versa.
					By("Setting ExternalIPs")
					s.tc.Felixes[0].Exec("ip", "addr", "add", testSvcExtIP0+"/"+s.ipMask(), "dev", "eth0")
					s.tc.Felixes[1].Exec("ip", "addr", "add", testSvcExtIP1+"/"+s.ipMask(), "dev", "eth0")

					ipRoute := []string{"ip"}
					if s.testOpts.ipv6 {
						ipRoute = append(ipRoute, "-6")
					}

					// The external IPs must be routable
					By("Setting routes for the ExternalIPs")
					cmd := append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP1+"/"+s.ipMask(), "via", s.felixIP(1))
					s.tc.Felixes[0].Exec(cmd...)
					cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP0+"/"+s.ipMask(), "via", s.felixIP(0))
					s.tc.Felixes[1].Exec(cmd...)
					cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP1+"/"+s.ipMask(), "via", s.felixIP(1))
					s.externalClient.Exec(cmd...)
					cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP0+"/"+s.ipMask(), "via", s.felixIP(0))
					s.externalClient.Exec(cmd...)

					By("Allow ingress from external client", func() {
						s.pol = api.NewGlobalNetworkPolicy()
						s.pol.Namespace = "fv"
						s.pol.Name = "policy-ext-client"
						s.pol.Spec.Ingress = []api.Rule{
							{
								Action: "Allow",
								Source: api.EntityRule{
									Nets: []string{s.containerIP(s.externalClient) + "/" + s.ipMask()},
								},
							},
						}
						w00Selector := fmt.Sprintf("name=='%s'", s.w[0][0].Name)
						s.pol.Spec.Selector = w00Selector

						s.pol = s.createPolicy(s.pol)
					})

					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)

					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)
					hostW11SrcIP := ExpectWithSrcIPs(testSvcExtIP1)

					if s.testOpts.ipv6 {
						switch s.testOpts.tunnel {
						case "none":
							hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
							hostW1SrcIP = ExpectWithSrcIPs(testSvcExtIP1)
						case "wireguard":
							hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
						case "vxlan":
							hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
						}
					} else {
						switch s.testOpts.tunnel {
						case "ipip":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
						case "wireguard":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						case "vxlan":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}

					ports := ExpectWithPorts(80)

					s.cc.Expect(Some, s.hostW[0], TargetIP(testSvcExtIP0), ports, ExpectWithSrcIPs(testSvcExtIP0))
					s.cc.Expect(Some, s.hostW[1], TargetIP(testSvcExtIP0), ports, hostW1SrcIP)
					s.cc.Expect(Some, s.hostW[0], TargetIP(testSvcExtIP1), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(testSvcExtIP1), ports, hostW11SrcIP)

					s.cc.Expect(Some, s.externalClient, TargetIP(testSvcExtIP0), ports)
					s.cc.Expect(Some, s.externalClient, TargetIP(testSvcExtIP1), ports)

					s.cc.CheckConnectivity()
				})

				_ = s.testIfNotUDPUConnected && // two app with two sockets cannot conflict
					Context("with conflict from host-networked workloads via clusterIP and directly", func() {
						JustBeforeEach(func() {
							for i, felix := range s.tc.Felixes {
								f := felix
								idx := i
								Eventually(func() bool {
									return checkServiceRoute(f, testSvc.Spec.ClusterIP)
								}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(),
									fmt.Sprintf("felix %d failed to sync with service", idx))

								if s.testOpts.ipv6 {
									felix.Exec("ip", "-6", "route")
								} else {
									felix.Exec("ip", "route")
								}
							}
						})
						if !s.testOpts.connTimeEnabled {
							It("should have connection when via clusterIP starts first", func() {
								node1IP := s.felixIP(1)

								hostW1SrcIP := ExpectWithSrcIPs(node1IP)

								switch s.testOpts.tunnel {
								case "ipip":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
								case "wireguard":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
									}
								case "vxlan":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
									}
								}

								clusterIP := testSvc.Spec.ClusterIP
								port := uint16(testSvc.Spec.Ports[0].Port)

								By("syncing with service programming")
								ports := ExpectWithPorts(port)
								s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)
								s.cc.CheckConnectivity()
								s.cc.ResetExpectations()

								By("starting a persistent connection to cluster IP")
								pc := s.hostW[1].StartPersistentConnection(clusterIP, int(port),
									workload.PersistentConnectionOpts{
										SourcePort:          12345,
										MonitorConnectivity: true,
									},
								)
								defer pc.Stop()

								s.cc.Expect(Some, s.hostW[1], s.w[0][0], hostW1SrcIP, ExpectWithSrcPort(12345))
								s.cc.CheckConnectivity()

								prevCount := pc.PongCount()
								Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
									"Expected to see pong responses on the connection but didn't receive any")
							})

							It("should have connection when direct starts first", func() {
								node1IP := s.felixIP(1)

								hostW1SrcIP := ExpectWithSrcIPs(node1IP)

								switch s.testOpts.tunnel {
								case "ipip":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
								case "wireguard":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
									}
								case "vxlan":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
									}
								}

								clusterIP := testSvc.Spec.ClusterIP
								port := uint16(testSvc.Spec.Ports[0].Port)

								By("syncing with service programming")
								ports := ExpectWithPorts(port)
								s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)
								s.cc.CheckConnectivity()
								s.cc.ResetExpectations()

								By("starting a persistent connection directly")
								pc := s.hostW[1].StartPersistentConnection(s.w[0][0].IP, 8055,
									workload.PersistentConnectionOpts{
										SourcePort:          12345,
										MonitorConnectivity: true,
									},
								)
								defer pc.Stop()

								s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports,
									hostW1SrcIP, ExpectWithSrcPort(12345))
								s.cc.CheckConnectivity()

								prevCount := pc.PongCount()
								Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
									"Expected to see pong responses on the connection but didn't receive any")
							})
						}
					})

				It("should have connectivity from all host-networked workloads to workload 0 via clusterIP", func() {
					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)

					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)

					switch s.testOpts.tunnel {
					case "ipip":
						if s.testOpts.connTimeEnabled {
							hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
						}
						hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
					case "wireguard":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
							hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						}
					case "vxlan":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
							hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}

					clusterIP := testSvc.Spec.ClusterIP
					ports := ExpectWithPorts(uint16(testSvc.Spec.Ports[0].Port))

					s.tc.Felixes[0].Exec("sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0")
					s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0")

					// Also try host networked pods, both on a local and remote node.
					s.cc.Expect(Some, s.hostW[0], TargetIP(clusterIP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)

					if s.testOpts.protocol == "tcp" && !s.testOpts.ipv6 {
						// Also excercise ipv4 as ipv6
						s.cc.Expect(Some, s.hostW[0], TargetIPv4AsIPv6(clusterIP), ports, hostW0SrcIP)
						s.cc.Expect(Some, s.hostW[1], TargetIPv4AsIPv6(clusterIP), ports, hostW1SrcIP)
					}

					s.cc.CheckConnectivity()
				})

				It("should have connectivity from all host-networked workloads to workload 0 "+
					"via clusterIP with non-routable address set on lo", func() {
					// It only makes sense for turned off CTLB as with CTLB routing
					// picks the right source IP.
					if s.testOpts.connTimeEnabled {
						return
					}
					By("Configuring ip on lo")
					s.tc.Felixes[0].Exec("ip", "addr", "add", loIP+"/"+s.ipMask(), "dev", "lo")
					s.tc.Felixes[1].Exec("ip", "addr", "add", loIP+"/"+s.ipMask(), "dev", "lo")

					By("testing connectivity")

					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)
					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)

					switch s.testOpts.tunnel {
					case "ipip":
						hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
					case "wireguard":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						}
					case "vxlan":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}
					clusterIP := testSvc.Spec.ClusterIP
					ports := ExpectWithPorts(uint16(testSvc.Spec.Ports[0].Port))

					s.cc.Expect(Some, s.hostW[0], TargetIP(clusterIP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)

					s.cc.CheckConnectivity()
				})
			})
		}

		if intLocal {
			It("workload should have connectivity to self via local and not remote node", func() {
				w00Expects := []ExpectationOption{ExpectWithPorts(npPort)}
				hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
				if s.testOpts.ipv6 {
					hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
					switch s.testOpts.tunnel {
					case "vxlan":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
					case "wireguard":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
					}
				}
				switch s.testOpts.tunnel {
				case "ipip":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
				}

				if !s.testOpts.connTimeEnabled {
					w00Expects = append(w00Expects, hostW0SrcIP)
				}

				s.cc.Expect(None, s.w[0][0], TargetIP(s.felixIP(1)), w00Expects...)
				s.cc.Expect(Some, s.w[0][0], TargetIP(s.felixIP(0)), w00Expects...)
				s.cc.CheckConnectivity()
			})
		} else {
			It("should have connectivity from a workload via a nodeport on another node to workload 0", func() {
				ip := s.felixIP(1)

				s.cc.ExpectSome(s.w[2][1], TargetIP(ip), npPort)
				s.cc.CheckConnectivity()
			})

			It("workload should have connectivity to self via local/remote node", func() {
				w00Expects := []ExpectationOption{ExpectWithPorts(npPort)}
				hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
				if s.testOpts.ipv6 {
					switch s.testOpts.tunnel {
					case "wireguard":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
					case "vxlan":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
					}
				} else {
					switch s.testOpts.tunnel {
					case "ipip":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
					}
				}

				if !s.testOpts.connTimeEnabled {
					w00Expects = append(w00Expects, hostW0SrcIP)
				}

				s.cc.Expect(Some, s.w[0][0], TargetIP(s.felixIP(1)), w00Expects...)
				s.cc.Expect(Some, s.w[0][0], TargetIP(s.felixIP(0)), w00Expects...)
				s.cc.CheckConnectivity()
			})
		}

		It("should not have connectivity from external to w[0] via local/remote node", func() {
			s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
			s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(0)), npPort)
			// Include a check that goes via the local nodeport to make sure the dataplane has converged.
			s.cc.ExpectSome(s.w[0][1], TargetIP(s.felixIP(0)), npPort)
			s.cc.CheckConnectivity()
		})

		Describe("after updating the policy to allow traffic from s.externalClient", func() {
			BeforeEach(func() {
				extClIP := s.externalClient.IP + "/32"
				if s.testOpts.ipv6 {
					extClIP = s.externalClient.IPv6 + "/128"
				}
				s.pol.Spec.Ingress = []api.Rule{
					{
						Action: "Allow",
						Source: api.EntityRule{
							Nets: []string{extClIP},
						},
					},
				}
				s.pol = s.updatePolicy(s.pol)
			})

			if extLocal && !s.testOpts.connTimeEnabled {
				It("should not have connectivity from external to w[0] via node1->node0 fwd", func() {
					s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
					// Include a check that goes via the nodeport with a local backing pod to make sure the dataplane has converged.
					s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(0)), npPort)
					s.cc.CheckConnectivity()
				})
			} else if !s.testOpts.connTimeEnabled && !intLocal /* irrelevant option for extClient */ {
				It("should have connectivity from external to w[0] via node1->node0 fwd", func() {
					By("checking the connectivity and thus populating the  neigh table", func() {
						s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(1)), npPort)
						s.cc.CheckConnectivity()
					})

					// The test does not make sense in DSR mode as the neigh
					// table is not used on the return path.
					if !s.testOpts.dsr {
						var srcMAC, dstMAC string

						By("making sure that neigh table is populated", func() {
							var (
								out string
								err error
							)

							if s.testOpts.ipv6 {
								out, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "-6", "arp", "dump")
							} else {
								out, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "arp", "dump")
							}
							Expect(err).NotTo(HaveOccurred())

							arpRegexp := regexp.MustCompile(fmt.Sprintf(".*%s : (.*) -> (.*)", s.felixIP(1)))

							lines := strings.SplitSeq(out, "\n")
							for l := range lines {
								if strings.Contains(l, s.felixIP(1)) {
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
							tcpdump := s.tc.Felixes[0].AttachTCPDump("eth0")
							tcpdump.SetLogEnabled(true)
							tcpdump.AddMatcher("MACs", regexp.MustCompile(fmt.Sprintf("%s > %s", srcMAC, dstMAC)))
							tcpdump.Start(s.infra, "-e", "udp", "and", "src", s.felixIP(0), "and", "port", "4789")

							s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(1)), npPort)
							s.cc.CheckConnectivity()

							Eventually(func() int { return tcpdump.MatchCount("MACs") }).
								Should(BeNumerically(">", 0), "MACs do not match")
						})
					}
				})

				// Our unconnected test client cannot handle multiple streams. Two
				// clients cannot use the same local address. The connected case shows
				// that it works in principle.
				_ = s.testIfNotUDPUConnected && It("should not break connectivity with source port collision", func() {
					By("Synchronizing with policy and services")
					s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(0)), ExpectWithPorts(npPort))
					s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(1)), ExpectWithPorts(npPort))
					s.cc.CheckConnectivity()

					pc := &PersistentConnection{
						Runtime:             s.externalClient,
						RuntimeName:         s.externalClient.Name,
						IP:                  s.felixIP(0),
						Port:                int(npPort),
						SourcePort:          12345,
						Protocol:            s.testOpts.protocol,
						MonitorConnectivity: true,
					}

					err := pc.Start()
					Expect(err).NotTo(HaveOccurred())
					defer pc.Stop()

					Eventually(pc.PongCount, "5s").Should(
						BeNumerically(">", 0),
						"Expected to see pong responses on the connection but didn't receive any")
					log.Info("Pongs received within last 1s")

					s.cc.ResetExpectations()
					s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(1)),
						ExpectWithPorts(npPort), ExpectWithSrcPort(12345))
					s.cc.CheckConnectivity()

					prevCount := pc.PongCount()

					Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
						"Expected to see pong responses on the connection but didn't receive any")
					log.Info("Pongs received within last 1s")
				})

				_ = s.testIfTCP && It("should survive conntrack cleanup sweep", func() {
					By("checking the connectivity and thus syncing with service creation", func() {
						s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(1)), npPort)
						s.cc.CheckConnectivity()
					})

					By("monitoring a persistent connection", func() {
						pc := &PersistentConnection{
							Runtime:             s.externalClient,
							RuntimeName:         s.externalClient.Name,
							IP:                  s.felixIP(1),
							Port:                int(npPort),
							Protocol:            s.testOpts.protocol,
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
						for time.Since(start) < 2*timeouts.ScanPeriod {
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

				_ = s.testIfTCP && !s.testOpts.ipv6 && s.testOpts.bpfLogLevel == "debug" && !s.testOpts.dsr &&
					s.testOpts.tunnel != "vxlan" &&
					It("tcp should survive spurious RST", func() {
						s.externalClient.Exec("ip", "route", "add", s.w[0][0].IP, "via", s.felixIP(0))
						pc := &PersistentConnection{
							Runtime:             s.externalClient,
							RuntimeName:         s.externalClient.Name,
							IP:                  s.w[0][0].IP,
							Port:                8055,
							SourcePort:          54321,
							Protocol:            s.testOpts.protocol,
							MonitorConnectivity: true,
							Sleep:               21 * time.Second,
						}
						tcpdump := s.tc.Felixes[0].AttachTCPDump("eth0")
						tcpdump.SetLogEnabled(true)
						tcpdump.Start(s.infra, "tcp", "port", "8055")

						err := pc.Start()
						Expect(err).NotTo(HaveOccurred())
						defer pc.Stop()

						EventuallyWithOffset(1, pc.PongCount, "5s").Should(
							BeNumerically(">", 0),
							"Expected to see pong responses on the connection but didn't receive any")
						log.Info("Pongs received within last 1s")

						// Now we send a spurious RST, which would bring the connection
						// down as the pace is a PING every 21s so once a periodic
						// cleanup ticks the entry is older than the TCPResetSeen timer
						// of 5s (40s by default).
						err = s.externalClient.ExecMayFail("pktgen",
							s.containerIP(s.externalClient), s.w[0][0].IP, "tcp",
							"--port-src", "54321", "--port-dst", "8055", "--tcp-rst", "--tcp-seq-no=123456")
						Expect(err).NotTo(HaveOccurred())

						time.Sleep(200 * time.Millisecond)

						// This is quite a bit artificial. We send a totally random ACK.
						// If the connection was idle for TCPResetSeen timeout, we clean
						// it up no matter what. This random ack kinda mimics that the
						// connection is not idle. (1) our conntrack does not maintain
						// the "in-window" for simplicity so it will say, OK some data
						// still going through, don't rush to clean it up. (2) it
						// triggers a proper ACK from the receiver side and its
						// ACKnowledgement from the sender side as a response, so some
						// real traffic, but no data. It allows us to control things
						// more precisely than say keepalive and minic active
						// connection.
						err = s.externalClient.ExecMayFail("pktgen", s.containerIP(s.externalClient), s.w[0][0].IP, "tcp",
							"--port-src", "54321", "--port-dst", "8055", "--tcp-ack-no=87238974", "--tcp-seq-no=98793")
						Expect(err).NotTo(HaveOccurred())

						// We make sure that at least two iteration of the conntrack
						// cleanup executes and we periodically monitor the connection if
						// it is alive by checking that the number of PONGs keeps
						// increasing. The ct entry may not be old enough in the first
						// iteration yet.
						time.Sleep(3 * timeouts.ScanPeriod)
						prevCount := pc.PongCount()

						// Try log enough to see a ping-pong
						Eventually(pc.PongCount, "22s", "1s").Should(
							BeNumerically(">", prevCount),
							"No new pongs since the last iteration. Connection broken?")
					})

				if !s.testOpts.dsr {
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
						//                                      |    s.w[0][0].IP:8055
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
						if s.testOpts.ipv6 {
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
								C:             s.tc.Felixes[1].Container,
								IP:            eth20IP,
								Ports:         "57005", // 0xdead
								Protocol:      s.testOpts.protocol,
								InterfaceName: "eth20",
								MTU:           1500, // Need to match host MTU or felix will restart.
							}
							err := eth20.Start(s.infra)
							Expect(err).NotTo(HaveOccurred())

							// assign address to eth20 and add route to the .20 network
							if s.testOpts.ipv6 {
								s.tc.Felixes[1].Exec("ip", "-6", "route", "add", eth20Route, "dev", "eth20")
								s.tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
								_, err = eth20.RunCmd("ip", "-6", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
								Expect(err).NotTo(HaveOccurred())
								// Add a route to felix[1] to be able to reach the nodeport
								_, err = eth20.RunCmd("ip", "-6", "route", "add", s.felixIP(1)+"/"+mask, "via", eth20ExtIP)
								Expect(err).NotTo(HaveOccurred())
							} else {
								s.tc.Felixes[1].Exec("ip", "route", "add", eth20Route, "dev", "eth20")
								s.tc.Felixes[1].Exec("ip", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
								_, err = eth20.RunCmd("ip", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
								Expect(err).NotTo(HaveOccurred())
								// Add a route to felix[1] to be able to reach the nodeport
								_, err = eth20.RunCmd("ip", "route", "add", s.felixIP(1)+"/"+mask, "via", eth20ExtIP)
								Expect(err).NotTo(HaveOccurred())
								// This multi-NIC scenario works only if the kernel's RPF check
								// is not strict so we need to override it for the test and must
								// be set properly when product is deployed. We reply on
								// iptables to do require check for us.
								s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
								s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf.eth20.rp_filter=2")
							}
						})

						By("setting up routes to .20 net on dest node to trigger RPF check", func() {
							if s.testOpts.ipv6 {
								// set up a dummy interface just for the routing purpose
								s.tc.Felixes[0].Exec("ip", "-6", "link", "add", "dummy1", "type", "dummy")
								s.tc.Felixes[0].Exec("ip", "-6", "link", "set", "dummy1", "up")
								// set up route to the .20 net through the dummy iface. This
								// makes the .20 a universally reachable external world from the
								// internal/private eth0 network
								s.tc.Felixes[0].Exec("ip", "-6", "route", "add", eth20Route, "dev", "dummy1")
							} else {
								// set up a dummy interface just for the routing purpose
								s.tc.Felixes[0].Exec("ip", "link", "add", "dummy1", "type", "dummy")
								s.tc.Felixes[0].Exec("ip", "link", "set", "dummy1", "up")
								// set up route to the .20 net through the dummy iface. This
								// makes the .20 a universally reachable external world from the
								// internal/private eth0 network
								s.tc.Felixes[0].Exec("ip", "route", "add", eth20Route, "dev", "dummy1")
								// This multi-NIC scenario works only if the kernel's RPF check
								// is not strict so we need to override it for the test and must
								// be set properly when product is deployed. We reply on
								// iptables to do require check for us.
								s.tc.Felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
								s.tc.Felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.dummy1.rp_filter=2")
							}
						})

						By("Allowing traffic from the eth20 network", func() {
							s.pol.Spec.Ingress = []api.Rule{
								{
									Action: "Allow",
									Source: api.EntityRule{
										Nets: []string{
											eth20.IP + "/" + s.ipMask(),
										},
									},
								},
							}
							s.pol = s.updatePolicy(s.pol)
						})

						By("Checking that there is connectivity from eth20 network", func() {
							s.cc.ExpectSome(eth20, TargetIP(s.felixIP(1)), npPort)
							s.cc.CheckConnectivity()
						})
					})
				}

				if s.testOpts.protocol == "tcp" {

					const (
						hostIfaceMTU = 1500
						podIfaceMTU  = 1450
						sendLen      = hostIfaceMTU
						recvLen      = podIfaceMTU
					)

					Context("with TCP, tx/rx close to MTU size on NP via node1->node0 ", func() {
						It("should not adjust MTU on client side if GRO off on nodes", func() {
							// force non-GSO packets on node ingress
							err := s.tc.Felixes[1].ExecMayFail("ethtool", "-K", "eth0", "gro", "off")
							Expect(err).NotTo(HaveOccurred())

							s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(1)),
								ExpectWithPorts(npPort),
								ExpectWithSendLen(sendLen),
								ExpectWithRecvLen(recvLen),
								ExpectWithClientAdjustedMTU(hostIfaceMTU, hostIfaceMTU),
							)
							s.cc.CheckConnectivity()
						})
					})
				}
			}

			if !s.testOpts.connTimeEnabled {
				It("should have connectivity from external to w[0] via node0", func() {
					log.WithFields(log.Fields{
						"externalClientIP": s.containerIP(s.externalClient),
						"nodePortIP":       s.felixIP(1),
					}).Infof("external->nodeport connection")

					s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(0)), npPort)
					s.cc.CheckConnectivity()
				})
			}
		})
	}

	Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort)), func() {
		nodePortsTest(false, false)

		if !s.testOpts.connTimeEnabled && s.testOpts.tunnel == "none" &&
			s.testOpts.protocol == "tcp" && !s.testOpts.dsr {
			Context("with small MTU between remote client and cluster", func() {
				var remoteWL *workload.Workload
				hostNP := uint16(30555)

				BeforeEach(func() {
					remoteWL = &workload.Workload{
						C:             s.externalClient,
						Name:          "remoteWL",
						InterfaceName: "ethwl",
						Protocol:      s.testOpts.protocol,
						MTU:           1500,
					}

					remoteWLIP := "192.168.15.15"
					remoteWL.IP = remoteWLIP
					if s.testOpts.ipv6 {
						remoteWLIP = "dead:beef:1515::1515"
						remoteWL.IP6 = remoteWLIP
					}

					err := remoteWL.Start(s.infra)
					Expect(err).NotTo(HaveOccurred())

					clusterIP := "10.101.0.211"
					if s.testOpts.ipv6 {
						clusterIP = "dead:beef::abcd:0:0:211"
					}

					svcHostNP := k8sService("test-host-np", clusterIP, s.hostW[0], 81, 8055, int32(hostNP), s.testOpts.protocol)
					testSvcNamespace := svcHostNP.Namespace
					_, err = s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), svcHostNP, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(checkSvcEndpoints(s.k8sClient, svcHostNP), "10s").Should(Equal(1),
						"Service endpoints didn't get created? Is controller-manager happy?")

					if s.testOpts.ipv6 {
						s.externalClient.Exec("ip", "-6", "route", "add", remoteWLIP, "dev",
							remoteWL.InterfaceName, "scope", "link")
						s.externalClient.Exec("ip", "-6", "route", "add", s.w[0][0].IP, "via", s.tc.Felixes[0].IPv6, "dev", "eth0")
						s.externalClient.Exec("ip", "addr", "add", "169.254.169.254", "dev", remoteWL.InterfaceName)
						// Need to change the MTU on the host side of the veth. If
						// we change it on the eth0 of the docker iface, no ICMP
						// is generated.
						s.externalClient.Exec("ip", "link", "set", "ethwl", "mtu", "1300")
						for _, f := range s.tc.Felixes {
							f.Exec("ip", "-6", "route", "add", remoteWLIP,
								"via", s.externalClient.IPv6, "dev", "eth0")
						}
					} else {
						s.externalClient.Exec("ip", "route", "add", remoteWLIP, "dev",
							remoteWL.InterfaceName, "scope", "link")
						s.externalClient.Exec("ip", "route", "add", s.w[0][0].IP, "via", s.tc.Felixes[0].IP, "dev", "eth0")
						s.externalClient.Exec("ip", "addr", "add", "169.254.169.254", "dev", remoteWL.InterfaceName)
						// Need to change the MTU on the host side of the veth. If
						// we change it on the eth0 of the docker iface, not ICMP
						// is generated.
						s.externalClient.Exec("ip", "link", "set", "ethwl", "mtu", "1300")
						for _, f := range s.tc.Felixes {
							f.Exec("ip", "route", "add", remoteWLIP,
								"via", s.externalClient.IP, "dev", "eth0")
						}
					}

					s.pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Nets: []string{remoteWLIP + "/" + s.ipMask()},
							},
						},
					}
					s.pol = s.updatePolicy(s.pol)
				})

				It("should have connectivity to service backend", func() {
					tcpdump := s.w[0][0].AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					tcpdump.AddMatcher("mtu-1300", regexp.MustCompile("mtu 1300"))
					tcpdump.Start(s.infra, "-vvv", "icmp", "or", "icmp6")

					ipRouteFlushCache := []string{"ip", "route", "flush", "cache"}
					if s.testOpts.ipv6 {
						ipRouteFlushCache = []string{"ip", "-6", "route", "flush", "cache"}
					}

					By("Trying directly to pod")
					s.w[0][0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, s.w[0][0], ExpectWithPorts(8055), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying directly to node with pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.w[0][0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(0)), ExpectWithPorts(npPort), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying to node without pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.w[0][0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(1)), ExpectWithPorts(npPort), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))
				})

				It("should have connectivity to service host-networked backend", func() {
					tcpdump := s.tc.Felixes[0].AttachTCPDump("eth0")
					tcpdump.SetLogEnabled(true)
					tcpdump.AddMatcher("mtu-1300", regexp.MustCompile("mtu 1300"))
					// we also need to watch for the ICMP forwarded to the host with the backend via VXLAN
					tcpdump.Start(s.infra, "-vvv", "icmp", "or", "icmp6", "or", "udp", "port", "4789")

					ipRouteFlushCache := []string{"ip", "route", "flush", "cache"}
					if s.testOpts.ipv6 {
						ipRouteFlushCache = []string{"ip", "-6", "route", "flush", "cache"}
					}

					By("Trying directly to host")
					s.tc.Felixes[0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, s.hostW[0], ExpectWithPorts(8055), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying directly to node with pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.tc.Felixes[0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(0)), ExpectWithPorts(hostNP), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying to node without pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.tc.Felixes[0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(1)), ExpectWithPorts(hostNP), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					// tpcudmp for some reason does not print content of the vxlan
					// packet when it is over ipv6
					if !s.testOpts.ipv6 {
						Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))
					}
				})
			})
		}
	})

	// FIXME connect time shares the same NAT table and it is a lottery which one it gets
	if !s.testOpts.connTimeEnabled {
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
		if s.testOpts.ipv6 {
			nets = []string{"::/0"}
		}

		BeforeEach(func() {
			icmpProto := numorstring.ProtocolFromString("icmp")
			if s.testOpts.ipv6 {
				icmpProto = numorstring.ProtocolFromString("icmpv6")
			}
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: nets,
					},
				},
			}
			s.pol.Spec.Egress = []api.Rule{
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
			s.pol = s.updatePolicy(s.pol)
		})

		var tgtPort int
		var tgtWorkload *workload.Workload

		JustBeforeEach(func() {
			s.k8sClient = s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			testSvc = k8sService(testSvcName, clusterIP,
				tgtWorkload, 80, tgtPort, int32(npPort), s.testOpts.protocol)
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoints didn't get created? Is controller-manager happy?")

			// Sync with all felixes because some fwd tests with "none"
			// connectivity need this to be set on all sides as they will not
			// retry when there is no connectivity.
			Eventually(func() bool {
				for _, flx := range s.tc.Felixes {
					var (
						family   int
						natFtKey nat.FrontendKeyInterface
					)

					if s.testOpts.ipv6 {
						natFtKey = nat.NewNATKeyV6Intf(net.ParseIP(s.containerIP(flx.Container)), npPort, s.numericProto)
						family = 6
					} else {
						natFtKey = nat.NewNATKeyIntf(net.ParseIP(s.containerIP(flx.Container)), npPort, s.numericProto)
						family = 4
					}

					m, be, _ := dumpNATMapsAny(family, flx)
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
			s.cc.ExpectSome(s.w[1][0], s.w[0][0])
			s.cc.CheckConnectivity()
		})

		icmpProto := "icmp"
		if s.testOpts.ipv6 {
			icmpProto = "icmp6"
		}

		Describe("with dead workload", func() {
			if s.testOpts.connTimeEnabled {
				// FIXME s.externalClient also does conntime balancing
				return
			}

			BeforeEach(func() {
				s.deadWorkload.ConfigureInInfra(s.infra)
				tgtPort = 8057
				tgtWorkload = s.deadWorkload
			})

			It("should get host unreachable from nodeport via node1->node0 fwd", func() {
				err := s.tc.Felixes[0].ExecMayFail("ip", "route", "add", "unreachable", s.deadWorkload.IP)
				Expect(err).NotTo(HaveOccurred())

				tcpdump := s.externalClient.AttachTCPDump("any")
				tcpdump.SetLogEnabled(true)
				var matcher string
				if s.testOpts.ipv6 {
					matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable route %s",
						s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1))
				} else {
					matcher = fmt.Sprintf("IP %s > %s: ICMP host %s unreachable",
						s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1))
				}
				tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
				tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)

				s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
				s.cc.CheckConnectivity()

				Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
					Should(BeNumerically(">", 0), matcher)
			})
		})

		Describe("with wrong target port", func() {
			// TCP would send RST instead of ICMP, it is enough to test one way of
			// triggering the ICMP message
			if s.testOpts.protocol != "udp" {
				return
			}

			BeforeEach(func() {
				tgtPort = 0xdead
				tgtWorkload = s.w[0][0]
			})

			if !s.testOpts.connTimeEnabled {
				It("should get port unreachable via node1->node0 fwd", func() {
					tcpdump := s.externalClient.AttachTCPDump("any")
					tcpdump.SetLogEnabled(true)

					var matcher string

					if s.testOpts.ipv6 {
						matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
							s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1), npPort)
					} else {
						matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
							s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1), npPort)
					}
					tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)

					s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
					s.cc.CheckConnectivity()
					Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
						Should(BeNumerically(">", 0), matcher)
				})
			}

			It("should get port unreachable workload to workload", func() {
				tcpdump := s.w[1][1].AttachTCPDump()
				tcpdump.SetLogEnabled(true)

				var matcher string

				if s.testOpts.ipv6 {
					matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
						tgtWorkload.IP, s.w[1][1].IP, tgtWorkload.IP, tgtPort)
				} else {
					matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
						tgtWorkload.IP, s.w[1][1].IP, tgtWorkload.IP, tgtPort)
				}
				tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
				tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(tgtPort), "or", icmpProto)

				s.cc.ExpectNone(s.w[1][1], TargetIP(tgtWorkload.IP), uint16(tgtPort))
				s.cc.CheckConnectivity()
				Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
					Should(BeNumerically(">", 0), matcher)
			})

			It("should get port unreachable workload to workload through NP", func() {
				tcpdump := s.w[1][1].AttachTCPDump()
				tcpdump.SetLogEnabled(true)

				var matcher string

				if s.testOpts.connTimeEnabled {
					if s.testOpts.ipv6 {
						matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
							tgtWorkload.IP, s.w[1][1].IP, s.w[0][0].IP, tgtPort)
					} else {
						matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
							tgtWorkload.IP, s.w[1][1].IP, s.w[0][0].IP, tgtPort)
					}
					tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(tgtPort), "or", icmpProto)
				} else {
					if s.testOpts.ipv6 {
						matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
							tgtWorkload.IP, s.w[1][1].IP, s.felixIP(1), npPort)
					} else {
						matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
							tgtWorkload.IP, s.w[1][1].IP, s.felixIP(1), npPort)
					}
					tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)
				}

				s.cc.ExpectNone(s.w[1][1], TargetIP(s.felixIP(1)), npPort)
				s.cc.CheckConnectivity()
				Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
					Should(BeNumerically(">", 0), matcher)
			})
		})
	})
}

func describeBPFSpecialTests(s *bpfTestContext) {
	_ = s.testOpts.tunnel != "vxlan" && Describe("with BPF disabled to begin with", func() {
		var pc *PersistentConnection

		BeforeEach(func() {
			s.options.TestManagesBPF = true
			s.setupCluster()

			// Default to Allow...
			pol := api.NewGlobalNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "policy-1"
			pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Selector = "all()"
			pol = s.createPolicy(pol)

			pc = nil
			if NFTMode() && s.testOpts.ipv6 && !s.testOpts.dsr && s.testOpts.tunnel == "none" && s.testOpts.connTimeEnabled {
				// In NFT mode, we add the kube-proxy tables.
				s.tc.Felixes[0].Exec("nft", "add", "table", "ip", "kube-proxy")
				s.tc.Felixes[0].Exec("nft", "add", "chain", "ip", "kube-proxy", "KUBE-TEST", "{ type filter hook forward priority 0 ; }")
				s.tc.Felixes[0].Exec("nft", "add", "table", "ip6", "kube-proxy")
				s.tc.Felixes[0].Exec("nft", "add", "chain", "ip6", "kube-proxy", "KUBE-TEST", "{ type filter hook forward priority 0 ; }")
			}
		})

		AfterEach(func() {
			if pc != nil {
				pc.Stop()
			}
		})

		enableBPF := func() {
			By("Enabling BPF")
			// Some tests start with a felix config pre-created, try to update it...
			fc, err := s.calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
			bpfEnabled := true
			if err == nil {
				fc.Spec.BPFEnabled = &bpfEnabled
				_, err := s.calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			} else {
				// Fall back on creating it...
				fc = api.NewFelixConfiguration()
				fc.Name = "default"
				fc.Spec.BPFEnabled = &bpfEnabled
				fc, err = s.calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}

			// Wait for BPF to be active.
			ensureAllNodesBPFProgramsAttached(s.tc.Felixes)
			if NFTMode() && s.testOpts.ipv6 && !s.testOpts.dsr && s.testOpts.tunnel == "none" && s.testOpts.connTimeEnabled {
				Eventually(func() string {
					out, _ := s.tc.Felixes[0].ExecOutput("nft", "list", "tables")
					return out
				}, "15s", "1s").ShouldNot(ContainSubstring("kube-proxy"))
			}
		}

		expectPongs := func() {
			count := pc.PongCount()
			EventuallyWithOffset(1, pc.PongCount, "60s").Should(
				BeNumerically(">", count),
				"Expected to see pong responses on the connection but didn't receive any")
			log.Info("Pongs received")
		}

		if s.testOpts.protocol == "tcp" && (s.testOpts.dsr || s.testOpts.ipv6) {
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
				verifyConnectivityWhileEnablingBPF(s.hostW[0], s.hostW[1])
			})

			It("should keep a connection up between workloads on different hosts when BPF is enabled", func() {
				verifyConnectivityWhileEnablingBPF(s.w[0][0], s.w[1][0])
			})

			It("should keep a connection up between hosts and remote workloads when BPF is enabled", func() {
				verifyConnectivityWhileEnablingBPF(s.hostW[0], s.w[1][0])
			})

			It("should keep a connection up between hosts and local workloads when BPF is enabled", func() {
				verifyConnectivityWhileEnablingBPF(s.hostW[0], s.w[0][0])
			})
		}
	})

	Describe("3rd party CNI", func() {
		// We do not use tunnel in such environments, no need to test.
		if s.testOpts.tunnel != "none" {
			return
		}

		BeforeEach(func() {
			// To mimic 3rd party CNI, we do not install IPPools and set the source to
			// learn routes to WorkloadIPs as IPAM/CNI is not going to provide either.
			s.options.UseIPPools = false
			s.options.SimulateBIRDRoutes = true
			s.options.ExtraEnvVars["FELIX_ROUTESOURCE"] = "WorkloadIPs"
			s.setupCluster()
		})

		Describe("CNI installs NAT outgoing iptable rules", func() {
			var extWorkload *workload.Workload
			BeforeEach(func() {
				if NFTMode() {
					Skip("NFT does not support third-party rules")
				}

				c := infrastructure.RunExtClient(s.infra, "ext-workload")
				extWorkload = &workload.Workload{
					C:        c,
					Name:     "ext-workload",
					Ports:    "4321",
					Protocol: s.testOpts.protocol,
					IP:       s.containerIP(c),
				}

				err := extWorkload.Start(s.infra) // FIXME
				Expect(err).NotTo(HaveOccurred())

				tool := "iptables"
				if s.testOpts.ipv6 {
					tool = "ip6tables"
				}

				for _, felix := range s.tc.Felixes {
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

					pol = s.createPolicy(pol)

					s.cc.ExpectSome(s.w[1][0], s.w[0][0])
					s.cc.ExpectSome(s.w[1][1], s.w[0][0])
					s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
					s.cc.ResetExpectations()
				})

				By("checking connectivity to the external workload", func() {
					s.cc.Expect(Some, s.w[0][0], extWorkload, ExpectWithPorts(4321), ExpectWithSrcIPs(s.felixIP(0)))
					s.cc.Expect(Some, s.w[1][0], extWorkload, ExpectWithPorts(4321), ExpectWithSrcIPs(s.felixIP(1)))
					s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
				})
			})

			AfterEach(func() {
				extWorkload.Stop()
			})
		})
	})

	Context("With host interface not managed by calico", func() {
		BeforeEach(func() {
			s.setupCluster()
			poolName := infrastructure.DefaultIPPoolName
			if s.testOpts.ipv6 {
				poolName = infrastructure.DefaultIPv6PoolName
			}
			pool, err := s.calicoClient.IPPools().Get(context.TODO(), poolName, options2.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pool.Spec.NATOutgoing = false
			pool, err = s.calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			pol := api.NewGlobalNetworkPolicy()
			pol.Name = "allow-all"
			pol.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
			pol.Spec.Selector = "all()"

			pol = s.createPolicy(pol)
		})

		if s.testOpts.protocol == "udp" || s.testOpts.tunnel == "ipip" || s.testOpts.ipv6 {
			return
		}
		It("should allow traffic from workload to this host device", func() {
			var (
				test30            *workload.Workload
				test30IP          string
				test30ExtIP       string
				test30Route, mask string
			)
			if s.testOpts.ipv6 {
				test30IP = "fd00::3001"
				test30ExtIP = "1000::0030"
				test30Route = "fd00::3000/120"
				mask = "128"
			} else {
				test30IP = "192.168.30.1"
				test30ExtIP = "10.0.0.30"
				test30Route = "192.168.30.0/24"
				mask = "32"
			}

			test30 = &workload.Workload{
				Name:          "test30",
				C:             s.tc.Felixes[1].Container,
				IP:            test30IP,
				Ports:         "57005", // 0xdead
				Protocol:      s.testOpts.protocol,
				InterfaceName: "test30",
				MTU:           1500, // Need to match host MTU or felix will restart.
			}
			err := test30.Start(s.infra)
			Expect(err).NotTo(HaveOccurred())
			// assign address to test30 and add route to the .30 network
			if s.testOpts.ipv6 {
				s.tc.Felixes[1].Exec("ip", "-6", "route", "add", test30Route, "dev", "test30")
				s.tc.Felixes[1].Exec("ip", "-6", "addr", "add", test30ExtIP+"/"+mask, "dev", "test30")
				_, err = test30.RunCmd("ip", "-6", "route", "add", test30ExtIP+"/"+mask, "dev", "eth0")
				Expect(err).NotTo(HaveOccurred())
				// Add a route to the test workload to the fake external
				// client emulated by the test-workload
				_, err = test30.RunCmd("ip", "-6", "route", "add", s.w[1][1].IP+"/"+mask, "via", test30ExtIP)
				Expect(err).NotTo(HaveOccurred())

			} else {
				s.tc.Felixes[1].Exec("ip", "route", "add", test30Route, "dev", "test30")
				s.tc.Felixes[1].Exec("ip", "addr", "add", test30ExtIP+"/"+mask, "dev", "test30")
				_, err = test30.RunCmd("ip", "route", "add", test30ExtIP+"/"+mask, "dev", "eth0")
				Expect(err).NotTo(HaveOccurred())
				// Add a route to the test workload to the fake external
				// client emulated by the test-workload
				_, err = test30.RunCmd("ip", "route", "add", s.w[1][1].IP+"/"+mask, "via", test30ExtIP)
				Expect(err).NotTo(HaveOccurred())

			}

			s.cc.ResetExpectations()
			s.cc.ExpectSome(s.w[1][1], TargetIP(test30.IP), 0xdead)
			s.cc.CheckConnectivity()
		})
	})

	Context("With BPFEnforceRPF=Strict", func() {
		BeforeEach(func() {
			s.options.ExtraEnvVars["FELIX_BPFEnforceRPF"] = "Strict"
			s.setupCluster()
		})

		// Test doesn't use services so ignore the runs with those turned on.
		if s.testOpts.protocol == "udp" && !s.testOpts.connTimeEnabled && !s.testOpts.dsr {
			It("should not be able to spoof UDP", func() {
				if !s.testOpts.ipv6 {
					By("Disabling dev RPF")
					setRPF(s.tc.Felixes, s.testOpts.tunnel, 0, 0)
					s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf."+s.w[1][0].InterfaceName+".rp_filter=0")
					s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf."+s.w[1][1].InterfaceName+".rp_filter=0")
				}

				By("allowing any traffic", func() {
					pol := api.NewGlobalNetworkPolicy()
					pol.Name = "allow-all"
					pol.Spec.Ingress = []api.Rule{{Action: api.Allow}}
					pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
					pol.Spec.Selector = "all()"

					pol = s.createPolicy(pol)

					s.cc.ExpectSome(s.w[1][0], s.w[0][0])
					s.cc.ExpectSome(s.w[1][1], s.w[0][0])
					s.cc.CheckConnectivity()
				})

				By("testing that packet sent by another workload is dropped", func() {
					tcpdump := s.w[0][0].AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					ipVer := "IP"
					if s.testOpts.ipv6 {
						ipVer = "IP6"
					}

					matcher := fmt.Sprintf("%s %s\\.30444 > %s\\.30444: UDP", ipVer, s.w[1][0].IP, s.w[0][0].IP)
					tcpdump.AddMatcher("UDP-30444", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", "30444", "or", "port", "30445")

					// send a packet from the correct workload to create a conntrack entry
					_, err := s.w[1][0].RunCmd("pktgen", s.w[1][0].IP, s.w[0][0].IP, "udp",
						"--port-src", "30444", "--port-dst", "30444")
					Expect(err).NotTo(HaveOccurred())

					// We must eventually see the packet at the target
					Eventually(func() int { return tcpdump.MatchCount("UDP-30444") }).
						Should(BeNumerically("==", 1), matcher)

					// Send a spoofed packet from a different pod. Since we hit the
					// conntrack we would not do the WEP only RPF check.
					_, err = s.w[1][1].RunCmd("pktgen", s.w[1][0].IP, s.w[0][0].IP, "udp",
						"--port-src", "30444", "--port-dst", "30444")
					Expect(err).NotTo(HaveOccurred())

					// Since the packet will get dropped, we would not see it at the dest.
					// So we send another good packet from the spoofing workload, that we
					// will see at the dest.
					matcher2 := fmt.Sprintf("%s %s\\.30445 > %s\\.30445: UDP", ipVer, s.w[1][1].IP, s.w[0][0].IP)
					tcpdump.AddMatcher("UDP-30445", regexp.MustCompile(matcher2))

					_, err = s.w[1][1].RunCmd("pktgen", s.w[1][1].IP, s.w[0][0].IP, "udp",
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

					if s.testOpts.ipv6 {
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
						C:             s.tc.Felixes[1].Container,
						IP:            eth20IP,
						Ports:         "57005", // 0xdead
						Protocol:      s.testOpts.protocol,
						InterfaceName: "eth20",
						MTU:           1500, // Need to match host MTU or felix will restart.
					}
					err := eth20.Start(s.infra)
					Expect(err).NotTo(HaveOccurred())

					// assign address to eth20 and add route to the .20 network
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", eth20Route, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
						_, err = eth20.RunCmd("ip", "-6", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth20.RunCmd("ip", "-6", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth20ExtIP)
						Expect(err).NotTo(HaveOccurred())
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "add", eth20Route, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
						_, err = eth20.RunCmd("ip", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth20.RunCmd("ip", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth20ExtIP)
						Expect(err).NotTo(HaveOccurred())
					}

					eth30 = &workload.Workload{
						Name:          "eth30",
						C:             s.tc.Felixes[1].Container,
						IP:            eth30IP,
						Ports:         "57005", // 0xdead
						Protocol:      s.testOpts.protocol,
						InterfaceName: "eth30",
						MTU:           1500, // Need to match host MTU or felix will restart.
					}
					err = eth30.Start(s.infra)
					Expect(err).NotTo(HaveOccurred())

					// assign address to eth30 and add route to the .30 network
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", eth30Route, "dev", "eth30")
						s.tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth30ExtIP+"/"+mask, "dev", "eth30")
						_, err = eth30.RunCmd("ip", "-6", "route", "add", eth30ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth30.RunCmd("ip", "-6", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth30ExtIP)
						Expect(err).NotTo(HaveOccurred())
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "add", eth30Route, "dev", "eth30")
						s.tc.Felixes[1].Exec("ip", "addr", "add", eth30ExtIP+"/"+mask, "dev", "eth30")
						_, err = eth30.RunCmd("ip", "route", "add", eth30ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth30.RunCmd("ip", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth30ExtIP)
						Expect(err).NotTo(HaveOccurred())
					}

					// Make sure Felix adds a BPF program before we run the test, otherwise the conntrack
					// may be crated in the reverse direction.  Since we're pretending to be a host interface
					// Felix doesn't block traffic by default.
					Eventually(s.tc.Felixes[1].NumTCBPFProgsFn("eth20"), "30s", "200ms").Should(Equal(2))
					Eventually(s.tc.Felixes[1].NumTCBPFProgsFn("eth30"), "30s", "200ms").Should(Equal(2))

					// Make sure that networking with the .20 and .30 networks works
					s.cc.ResetExpectations()
					s.cc.ExpectSome(s.w[1][1], TargetIP(eth20.IP), 0xdead)
					s.cc.ExpectSome(s.w[1][1], TargetIP(eth30.IP), 0xdead)
					s.cc.CheckConnectivity()
				})

				By("testing that external traffic updates the RPF check if routing changes", func() {
					// set the route to the fake workload to .20 network
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth20")
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth20")
					}

					tcpdump := s.w[1][1].AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					matcher := fmt.Sprintf("%s %s\\.30446 > %s\\.30446: UDP", ipVer, fakeWorkloadIP, s.w[1][1].IP)
					tcpdump.AddMatcher("UDP-30446", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra)

					_, err := eth20.RunCmd("pktgen", fakeWorkloadIP, s.w[1][1].IP, "udp",
						"--port-src", "30446", "--port-dst", "30446")
					Expect(err).NotTo(HaveOccurred())

					// Expect to receive the packet from the .20 as the routing is correct
					Eventually(func() int { return tcpdump.MatchCount("UDP-30446") }).
						Should(BeNumerically("==", 1), matcher)

					ctBefore := dumpCTMapsAny(family, s.tc.Felixes[1])

					var k conntrack.KeyInterface
					if s.testOpts.ipv6 {
						k = conntrack.NewKeyV6(17, net.ParseIP(s.w[1][1].IP).To16(), 30446,
							net.ParseIP(fakeWorkloadIP).To16(), 30446)
					} else {
						k = conntrack.NewKey(17, net.ParseIP(s.w[1][1].IP).To4(), 30446,
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
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "del", fakeWorkloadIP+"/"+mask, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth30")
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "del", fakeWorkloadIP+"/"+mask, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth30")
					}

					_, err = eth30.RunCmd("pktgen", fakeWorkloadIP, s.w[1][1].IP, "udp",
						"--port-src", "30446", "--port-dst", "30446")
					Expect(err).NotTo(HaveOccurred())

					// Expect the packet from the .30 to make it through as RPF will
					// allow it and we will update the expected interface
					Eventually(func() int { return tcpdump.MatchCount("UDP-30446") }).
						Should(BeNumerically("==", 2), matcher)

					ctAfter := dumpCTMapsAny(family, s.tc.Felixes[1])
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
}
