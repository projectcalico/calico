// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/fv/containers"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

const (
	FlowLogSourceNone = iota
	FlowLogSourceFile
	FlowLogSourceGoldmane
)

type TopologyOptions struct {
	FelixLogSeverity        string
	FelixDebugFilenameRegex string
	FelixCoreDumpsEnabled   bool
	EnableIPv6              bool
	// Temporary flag to implement and test IPv6 in bpf dataplane.
	// TODO: Remove it when IPv6 implementation in BPF mode is complete.
	BPFEnableIPv6             bool
	ExtraEnvVars              map[string]string
	ExtraVolumes              map[string]string
	WithTypha                 bool
	WithFelixTyphaTLS         bool
	TestManagesBPF            bool
	TyphaLogSeverity          string
	IPIPEnabled               bool
	IPIPRoutesEnabled         bool
	VXLANMode                 api.VXLANMode
	VXLANStrategy             VXLANStrategy
	WireguardEnabled          bool
	WireguardEnabledV6        bool
	InitialFelixConfiguration *api.FelixConfiguration
	NATOutgoingEnabled        bool
	DelayFelixStart           bool
	AutoHEPsEnabled           bool
	TriggerDelayedFelixStart  bool
	FelixStopGraceful         bool
	ExternalIPs               bool
	UseIPPools                bool
	IPPoolCIDR                string
	IPv6PoolCIDR              string
	IPPoolUsages              []api.IPPoolAllowedUse
	IPv6PoolUsages            []api.IPPoolAllowedUse
	NeedNodeIP                bool
	FlowLogSource             int
}

// Calico containers created during topology creation.
type TopologyContainers struct {
	Felixes []*Felix
	Typha   *Typha
}

func (c *TopologyContainers) Stop() {
	for _, felix := range c.Felixes {
		felix.Stop()
	}
	if c.Typha != nil {
		c.Typha.Stop()
	}
}

func (c *TopologyContainers) TriggerDelayedStart() {
	for _, f := range c.Felixes {
		f.TriggerDelayedStart()
	}
}

func DefaultTopologyOptions() TopologyOptions {
	felixLogLevel := "Info"
	if envLogLevel := os.Getenv("FV_FELIX_LOG_LEVEL"); envLogLevel != "" {
		log.WithField("level", envLogLevel).Info("FV_FELIX_LOG_LEVEL env var set; overriding felix log level")
		felixLogLevel = envLogLevel
	}
	return TopologyOptions{
		FelixLogSeverity:      felixLogLevel,
		FelixCoreDumpsEnabled: true,
		EnableIPv6:            os.Getenv("FELIX_FV_ENABLE_BPF") != "true",
		BPFEnableIPv6:         false,
		ExtraEnvVars:          map[string]string{},
		ExtraVolumes:          map[string]string{},
		WithTypha:             false,
		WithFelixTyphaTLS:     false,
		TyphaLogSeverity:      "info",
		IPIPEnabled:           true,
		IPIPRoutesEnabled:     true,
		IPPoolCIDR:            DefaultIPPoolCIDR,
		IPv6PoolCIDR:          DefaultIPv6PoolCIDR,
		UseIPPools:            true,
	}
}

const (
	DefaultIPPoolName   = "test-pool"
	DefaultIPPoolCIDR   = "10.65.0.0/16"
	DefaultIPv6PoolName = "test-pool-v6"
	DefaultIPv6PoolCIDR = "dead:beef::/64"
)

func CreateDefaultIPPoolFromOpts(
	ctx context.Context,
	client client.Interface,
	opts TopologyOptions,
	ipVersion int,
) (*api.IPPool, error) {
	ipPool := api.NewIPPool()

	switch ipVersion {
	case 4:
		ipPool.Name = DefaultIPPoolName
		ipPool.Spec.CIDR = opts.IPPoolCIDR

		// IPIP is only supported on IPv4
		if opts.IPIPEnabled {
			ipPool.Spec.IPIPMode = api.IPIPModeAlways
		} else {
			ipPool.Spec.IPIPMode = api.IPIPModeNever
		}

		if len(opts.IPPoolUsages) > 0 {
			ipPool.Spec.AllowedUses = opts.IPPoolUsages
		}
	case 6:
		ipPool.Name = DefaultIPv6PoolName
		ipPool.Spec.CIDR = opts.IPv6PoolCIDR

		if len(opts.IPv6PoolUsages) > 0 {
			ipPool.Spec.AllowedUses = opts.IPv6PoolUsages
		}
	default:
		log.WithField("ipVersion", ipVersion).Panic("Unknown IP version")
	}
	ipPool.Spec.NATOutgoing = opts.NATOutgoingEnabled
	ipPool.Spec.VXLANMode = opts.VXLANMode

	return client.IPPools().Create(ctx, ipPool, options.SetOptions{})
}

func DeleteIPPoolByName(ctx context.Context, client client.Interface, name string) (*api.IPPool, error) {
	return client.IPPools().Delete(ctx, name, options.DeleteOptions{})
}

func DeleteDefaultIPPool(ctx context.Context, client client.Interface) (*api.IPPool, error) {
	return DeleteIPPoolByName(ctx, client, DefaultIPPoolName)
}

// StartSingleNodeEtcdTopology starts an etcd container and a single Felix container; it initialises
// the datastore and installs a Node resource for the Felix node.
func StartSingleNodeEtcdTopology(options TopologyOptions) (tc TopologyContainers, etcd *containers.Container, calicoClient client.Interface, infra DatastoreInfra) {
	tc, etcd, calicoClient, infra = StartNNodeEtcdTopology(1, options)
	return
}

// StartNNodeEtcdTopology starts an etcd container and a set of Felix hosts.  If n > 1, sets
// up IPIP, otherwise this is skipped.
//
//   - Configures an IPAM pool for 10.65.0.0/16 (so that Felix programs the all-IPAM blocks IP set)
//     but (for simplicity) we don't actually use IPAM to assign IPs.
//   - Configures routes between the hosts, giving each host 10.65.x.0/24, where x is the
//     index in the returned array.  When creating workloads, use IPs from the relevant block.
//   - Configures the Tunnel IP for each host as 10.65.x.1.
func StartNNodeEtcdTopology(
	n int,
	opts TopologyOptions,
) (tc TopologyContainers, etcd *containers.Container, client client.Interface, infra DatastoreInfra) {
	log.Infof("Starting a %d-node etcd topology.", n)

	eds, err := GetEtcdDatastoreInfra()
	Expect(err).ToNot(HaveOccurred())
	etcd = eds.etcdContainer
	infra = eds

	tc, client = StartNNodeTopology(n, opts, eds)

	return
}

// StartSingleNodeTopology starts an etcd container and a single Felix container; it initialises
// the datastore and installs a Node resource for the Felix node.
func StartSingleNodeTopology(
	options TopologyOptions,
	infra DatastoreInfra,
) (tc TopologyContainers, calicoClient client.Interface) {
	tc, calicoClient = StartNNodeTopology(1, options, infra)
	return
}

// StartNNodeTopology starts an etcd container and a set of Felix hosts.  If n > 1, sets
// up IPIP, otherwise this is skipped.
//
//   - Configures an IPAM pool for 10.65.0.0/16 (so that Felix programs the all-IPAM blocks IP set)
//     but (for simplicity) we don't actually use IPAM to assign IPs.
//   - Configures routes between the hosts, giving each host 10.65.x.0/24, where x is the
//     index in the returned array.  When creating workloads, use IPs from the relevant block.
//   - Configures the Tunnel IP for each host as 10.65.x.1.
func StartNNodeTopology(
	n int,
	opts TopologyOptions,
	infra DatastoreInfra,
) (tc TopologyContainers, client client.Interface) {
	log.WithField("options", opts).Infof("Starting a %d-node topology", n)
	success := false
	var err error

	if opts.EnableIPv6 && opts.IPIPEnabled && os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
		log.Errorf("IPIP not supported in BPF with ipv6!")
		return
	}

	startTime := time.Now()
	defer func() {
		if !success {
			log.WithError(err).Error("Failed to start topology, tearing down containers")
			tc.Stop()
			infra.Stop()
			return
		}
		log.WithField("time", time.Since(startTime)).Info("Started topology.")
	}()

	if opts.VXLANMode == "" {
		opts.VXLANMode = api.VXLANModeNever
	}

	// Get client.
	client = infra.GetCalicoClient()
	mustInitDatastore(client)

	// If asked to, pre-create a felix configuration.  We do this before enabling IPIP because IPIP set-up can
	// create/update a FelixConfiguration as a side-effect.
	if opts.InitialFelixConfiguration != nil {
		log.WithField("config", opts.InitialFelixConfiguration).Info(
			"Installing initial FelixConfiguration")
		Eventually(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err = client.FelixConfigurations().Create(ctx, opts.InitialFelixConfiguration, options.SetOptions{})
			if _, ok := err.(errors.ErrorResourceAlreadyExists); ok {
				// Try to delete the unexpected config, then, if there's still time in the Eventually loop,
				// we'll try to recreate
				_, _ = client.FelixConfigurations().Delete(ctx, "default", options.DeleteOptions{})
			}
			return err
		}, "10s").ShouldNot(HaveOccurred())
	}

	if n > 1 {
		Eventually(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if opts.UseIPPools {
				_, err = CreateDefaultIPPoolFromOpts(ctx, client, opts, 4)
			}
			return err
		}).ShouldNot(HaveOccurred())

		if opts.EnableIPv6 {
			Eventually(func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if opts.UseIPPools {
					_, err = CreateDefaultIPPoolFromOpts(ctx, client, opts, 6)
				}
				return err
			}).ShouldNot(HaveOccurred())
		}
	}

	typhaIP := ""
	if opts.WithTypha {
		tc.Typha = RunTypha(infra, opts)
		opts.ExtraEnvVars["FELIX_TYPHAADDR"] = tc.Typha.IP + ":5473"
		typhaIP = tc.Typha.IP
	}

	tc.Felixes = make([]*Felix, n)
	var wg sync.WaitGroup

	// Make a separate copy of TopologyOptions for each Felix that we will run.  This
	// is because we need to modify ExtraEnvVars for some of them.  If we kept using
	// the same copy, while starting Felixes, we could hit a concurrent map read/write
	// problem.
	optsPerFelix := make([]TopologyOptions, n)
	for i := 0; i < n; i++ {
		optsPerFelix[i] = opts
		optsPerFelix[i].ExtraEnvVars = map[string]string{}
		for k, v := range opts.ExtraEnvVars {
			optsPerFelix[i].ExtraEnvVars[k] = v
		}

		// Different log prefix for each Felix.
		optsPerFelix[i].ExtraEnvVars["BPF_LOG_PFX"] = fmt.Sprintf("%d-", i)

		// Only the first Felix enables the BPF connect-time load balancer, as
		// we get unpredictable behaviour if more than one Felix enables it on the same
		// host.  So, disable CTLB handling for subsequent Felixes.
		if i > 0 {
			optsPerFelix[i].ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancingEnabled"] = "false"
			optsPerFelix[i].ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBDisabled)
			if optsPerFelix[i].ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] == "" {
				optsPerFelix[i].ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATDisabled)
			}
			optsPerFelix[i].ExtraEnvVars["FELIX_DebugSkipCTLBCleanup"] = "true"
		}
	}

	// Now start the Felixes.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer ginkgo.GinkgoRecover()
			tc.Felixes[i] = RunFelix(infra, i, optsPerFelix[i])
		}(i)
	}
	wg.Wait()

	_, IPv4CIDR, err := net.ParseCIDR(opts.IPPoolCIDR)
	Expect(err).To(BeNil())
	_, IPv6CIDR, err := net.ParseCIDR(opts.IPv6PoolCIDR)
	Expect(err).To(BeNil())

	for i := 0; i < n; i++ {
		opts.ExtraEnvVars["BPF_LOG_PFX"] = ""
		felix := tc.Felixes[i]
		felix.TyphaIP = typhaIP

		if opts.EnableIPv6 {
			Expect(felix.IPv6).ToNot(BeEmpty(), "IPv6 enabled but Felix didn't get an IPv6 address, is docker configured for IPv6?")
		}

		expectedIPs := []string{felix.IP}
		if felix.IPv6 != "" {
			expectedIPs = append(expectedIPs, felix.IPv6)
		}
		if kdd, ok := infra.(*K8sDatastoreInfra); ok && opts.ExternalIPs {
			kdd.SetExternalIP(felix, i)
			expectedIPs = append(expectedIPs, felix.ExternalIP)
		}

		setUpBGPNodeIPAndIPIPTunnelIP := n > 1 || opts.NeedNodeIP
		if opts.IPIPEnabled {
			infra.SetExpectedIPIPTunnelAddr(felix, IPv4CIDR, i, setUpBGPNodeIPAndIPIPTunnelIP)
			expectedIPs = append(expectedIPs, felix.ExpectedIPIPTunnelAddr)
		}
		if opts.VXLANMode != api.VXLANModeNever {
			ExpectWithOffset(1, opts.VXLANStrategy).ToNot(BeNil(), "VXLANMode is set but VXLANStrategy is nil")
			infra.SetExpectedVXLANTunnelAddr(felix, opts.VXLANStrategy.TunnelAddress(i))
			expectedIPs = append(expectedIPs, felix.ExpectedVXLANTunnelAddr)
			if opts.EnableIPv6 {
				expectedIPs = append(expectedIPs, felix.IPv6)
				infra.SetExpectedVXLANV6TunnelAddr(felix, opts.VXLANStrategy.TunnelAddressV6(i))
				expectedIPs = append(expectedIPs, felix.ExpectedVXLANV6TunnelAddr)
			}
		}
		if opts.WireguardEnabled {
			infra.SetExpectedWireguardTunnelAddr(felix, IPv4CIDR, i, n > 1)
			expectedIPs = append(expectedIPs, felix.ExpectedWireguardTunnelAddr)
		}
		if opts.WireguardEnabledV6 {
			infra.SetExpectedWireguardV6TunnelAddr(felix, IPv6CIDR, i, n > 1)
			expectedIPs = append(expectedIPs, felix.ExpectedWireguardV6TunnelAddr)
		}

		var w chan struct{}
		if !opts.DelayFelixStart && felix.ExpectedIPIPTunnelAddr != "" {
			// If felix has an IPIP tunnel address defined, Felix may restart after loading its config.
			// Handle that here by monitoring the log and waiting for the correct tunnel IP to show up
			// before we return.
			log.Info("Waiting for felix to restart after setting tunnel IP.")
			w = felix.WatchStdoutFor(regexp.MustCompile(
				`Successfully loaded configuration.*"IpInIpTunnelAddr":"` + regexp.QuoteMeta(felix.ExpectedIPIPTunnelAddr) + `"`))
		} else if opts.NeedNodeIP {
			// opts.NeedNodeIP is implicitly handled by the previous branch.  We rely on the infra to
			// set the (formerly BGP) node IP and tunnel IP together so if we hit this branch then the
			// infra isn't doing what we expect.
			log.Panic("NeedNodeIP set but infra didn't set ExpectedIPIPTunnelAddr.")
		}
		infra.AddNode(felix, IPv4CIDR, IPv6CIDR, i, setUpBGPNodeIPAndIPIPTunnelIP)
		if w != nil {
			// Wait for any expected Felix restart...
			log.Info("Wait for Felix to restart")
			Eventually(w, "10s").Should(BeClosed(),
				fmt.Sprintf("Timed out waiting for %s to restart", felix.Name))
		}

		if opts.AutoHEPsEnabled {
			hep := &api.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("%s-auto-hep", felix.Name),
					Labels: map[string]string{
						"projectcalico.org/created-by": "calico-kube-controllers",
						"node":                         felix.Name,
						"ep-type":                      "host",
					},
				},
				Spec: api.HostEndpointSpec{
					Node:          felix.Name,
					InterfaceName: "*",
					ExpectedIPs:   expectedIPs,
					Profiles:      []string{resources.DefaultAllowProfileName},
				},
			}
			_, err := client.HostEndpoints().Create(context.Background(), hep, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
		}

		if opts.TriggerDelayedFelixStart {
			felix.TriggerDelayedStart()
		}

	}

	// Set up routes between the hosts, note: we're not using BGP here but we set up similar
	// CIDR-based routes.
	for i, iFelix := range tc.Felixes {
		for j, jFelix := range tc.Felixes {
			if i == j {
				continue
			}
			wg.Add(1)
			go func(i, j int, iFelix, jFelix *Felix) {
				defer wg.Done()
				defer ginkgo.GinkgoRecover()
				jBlock := fmt.Sprintf("%d.%d.%d.0/24", IPv4CIDR.IP[0], IPv4CIDR.IP[1], j)
				if opts.IPIPEnabled && opts.IPIPRoutesEnabled {
					// Can get "Nexthop device is not up" error here if tunl0 device is
					// not ready yet, which can happen especially if Felix start was
					// delayed.
					Eventually(func() error {
						return iFelix.ExecMayFail("ip", "route", "add", jBlock, "via", jFelix.IP, "dev", "tunl0", "onlink")
					}, "10s", "1s").ShouldNot(HaveOccurred())
				} else if opts.VXLANMode == api.VXLANModeNever {
					// If VXLAN is enabled, Felix will program these routes itself.
					err := iFelix.ExecMayFail("ip", "route", "add", jBlock, "via", jFelix.IP, "dev", "eth0")
					Expect(err).ToNot(HaveOccurred())
				}
				if opts.EnableIPv6 {
					jBlockV6 := fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:0:%d:0/112", IPv6CIDR.IP[0], IPv6CIDR.IP[1], IPv6CIDR.IP[2], IPv6CIDR.IP[3], IPv6CIDR.IP[4], IPv6CIDR.IP[5], IPv6CIDR.IP[6], IPv6CIDR.IP[7], IPv6CIDR.IP[8], IPv6CIDR.IP[9], j)
					if opts.VXLANMode == api.VXLANModeNever {
						// If VXLAN is enabled, Felix will program these routes itself.
						// If IPIP routes are enabled, these routes will conflict with configured ones and a 'RTNETLINK answers: File exists' error would occur.
						err := iFelix.ExecMayFail("ip", "-6", "route", "add", jBlockV6, "via", jFelix.IPv6, "dev", "eth0")
						Expect(err).ToNot(HaveOccurred())
					}

				}
			}(i, j, iFelix, jFelix)
		}
	}

	wg.Wait()
	success = true
	return
}

func mustInitDatastore(client client.Interface) {
	Eventually(func() error {
		log.Info("Initializing the datastore...")
		ctx, cancelFun := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFun()
		err := client.EnsureInitialized(
			ctx,
			"v3.0.0-test",
			"felix-fv",
		)
		log.WithError(err).Info("EnsureInitialized result")
		return err
	}).ShouldNot(HaveOccurred(), "mustInitDatastore failed")
}
