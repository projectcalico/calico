package fv_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("WireGuard source-scoped routing (Issue #9751)", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount = 2

	var (
		infra              infrastructure.DatastoreInfra
		topologyContainers infrastructure.TopologyContainers
		client             clientv3.Interface
		cc                 *connectivity.Checker
		wls                [nodeCount]*workload.Workload
	)

	BeforeEach(func() {
		infra = getInfra()
		topologyContainers = infrastructure.RunTopology(infrastructure.TopologyOptions{
			FelixLogSeverity:           "info",
			EnableIPv6:                 false,
			ExtraEnvVars:               map[string]string{
				"FELIX_WIREGUARDENABLED": "true",
				"FELIX_WIREGUARDENCRYPTHOSTTRAFFIC": "false",
			},
			NATOutgoingEnabled: true,
		}, &infra)

		var err error
		client, err = infra.GetCalicoClient()
		Expect(err).NotTo(HaveOccurred())

		for ii := range wls {
			wls[ii] = workload.Run(
				&topologyContainers.Felixes[ii].Container,
				fmt.Sprintf("w%d", ii),
				"default",
				fmt.Sprintf("10.65.%d.2", ii),
				"8055",
				"tcp",
			)
			wls[ii].ConfigureInInfra(infra)
		}

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		for ii := range wls {
			if wls[ii] != nil {
				wls[ii].Stop()
			}
		}

		topologyContainers.Stop()

		if CurrentSpecReport().Failed() {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	Context("with EncryptHostTraffic=false", func() {
		It("should create source-scoped routing rules", func() {
			Eventually(func() error {
				for i, felix := range topologyContainers.Felixes {
					rule, err := felix.ExecOutput("ip", "rule", "show", "pref", "99")
					if err != nil {
						return fmt.Errorf("node %d: failed to get routing rule: %v", i, err)
					}

					if rule == "" {
						return fmt.Errorf("node %d: no routing rule found at priority 99", i)
					}

					if !strings.Contains(rule, "from 10.65.") {
						return fmt.Errorf("node %d: routing rule missing source constraint: %s", i, rule)
					}

					if !regexp.MustCompile(`from 10\.65\.\d+\.\d+/\d+`).MatchString(rule) {
						return fmt.Errorf("node %d: routing rule malformed: %s", i, rule)
					}

					if strings.Contains(rule, "not from") {
						return fmt.Errorf("node %d: routing rule must not use inverted source constraint: %s", i, rule)
					}
					rule98, err := felix.ExecOutput("ip", "rule", "show", "pref", "98")
					if err != nil {
						return fmt.Errorf("node %d: failed to check priority 98: %v", i, err)
					}
					if rule98 != "" {
						return fmt.Errorf("node %d: found unexpected bypass rule at priority 98: %s", i, rule98)
					}
				}
				return nil
			}, "30s", "500ms").Should(Succeed())
		})

		It("should allow host-to-pod connectivity", func() {
			cc.ExpectSome(topologyContainers.Felixes[0], wls[0])
			cc.ExpectSome(topologyContainers.Felixes[1], wls[1])
			cc.ExpectSome(topologyContainers.Felixes[0], wls[1])
			cc.ExpectSome(topologyContainers.Felixes[1], wls[0])
			cc.CheckConnectivity()
		})

		It("should still encrypt pod-to-pod traffic", func() {
			cc.ExpectSome(wls[0], wls[1])
			cc.ExpectSome(wls[1], wls[0])
			cc.CheckConnectivity()

			for i, felix := range topologyContainers.Felixes {
				out, err := felix.ExecOutput("wg", "show", "wireguard.cali")
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("node %d failed to show wireguard config", i))
				Expect(out).To(ContainSubstring("peer:"), fmt.Sprintf("node %d should have wireguard peers configured", i))
			}
		})

		It("should not route host traffic to wireguard interface", func() {
			for i, felix := range topologyContainers.Felixes {
				wgStats1, err := felix.ExecOutput("wg", "show", "wireguard.cali", "transfer")
				Expect(err).NotTo(HaveOccurred())

				_, err = felix.ExecOutput("ping", "-c", "3", wls[i].IP)
				Expect(err).NotTo(HaveOccurred())

				wgStats2, err := felix.ExecOutput("wg", "show", "wireguard.cali", "transfer")
				Expect(err).NotTo(HaveOccurred())

				if wgStats1 != wgStats2 {
					Fail(fmt.Sprintf("node %d: host→pod ping incorrectly went through wireguard (stats changed)", i))
				}
			}
		})

		It("should handle IP pool changes", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ipPool := api.NewIPPool()
			ipPool.Name = "test-pool"
			ipPool.Spec.CIDR = "10.66.0.0/16"
			ipPool.Spec.NATOutgoing = true

			_, err := client.IPPools().Create(ctx, ipPool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() error {
				for i, felix := range topologyContainers.Felixes {
					rules, err := felix.ExecOutput("ip", "rule", "show", "pref", "99")
					if err != nil {
						return err
					}

					lines := strings.Split(strings.TrimSpace(rules), "\n")
					foundOldPool := false
					foundNewPool := false

					for _, line := range lines {
						if strings.Contains(line, "from 10.65.") {
							foundOldPool = true
						}
						if strings.Contains(line, "from 10.66.") {
							foundNewPool = true
						}
					}

					if !foundOldPool {
						return fmt.Errorf("node %d: old pool routing rule disappeared", i)
					}
					if !foundNewPool {
						return fmt.Errorf("node %d: new pool routing rule not found yet", i)
					}
				}
				return nil
			}, "30s", "500ms").Should(Succeed())
		})
	})

	Context("with EncryptHostTraffic=true", func() {
		BeforeEach(func() {
			topologyContainers.Stop()
			
			topologyContainers = infrastructure.RunTopology(infrastructure.TopologyOptions{
				FelixLogSeverity:           "info",
				EnableIPv6:                 false,
				ExtraEnvVars:               map[string]string{
					"FELIX_WIREGUARDENABLED": "true",
					"FELIX_WIREGUARDENCRYPTHOSTTRAFFIC": "true",
				},
				NATOutgoingEnabled: true,
			}, &infra)

			for ii := range wls {
				if wls[ii] != nil {
					wls[ii].Stop()
				}
				wls[ii] = workload.Run(
					&topologyContainers.Felixes[ii].Container,
					fmt.Sprintf("w%d", ii),
					"default",
					fmt.Sprintf("10.65.%d.2", ii),
					"8055",
					"tcp",
				)
				wls[ii].ConfigureInInfra(infra)
			}
		})

		It("should create single unscoped routing rule without source match", func() {
			Eventually(func() error {
				for i, felix := range topologyContainers.Felixes {
					rule, err := felix.ExecOutput("ip", "rule", "show", "pref", "99")
					if err != nil {
						return fmt.Errorf("node %d: failed to get routing rule: %v", i, err)
					}

					if rule == "" {
						return fmt.Errorf("node %d: no routing rule found at priority 99", i)
					}

					if strings.Contains(rule, "from 10.") {
						return fmt.Errorf("node %d: routing rule should not have source constraint with EncryptHostTraffic=true: %s", i, rule)
					}

					if !strings.Contains(rule, "not from all") {
						return fmt.Errorf("node %d: routing rule should match 'not from all': %s", i, rule)
					}
				}
				return nil
			}, "30s", "500ms").Should(Succeed())
		})

		It("should encrypt host traffic through wireguard", func() {
			for i, felix := range topologyContainers.Felixes {
				wgStats1, err := felix.ExecOutput("wg", "show", "wireguard.cali", "transfer")
				Expect(err).NotTo(HaveOccurred())

				_, err = felix.ExecOutput("ping", "-c", "3", wls[(i+1)%nodeCount].IP)
				Expect(err).NotTo(HaveOccurred())

				wgStats2, err := felix.ExecOutput("wg", "show", "wireguard.cali", "transfer")
				Expect(err).NotTo(HaveOccurred())

				Expect(wgStats2).NotTo(Equal(wgStats1), fmt.Sprintf("node %d: host traffic should go through wireguard", i))
			}
		})
	})
})
