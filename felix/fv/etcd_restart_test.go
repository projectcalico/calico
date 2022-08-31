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

//go:build fvtests

package fv_test

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = Context("etcd connection interruption", func() {

	var (
		etcd    *containers.Container
		felixes []*infrastructure.Felix
		client  client.Interface
		infra   infrastructure.DatastoreInfra
		w       [2]*workload.Workload
		cc      *connectivity.Checker
	)

	BeforeEach(func() {
		felixes, etcd, client, infra = infrastructure.StartNNodeEtcdTopology(2, infrastructure.DefaultTopologyOptions())
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "")
		// Wait until the tunl0 device appears; it is created when felix inserts the ipip module
		// into the kernel.
		Eventually(func() error {
			links, err := netlink.LinkList()
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Attrs().Name == "tunl0" {
					return nil
				}
			}
			return errors.New("tunl0 wasn't auto-created")
		}).Should(BeNil())

		// Create workloads, using that profile.  One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
			}
		}

		for _, wl := range w {
			wl.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "get", "/", "--prefix", "--keys-only")
		}
		etcd.Stop()
		infra.Stop()
	})

	It("shouldn't use excessive CPU when etcd is stopped", func() {
		By("having initial workload to workload connectivity", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		etcd.Stop()

		delay := 10 * time.Second
		startCPU, err := metrics.GetFelixMetricFloat(felixes[0].IP, "process_cpu_seconds_total")
		Expect(err).NotTo(HaveOccurred())
		time.Sleep(delay)
		endCPU, err := metrics.GetFelixMetricFloat(felixes[0].IP, "process_cpu_seconds_total")
		Expect(err).NotTo(HaveOccurred())

		cpuPct := (endCPU - startCPU) / delay.Seconds() * 100

		Expect(cpuPct).To(BeNumerically("<", 50))
	})

	It("should detect and reconnect after the etcd connection is black-holed", func() {
		By("having initial workload to workload connectivity", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		By("silently dropping etcd packets", func() {
			// Normally, if a connection closes at either end, the other peer's traffic will get
			// FIN or RST responses, which cleanly shut down the connection.  However, in order
			// to test the GRPC-level keep-alive, we want to simulate a network or NAT change that
			// starts to black-hole the TCP connection so that there are no responses of any kind.
			var portRegexp = regexp.MustCompile(`sport=(\d+).*dport=2379`)
			for _, felix := range felixes {
				// Use conntrack to identify the source port that Felix is using.
				out, err := felix.ExecOutput("conntrack", "-L")
				Expect(err).NotTo(HaveOccurred())
				logrus.WithField("output", out).WithError(err).Info("Conntrack entries")
				found := false
				for _, line := range strings.Split(out, "\n") {
					matches := portRegexp.FindStringSubmatch(line)
					if len(matches) < 2 {
						continue
					}
					found = true

					// Use the raw table to drop the TCP connections (to etcd) that felix is using,
					// in both directions, based on source and destination port.
					felix.Exec("iptables",
						"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
						"-W", "100000", // How often to probe the lock in microsecs.
						"-t", "raw", "-I", "PREROUTING",
						"-p", "tcp",
						"-s", etcd.IP,
						"-m", "multiport", "--destination-ports", matches[1],
						"-j", "DROP")
					felix.Exec("iptables",
						"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
						"-W", "100000", // How often to probe the lock in microsecs.
						"-t", "raw", "-I", "OUTPUT",
						"-p", "tcp",
						"-d", etcd.IP,
						"-m", "multiport", "--source-ports", matches[1],
						"-j", "DROP")
				}
				Expect(found).To(BeTrue(), "Failed to detect any felix->etcd connections")
				felix.Exec("conntrack", "-D", "--orig-dst", etcd.IP)
			}
		})

		By("updating policy again", func() {
			// Create a Policy that denies all traffic, after we've already cut the etcd connection.
			deny := api.NewGlobalNetworkPolicy()
			deny.Name = "deny-all"
			deny.Spec.Selector = "all()"
			deny.Spec.Egress = []api.Rule{{Action: api.Deny}}
			deny.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, deny, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Felix should start applying policy again when it detects the connection failure.
			cc.ResetExpectations()
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.CheckConnectivityWithTimeout(120 * time.Second)
		})
	})
})
