// +build fvtests

// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"errors"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

var _ = Context("etcd connection interruption", func() {

	var (
		etcd    *containers.Container
		felixes []*containers.Felix
		client  client.Interface
		w       [2]*workload.Workload
		cc      *workload.ConnectivityChecker
	)

	BeforeEach(func() {
		felixes, etcd, client = containers.StartNNodeEtcdTopology(2, containers.DefaultTopologyOptions())

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Name = "default"
		defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
		defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
		defaultProfile.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err := client.Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

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
			wIface := fmt.Sprintf("cali1%d", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felixes[ii], wName, wIface, wIP, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &workload.ConnectivityChecker{}
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
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	It("should detect and recoonnect after the etcd connection is black-holed", func() {
		By("having initial workload to workload connectivity", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		By("silently dropping etcd packets", func() {
			// Normally, if a connection closes at either end, the other peer's traffic will get
			// FIN or RST responses, which cleanly shut down the connection.  However, in order
			// to test the GRPC-level keep-alives, we want to simulate a network or NAT change that
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
						"-t", "raw", "-I", "PREROUTING",
						"-p", "tcp",
						"-s", etcd.IP,
						"-m", "multiport", "--destination-ports", matches[1],
						"-j", "DROP")
					felix.Exec("iptables",
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
