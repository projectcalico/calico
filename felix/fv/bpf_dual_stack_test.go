// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"
	"fmt"
	"net"
	"strconv"

	//"time"

	//"strings"
	"k8s.io/client-go/kubernetes"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"

	//"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	//options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf dual stack tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	if !BPFMode() {
		return
	}

	var (
		infra          infrastructure.DatastoreInfra
		tc             infrastructure.TopologyContainers
		w              [3][2]*workload.Workload
		hostW          [3]*workload.Workload
		externalClient *containers.Container
		calicoClient   client.Interface
		cc             *Checker
	)

	felixIP := func(f int) string {
		return tc.Felixes[f].Container.IP
	}

	felixIP6 := func(f int) string {
		return tc.Felixes[f].Container.IPv6
	}

	BeforeEach(func() {
		iOpts := []infrastructure.CreateOption{infrastructure.K8sWithIPv6(),
			infrastructure.K8sWithAPIServerBindAddress("::"),
			infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112")}
		infra = getInfra(iOpts...)
		cc = &Checker{
			CheckSNAT: true,
		}
		cc.Protocol = "tcp"
		opts := infrastructure.DefaultTopologyOptions()
		opts.EnableIPv6 = true
		//opts.FelixLogSeverity = "Debug"
		opts.NATOutgoingEnabled = true
		opts.AutoHEPsEnabled = true
		opts.IPIPEnabled = false
		opts.IPIPRoutesEnabled = false

		opts.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
		opts.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBDisabled)
		opts.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)

		//opts.ExtraEnvVars["FELIX_BPFLogLevel"] = fmt.Sprint("debug")
		tc, calicoClient = infrastructure.StartNNodeTopology(3, opts, infra)

		addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
			if labels == nil {
				labels = make(map[string]string)
			}

			wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2) + "," + net.ParseIP(fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)).String()
			wName := fmt.Sprintf("w%d%d", ii, wi)

			w := workload.New(tc.Felixes[ii], wName, "default",
				wIP, strconv.Itoa(port), "tcp")

			labels["name"] = w.Name
			labels["workload"] = "regular"

			w.WorkloadEndpoint.Labels = labels
			if run {
				err := w.Start()
				Expect(err).NotTo(HaveOccurred())
				w.ConfigureInInfra(infra)
			}

			if opts.UseIPPools {
				// Assign the workload's IP in IPAM, this will trigger calculation of routes.
				err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
					IP:       cnet.MustParseIP(w.IP),
					HandleID: &w.Name,
					Attrs: map[string]string{
						ipam.AttributeNode: tc.Felixes[ii].Hostname,
					},
					Hostname: tc.Felixes[ii].Hostname,
				})
				Expect(err).NotTo(HaveOccurred())
				err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
					IP:       cnet.MustParseIP(w.IP6),
					HandleID: &w.Name,
					Attrs: map[string]string{
						ipam.AttributeNode: tc.Felixes[ii].Hostname,
					},
					Hostname: tc.Felixes[ii].Hostname,
				})
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
				felixIP(ii)+","+felixIP6(ii), // Same IP as felix means "run in the host's namespace"
				"8055",
				"tcp")

			hostW[ii].WorkloadEndpoint.Labels = map[string]string{"name": hostW[ii].Name}

			// Two workloads on each host so we can check the same host and other host cases.
			w[ii][0] = addWorkload(true, ii, 0, 8055, map[string]string{"port": "8055"})
			w[ii][1] = addWorkload(true, ii, 1, 8056, nil)
		}

		// Create a workload on node 0 that does not run, but we can use it to set up paths
		//deadWorkload = addWorkload(false, 0, 2, 8057, nil)

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		// TODO: Copied from another test
		externalClient = infrastructure.RunExtClient("ext-client")
		_ = externalClient

		err := infra.AddDefaultDeny()
		Expect(err).NotTo(HaveOccurred())
		ensureAllNodesBPFProgramsAttached(tc.Felixes)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
			for _, felix := range tc.Felixes {
				felix.Exec("calico-bpf", "counters", "dump")
			}
		}

		for i := 0; i < 3; i++ {
			for j := 0; j < 2; j++ {
				w[i][j].Stop()
			}
		}
		tc.Stop()
		infra.Stop()
	})

	createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
		log.WithField("policy", dumpResource(policy)).Info("Creating policy")
		policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		return policy
	}

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
		It("Connect to w[0][0] from all other workloads", func() {
			cc.ExpectSome(w[0][1], w[0][0])
			cc.Expect(Some, w[1][0], w[0][0])
			cc.ExpectSome(w[1][1], w[0][0])
			cc.Expect(Some, w[0][1], w[0][0], ExpectWithIPv6())
			cc.Expect(Some, w[1][0], w[0][0], ExpectWithIPv6())
			cc.Expect(Some, w[1][1], w[0][0], ExpectWithIPv6())
			cc.CheckConnectivity()
		})
	})

})
