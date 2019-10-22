// +build fvtests

// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strconv"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-NAT_ _BPF-SAFE_ BPF NAT tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra          infrastructure.DatastoreInfra
		felixes        []*infrastructure.Felix
		w              [2][2]*workload.Workload // 1st workload on each host
		hostW          [2]*workload.Workload
		client         client.Interface
		cc             *workload.ConnectivityChecker
		externalClient *containers.Container
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		options := infrastructure.DefaultTopologyOptions()
		felixes, client = infrastructure.StartNNodeTopology(2, options, infra)
		cc = &workload.ConnectivityChecker{}

		// Start a host networked workload on each host for connectivity checks.
		for ii, felix := range felixes {
			// We tell each host-networked workload to open:
			// TODO: Copied from another test
			// - its normal (uninteresting) port, 8055
			// - port 2379, which is both an inbound and an outbound failsafe port
			// - port 22, which is an inbound failsafe port.
			// This allows us to test the interaction between do-not-track policy and failsafe
			// ports.
			const portsToOpen = "8055,2379,22"
			hostW[ii] = workload.Run(
				felixes[ii],
				fmt.Sprintf("host%d", ii),
				"default",
				felixes[ii].IP, // Same IP as felix means "run in the host's namespace"
				portsToOpen,
				"tcp")

			// Two workloads on each host so we can check the same host and other host cases.
			iiStr := strconv.Itoa(ii)
			w[ii][0] = workload.Run(felix, "w"+iiStr+"0", "default", "10.65."+iiStr+".2", "8055", "tcp")
			w[ii][0].WorkloadEndpoint.Labels = map[string]string{"name": w[ii][0].Name}
			w[ii][0].ConfigureInDatastore(infra)
			w[ii][1] = workload.Run(felix, "w"+iiStr+"1", "default", "10.65."+iiStr+".3", "8056", "tcp")
			w[ii][1].WorkloadEndpoint.Labels = map[string]string{"name": w[ii][1].Name}
			w[ii][1].ConfigureInDatastore(infra)
		}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		// TODO: Copied from another test
		externalClient = containers.Run("external-client",
			containers.RunOpts{AutoRemove: true},
			"--privileged", // So that we can add routes inside the container.
			utils.Config.BusyboxImage,
			"/bin/sh", "-c", "sleep 1000")
		_ = externalClient

		err = infra.AddDefaultDeny()
		Expect(err).To(BeNil())
	})

	JustAfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ip", "r")
				felix.Exec("calico-bpf", "ipsets", "dump")
			}
		}
	})

	AfterEach(func() {
		for _, f := range felixes {
			f.Stop()
		}
		infra.Stop()
		externalClient.Stop()
	})

	It("should deny all by default", func() {
		// Same host, other workload.
		cc.ExpectNone(w[0][0], w[0][1])
		cc.ExpectNone(w[0][1], w[0][0])
		// Other host.
		cc.ExpectNone(w[0][0], w[1][0])
		cc.ExpectNone(w[1][0], w[0][0])
		cc.CheckConnectivity()
	})

	createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
		log.WithField("policy", dumpResource(policy)).Info("Creating policy")
		policy, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		return policy
	}

	updatePolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
		log.WithField("policy", dumpResource(policy)).Info("Updating policy")
		policy, err := client.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		return policy
	}
	_ = updatePolicy

	Context("with a policy allowing ingress to w[0][0]", func() {
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
						Selector: "all()",
					},
				},
			}
			pol.Spec.Egress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Selector: "all()",
					},
				},
			}
			pol.Spec.Selector = "all()"

			pol = createPolicy(pol)

			k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			_ = k8sClient
		})

		It("connectivity from all workloads via workload 0's main IP", func() {
			cc.ExpectSome(w[0][1], w[0][0])
			cc.ExpectSome(w[1][0], w[0][0])
			cc.ExpectSome(w[1][1], w[0][0])
			cc.CheckConnectivity()
		})

		Context("with nat configured 10.96.0.1:80 -> 10.65.0.1:8055 (w[0][0])", func() {
			BeforeEach(func() {
				testSvc := &v1.Service{
					TypeMeta:   typeMetaV1("Service"),
					ObjectMeta: objectMetaV1("test-service"),
					Spec: v1.ServiceSpec{
						ClusterIP: "10.101.0.10",
						Type:      v1.ServiceTypeClusterIP,
						Selector: map[string]string{
							"name": w[0][0].Name,
						},
						Ports: []v1.ServicePort{
							{
								Protocol: v1.ProtocolTCP,
								Port:     80,
							},
						},
					},
				}

				_, err := k8sClient.CoreV1().Services("default").Create(testSvc)
				Expect(err).NotTo(HaveOccurred())
			})

			It("connectivity from all workloads via workload 0's NAT", func() {
				cc.ExpectSome(w[0][1], workload.IP("10.101.0.10"), 80)
				cc.ExpectSome(w[1][0], workload.IP("10.101.0.10"), 80)
				cc.ExpectSome(w[1][1], workload.IP("10.101.0.10"), 80)
				cc.CheckConnectivity()
			})
		})
	})
})

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
