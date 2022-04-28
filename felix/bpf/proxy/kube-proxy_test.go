// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package proxy_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/mock"
	proxy "github.com/projectcalico/calico/felix/bpf/proxy"
)

var _ = Describe("BPF kube-proxy", func() {
	initIP := net.IPv4(1, 1, 1, 1)

	bpfMc := &bpf.MapContext{}
	bpfMc.FrontendMap = newMockNATMap()
	bpfMc.BackendMap = newMockNATBackendMap()
	bpfMc.AffinityMap = newMockAffinityMap()
	bpfMc.CtMap = mock.NewMockMap(conntrack.MapParams)
	front := bpfMc.FrontendMap.(*mockNATMap)

	var p *proxy.KubeProxy

	BeforeEach(func() {
		testSvc := &v1.Service{
			TypeMeta:   typeMetaV1("Service"),
			ObjectMeta: objectMeataV1("testService"),
			Spec: v1.ServiceSpec{
				ClusterIP: "10.1.0.1",
				Type:      v1.ServiceTypeClusterIP,
				Selector: map[string]string{
					"app": "test",
				},
				Ports: []v1.ServicePort{
					{
						Protocol: v1.ProtocolTCP,
						Port:     1234,
						NodePort: 666,
					},
				},
			},
		}

		testSvcEps := &v1.Endpoints{
			TypeMeta:   typeMetaV1("Endpoints"),
			ObjectMeta: objectMeataV1("testService"),
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP: "10.1.2.1",
						},
					},
					Ports: []v1.EndpointPort{
						{
							Port: 1234,
						},
					},
				},
			},
		}

		k8s := fake.NewSimpleClientset(testSvc, testSvcEps)
		p, _ = proxy.StartKubeProxy(k8s, "test-node", bpfMc, proxy.WithImmediateSync())
	})

	AfterEach(func() {
		p.Stop()
	})

	It("should update nodeports after host ip changes", func() {
		By("checking nodeport has the initial IP", func() {
			p.OnHostIPsUpdate([]net.IP{initIP})
			Eventually(func() bool {
				front.Lock()
				defer front.Unlock()

				for k := range front.m {
					if k.Addr().String() == initIP.String() {
						return true
					}
				}
				return false
			}).Should(BeTrue())
		})

		By("checking nodeport has the updated IP and not the initial IP", func() {
			updatedIP := net.IPv4(2, 2, 2, 2)
			p.OnHostIPsUpdate([]net.IP{updatedIP})

			Eventually(func() bool {
				front.Lock()
				defer front.Unlock()

				for k := range front.m {
					if k.Addr().String() == initIP.String() {
						return false
					}
					if k.Addr().String() == updatedIP.String() {
						return true
					}
				}
				return false
			}).Should(BeTrue())
		})

		By("checking nodeport has 2 updated IPs", func() {
			ip1 := net.IPv4(3, 3, 3, 3)
			ip2 := net.IPv4(4, 4, 4, 4)
			p.OnHostIPsUpdate([]net.IP{ip1, ip2})

			Eventually(func() bool {
				front.Lock()
				defer front.Unlock()

				ip1ok := false
				ip2ok := false

				for k := range front.m {
					if k.Addr().String() == ip1.String() {
						ip1ok = true
					} else if k.Addr().String() == ip2.String() {
						ip2ok = true
					}
				}
				return ip1ok && ip2ok
			}).Should(BeTrue())
		})
	})
})
