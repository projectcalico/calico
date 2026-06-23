// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/bpf/nat"
	proxy "github.com/projectcalico/calico/felix/bpf/proxy"
)

// In BPF bootstrap mode Felix reaches the API server through the
// default/kubernetes ClusterIP service's NAT entry. If a transient loss of that
// service's endpoints cleared the NAT backend, Felix would sever its own
// connection to the API server and could never learn the restored endpoints —
// an unrecoverable deadlock that only a calico-node restart fixes. The syncer
// must therefore retain the last-known-good backend for that service.
var _ = Describe("BPF Syncer API server NAT preservation", func() {
	var (
		svcs  *mockNATMap
		eps   *mockNATBackendMap
		mgEps *mockMaglevMap
		aff   *mockAffinityMap
		rt    *proxy.RTCache
		s     *proxy.Syncer
	)

	nodeIPs := []net.IP{net.IPv4(192, 168, 0, 1)}

	apiSvcKey := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "kubernetes"},
	}
	apiClusterIP := net.IPv4(10, 49, 0, 1)
	apiPort := 443
	apiServerIP := net.IPv4(10, 0, 1, 20)

	regularSvcKey := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "regular"},
	}
	regClusterIP := net.IPv4(10, 49, 0, 2)
	regPort := 80

	tcp := proxy.ProtoV1ToIntPanic(v1.ProtocolTCP)
	apiFrontKey := nat.NewNATKey(apiClusterIP, uint16(apiPort), tcp)
	regFrontKey := nat.NewNATKey(regClusterIP, uint16(regPort), tcp)
	apiBackend := nat.NewNATBackendValue(apiServerIP, 6443)

	// state builds a sync state with the regular service always backed by a
	// ready endpoint. The API server service is backed by apiEPIP when non-empty,
	// otherwise it has no endpoints at all (the transient outage we reproduce).
	state := func(apiEPIP string, regularEPs bool) proxy.DPSyncerState {
		st := proxy.DPSyncerState{
			SvcMap: k8sp.ServicePortMap{
				apiSvcKey:     proxy.NewK8sServicePort(apiClusterIP, apiPort, v1.ProtocolTCP),
				regularSvcKey: proxy.NewK8sServicePort(regClusterIP, regPort, v1.ProtocolTCP),
			},
			EpsMap: k8sp.EndpointsMap{},
		}
		if apiEPIP != "" {
			st.EpsMap[apiSvcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo(apiEPIP, 6443, proxy.EndpointInfoOptIsReady(true)),
			}
		}
		if regularEPs {
			st.EpsMap[regularSvcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 8080, proxy.EndpointInfoOptIsReady(true)),
			}
		}
		return st
	}

	BeforeEach(func() {
		svcs = newMockNATMap()
		eps = newMockNATBackendMap()
		mgEps = newMockMaglevMap()
		aff = newMockAffinityMap()
		rt = proxy.NewRTCache()
		s, _ = proxy.NewSyncer(4, nodeIPs, svcs, eps, mgEps, aff, rt, nil, maglevLUTSize)
	})

	It("retains the API server backend across a transient loss of endpoints", func() {
		By("programming the API server backend from real endpoints")
		Expect(s.Apply(state(apiServerIP.String(), true))).NotTo(HaveOccurred())

		front, ok := svcs.m[apiFrontKey]
		Expect(ok).To(BeTrue())
		Expect(front.Count()).To(Equal(uint32(1)))
		Expect(eps.m[nat.NewNATBackendKey(front.ID(), 0)]).To(Equal(apiBackend))

		By("losing all API server endpoints: the backend must be preserved")
		Expect(s.Apply(state("", true))).NotTo(HaveOccurred())

		front, ok = svcs.m[apiFrontKey]
		Expect(ok).To(BeTrue())
		Expect(front.Count()).To(Equal(uint32(1)),
			"API server NAT frontend must keep its last-known-good backend")
		Expect(eps.m[nat.NewNATBackendKey(front.ID(), 0)]).To(Equal(apiBackend))

		By("a regular service losing its endpoints still drops to zero (scoping)")
		Expect(s.Apply(state("", false))).NotTo(HaveOccurred())
		regFront, ok := svcs.m[regFrontKey]
		Expect(ok).To(BeTrue())
		Expect(regFront.Count()).To(Equal(uint32(0)),
			"only the API server service is protected; regular services are not")
		// API server backend is still preserved through this apply too.
		apiFront, ok := svcs.m[apiFrontKey]
		Expect(ok).To(BeTrue())
		Expect(apiFront.Count()).To(Equal(uint32(1)))

		By("API server endpoints returning: the NAT converges on the live backend")
		Expect(s.Apply(state(apiServerIP.String(), true))).NotTo(HaveOccurred())
		front, ok = svcs.m[apiFrontKey]
		Expect(ok).To(BeTrue())
		Expect(front.Count()).To(Equal(uint32(1)))
		Expect(eps.m[nat.NewNATBackendKey(front.ID(), 0)]).To(Equal(apiBackend))
	})
})
