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

package discovery

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

// epSlice builds an EndpointSlice for serviceName with the given (ip, node)
// endpoints, all marked ready, exposing the calico-typha port.
func epSlice(name, serviceName string, eps ...endpointSpec) *discoveryv1.EndpointSlice {
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kube-system",
			Labels:    map[string]string{discoveryv1.LabelServiceName: serviceName},
		},
		Ports: []discoveryv1.EndpointPort{
			{Name: ptr.To("calico-typha"), Port: ptr.To(int32(5473))},
		},
	}
	for _, e := range eps {
		node := e.node
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{e.ip},
			NodeName:  &node,
		})
	}
	return slice
}

type endpointSpec struct {
	ip   string
	node string
}

var _ = Describe("Typha tier classification", func() {
	const (
		mainSvc   = "calico-typha"
		leaderSvc = "calico-typha-leader"
		tier1Svc  = "calico-typha-tier1"
		localNode = "node-local"
		leaderNd  = "node-leader"
		t1Node    = "node-t1"
		t2NodeA   = "node-t2a"
		t2NodeB   = "node-t2b"
	)

	// Topology: leader (10.0.0.1), one tier1 (10.0.0.2), two tier2 (10.0.0.3,
	// 10.0.0.4).  The main Service selects all four.
	var k8sClient *fake.Clientset
	buildClient := func(tieringActive bool) {
		main := epSlice("main-0", mainSvc,
			endpointSpec{"10.0.0.1", leaderNd},
			endpointSpec{"10.0.0.2", t1Node},
			endpointSpec{"10.0.0.3", t2NodeA},
			endpointSpec{"10.0.0.4", t2NodeB},
		)
		leader := epSlice("leader-0", leaderSvc, endpointSpec{"10.0.0.1", leaderNd})
		objs := []runtime.Object{main, leader}
		if tieringActive {
			objs = append(objs, epSlice("tier1-0", tier1Svc, endpointSpec{"10.0.0.2", t1Node}))
		}
		k8sClient = fake.NewClientset(objs...)
	}

	tierOf := func(addrs []Typha, ip string) Tier {
		for _, t := range addrs {
			if t.IP == ip {
				return t.Tier
			}
		}
		return TierUnknown
	}
	ipsOf := func(addrs []Typha) []string {
		var out []string
		for _, t := range addrs {
			out = append(out, t.IP)
		}
		return out
	}

	It("classifies every endpoint's tier (observed via a co-located client that keeps all tiers)", func() {
		// Co-locate the client with every Typha so the off-node tier filter keeps
		// them all, letting us assert the classification of each tier directly.
		main := epSlice("main-0", mainSvc,
			endpointSpec{"10.0.0.1", localNode}, // leader, local
			endpointSpec{"10.0.0.2", localNode}, // tier1, local
			endpointSpec{"10.0.0.3", localNode}, // tier2, local
		)
		leader := epSlice("leader-0", leaderSvc, endpointSpec{"10.0.0.1", localNode})
		tier1 := epSlice("tier1-0", tier1Svc, endpointSpec{"10.0.0.2", localNode})
		k8sClient = fake.NewClientset(main, leader, tier1)

		addrs, err := New(
			WithKubeService("kube-system", mainSvc),
			WithKubeClient(k8sClient),
			WithTierServices(leaderSvc, tier1Svc),
			WithNodeAffinity(localNode),
		).LoadTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		Expect(tierOf(addrs, "10.0.0.1")).To(Equal(TierLeader), "leader IP should be classified leader")
		Expect(tierOf(addrs, "10.0.0.2")).To(Equal(TierOne), "tier1 IP should be classified tier1")
		Expect(tierOf(addrs, "10.0.0.3")).To(Equal(TierTwo))
	})

	It("forbids off-node clients from leader/tier1 when tiering is active", func() {
		buildClient(true)
		addrs, err := New(
			WithKubeService("kube-system", mainSvc),
			WithKubeClient(k8sClient),
			WithTierServices(leaderSvc, tier1Svc),
			WithNodeAffinity(localNode), // client not co-located with any typha
		).LoadTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		// Only the two tier-2 endpoints survive.
		Expect(ipsOf(addrs)).To(ConsistOf("10.0.0.3", "10.0.0.4"))
	})

	It("always prefers a same-node Typha whatever its tier (even the leader)", func() {
		// Put the leader on the client's own node.  The client must still be
		// allowed to use it (same-node-first beats the off-node tier filter), and
		// it must come first in the ordering.
		main := epSlice("main-0", mainSvc,
			endpointSpec{"10.0.0.1", localNode}, // leader, co-located with client
			endpointSpec{"10.0.0.2", t1Node},
			endpointSpec{"10.0.0.3", t2NodeA},
		)
		leader := epSlice("leader-0", leaderSvc, endpointSpec{"10.0.0.1", localNode})
		tier1 := epSlice("tier1-0", tier1Svc, endpointSpec{"10.0.0.2", t1Node})
		k8sClient = fake.NewClientset(main, leader, tier1)

		addrs, err := New(
			WithKubeService("kube-system", mainSvc),
			WithKubeClient(k8sClient),
			WithTierServices(leaderSvc, tier1Svc),
			WithNodeAffinity(localNode),
		).LoadTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		// The co-located leader is kept and ordered first; the off-node tier1 is
		// filtered out; the off-node tier2 survives.
		Expect(addrs).NotTo(BeEmpty())
		Expect(addrs[0].IP).To(Equal("10.0.0.1"), "same-node leader must be first")
		Expect(addrs[0].Tier).To(Equal(TierLeader))
		Expect(ipsOf(addrs)).To(ConsistOf("10.0.0.1", "10.0.0.3"))
		Expect(ipsOf(addrs)).NotTo(ContainElement("10.0.0.2"), "off-node tier1 must be filtered")
	})

	It("allows off-node clients to use any Typha when tiering is NOT active", func() {
		// Single-tier mode: no tier1 Service endpoints.  The leader is still
		// classified, but off-node clients may use it.
		buildClient(false)
		addrs, err := New(
			WithKubeService("kube-system", mainSvc),
			WithKubeClient(k8sClient),
			WithTierServices(leaderSvc, tier1Svc),
			WithNodeAffinity(localNode),
		).LoadTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		// All four endpoints survive (leader included).
		Expect(ipsOf(addrs)).To(ConsistOf("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"))
		Expect(tierOf(addrs, "10.0.0.1")).To(Equal(TierLeader))
	})

	It("treats unknown-tier endpoints as tier-2 (fail open) on a fresh cluster", func() {
		// Brand-new cluster: tier1 Service has endpoints (tiering active) but the
		// leader Service has none yet (leader hasn't labelled itself).  The leader
		// IP is then unknown ⇒ tier2 ⇒ usable off-node.
		main := epSlice("main-0", mainSvc,
			endpointSpec{"10.0.0.1", leaderNd},
			endpointSpec{"10.0.0.3", t2NodeA},
		)
		// tier1 Service active but leader Service empty.
		tier1 := epSlice("tier1-0", tier1Svc, endpointSpec{"10.0.0.2", t1Node})
		emptyLeader := epSlice("leader-0", leaderSvc)
		k8sClient = fake.NewClientset(main, tier1, emptyLeader)

		addrs, err := New(
			WithKubeService("kube-system", mainSvc),
			WithKubeClient(k8sClient),
			WithTierServices(leaderSvc, tier1Svc),
			WithNodeAffinity(localNode),
		).LoadTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		// 10.0.0.1 is unknown (not in leader svc) ⇒ tier2 ⇒ kept off-node.
		Expect(tierOf(addrs, "10.0.0.1")).To(Equal(TierTwo))
		Expect(ipsOf(addrs)).To(ConsistOf("10.0.0.1", "10.0.0.3"))
	})

	It("fails open (keeps everything) when listing tier Services errors", func() {
		// No tier Service slices exist at all ⇒ serviceEndpointIPs returns empty
		// ⇒ tiering not active ⇒ everything classified tier2 and kept.
		main := epSlice("main-0", mainSvc,
			endpointSpec{"10.0.0.1", leaderNd},
			endpointSpec{"10.0.0.3", t2NodeA},
		)
		k8sClient = fake.NewClientset(main)
		addrs, err := New(
			WithKubeService("kube-system", mainSvc),
			WithKubeClient(k8sClient),
			WithTierServices(leaderSvc, tier1Svc),
			WithNodeAffinity(localNode),
		).LoadTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		Expect(ipsOf(addrs)).To(ConsistOf("10.0.0.1", "10.0.0.3"))
	})
})
