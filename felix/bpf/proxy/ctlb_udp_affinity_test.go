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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/nat"
	proxy "github.com/projectcalico/calico/felix/bpf/proxy"
)

// The connect-time load balancer keeps a backend affine to an *unconnected* UDP
// socket for the "UDP not seen" timeout, whether or not the service asks for
// session affinity, so that consecutive datagrams from one socket reach one
// backend. The syncer's affinity map cleanup must leave those entries alone;
// deleting them sends the next datagram to a fresh random backend.
var _ = Describe("BPF Syncer CTLB UDP affinity cleanup", func() {
	const ctlbUDPTimeo = 60 * time.Second

	svcKey := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "udp-service"},
	}
	clusterIP := net.IPv4(10, 0, 0, 1)
	const svcPort = 1234
	liveBackend := net.IPv4(10, 1, 0, 1)
	const backendPort = 5555
	clientIP := net.IPv4(5, 5, 5, 5)

	var (
		aff *mockAffinityMap
		s   *proxy.Syncer
	)

	// newSyncer builds a syncer that has already programmed a single service with
	// the given protocol and session affinity, and that believes the CTLB enforces
	// UDP affinity for ctlbAffinityTimeo.
	newSyncer := func(proto v1.Protocol, sticky bool, ctlbAffinityTimeo time.Duration) proxy.DPSyncerState {
		aff = newMockAffinityMap()
		var err error
		s, err = proxy.NewSyncer(4, []net.IP{net.IPv4(192, 168, 0, 1)},
			newMockNATMap(), newMockNATBackendMap(), newMockMaglevMap(), aff,
			proxy.NewRTCache(), nil, maglevLUTSize, ctlbAffinityTimeo)
		Expect(err).NotTo(HaveOccurred())

		opts := []proxy.K8sServicePortOption{}
		if sticky {
			opts = append(opts, proxy.K8sSvcWithStickyClientIP(5))
		}
		state := proxy.DPSyncerState{
			SvcMap: k8sp.ServicePortMap{
				svcKey: proxy.NewK8sServicePort(clusterIP, svcPort, proto, opts...),
			},
			EpsMap: k8sp.EndpointsMap{
				svcKey: []k8sp.Endpoint{
					proxy.NewEndpointInfo(liveBackend.String(), backendPort,
						proxy.EndpointInfoOptIsReady(true)),
				},
			},
		}
		Expect(s.Apply(state)).NotTo(HaveOccurred())
		return state
	}

	// addAffEntry writes the affinity entry that the CTLB would have written for a
	// datagram sent age ago to the given backend.
	addAffEntry := func(proto v1.Protocol, backend net.IP, age time.Duration) {
		err := aff.Update(
			nat.NewAffinityKey(clientIP,
				nat.NewNATKey(clusterIP, svcPort, proxy.ProtoV1ToIntPanic(proto)),
			).AsBytes(),
			nat.NewAffinityValue(
				uint64(bpf.KTimeNanos())-uint64(age),
				nat.NewNATBackendValue(backend, backendPort),
			).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(aff.m).To(HaveLen(1))
	}

	DescribeTable("cleanup of a UDP affinity entry",
		func(sticky bool, ctlbAffinityTimeo time.Duration, age time.Duration, backend net.IP, expectKept bool) {
			state := newSyncer(v1.ProtocolUDP, sticky, ctlbAffinityTimeo)
			addAffEntry(v1.ProtocolUDP, backend, age)

			Expect(s.Apply(state)).NotTo(HaveOccurred())

			if expectKept {
				Expect(aff.m).To(HaveLen(1), "affinity entry must survive cleanup")
			} else {
				Expect(aff.m).To(BeEmpty(), "affinity entry must be cleaned up")
			}
		},
		// The regression: without session affinity the syncer used to know
		// nothing about the entry and deleted it on the next sync.
		Entry("fresh, no session affinity, CTLB does UDP: kept",
			false, ctlbUDPTimeo, time.Second, liveBackend, true),
		Entry("older than the CTLB timeout: cleaned up",
			false, ctlbUDPTimeo, 2*ctlbUDPTimeo, liveBackend, false),
		Entry("pointing at a backend that is gone: cleaned up",
			false, ctlbUDPTimeo, time.Second, net.IPv4(10, 9, 9, 9), false),
		// With no CTLB UDP affinity nothing should be creating these entries, so
		// the syncer is right to reclaim them.
		Entry("fresh, no session affinity, CTLB skips UDP: cleaned up",
			false, time.Duration(0), time.Second, liveBackend, false),
		// Session affinity's own (longer) timeout must still win.
		Entry("fresh, session affinity, CTLB skips UDP: kept",
			true, time.Duration(0), time.Second, liveBackend, true),
	)

	It("cleans up a TCP affinity entry for a service without session affinity", func() {
		// The CTLB only enforces affinity for unconnected UDP, so a TCP entry on a
		// service without session affinity is still stale.
		state := newSyncer(v1.ProtocolTCP, false, ctlbUDPTimeo)
		addAffEntry(v1.ProtocolTCP, liveBackend, time.Second)

		Expect(s.Apply(state)).NotTo(HaveOccurred())
		Expect(aff.m).To(BeEmpty())
	})
})
