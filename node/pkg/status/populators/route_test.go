// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package populator

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("Test BIRD BGP routes Scanner", func() {

	It("should be able to scan routes", func() {

		table := `0001 BIRD v0.3.3+birdv1.6.8 ready.
1007-0.0.0.0/0          via 172.17.0.1 on eth0 [kernel1 20:10:57] * (10)
 192.168.110.128/26 via 172.17.0.5 on eth0 [Mesh_172_17_0_5 20:10:57] * (100/0) [i]
 192.168.82.0/26    via 172.17.0.4 on eth0 [Mesh_172_17_0_4 20:11:00] * (100/0) [i]
                    via 100.100.100.100 on em0 [Global_100_100_100_100 20:11:00] (100/?) [AS65001?]
 192.168.162.128/26 blackhole [static1 20:10:56] * (200)
 192.168.162.128/32 dev tunl0 [direct1 20:10:56] * (240)
 192.168.162.129/32 dev calie58e37f9a7f [kernel1 20:11:10] * (10)
 172.17.0.0/16      dev eth0 [direct1 20:10:56] * (240)
0000
`
		expectedRoutes := []route{
			{
				dest:        "0.0.0.0/0",
				gateway:     "172.17.0.1",
				iface:       "eth0",
				learnedFrom: "kernel1",
				primary:     true,
			},
			{
				dest:        "192.168.110.128/26",
				gateway:     "172.17.0.5",
				iface:       "eth0",
				learnedFrom: "Mesh_172_17_0_5",
				primary:     true,
			},
			{
				dest:        "192.168.82.0/26",
				gateway:     "172.17.0.4",
				iface:       "eth0",
				learnedFrom: "Mesh_172_17_0_4",
				primary:     true,
			},
			{
				dest:        "192.168.82.0/26",
				gateway:     "100.100.100.100",
				iface:       "em0",
				learnedFrom: "Global_100_100_100_100",
				primary:     false,
			},
			{
				dest:        "192.168.162.128/26",
				gateway:     "N/A",
				iface:       "blackhole",
				learnedFrom: "static1",
				primary:     true,
			},
			{
				dest:        "192.168.162.128/32",
				gateway:     "N/A",
				iface:       "tunl0",
				learnedFrom: "direct1",
				primary:     true,
			},
			{
				dest:        "192.168.162.129/32",
				gateway:     "N/A",
				iface:       "calie58e37f9a7f",
				learnedFrom: "kernel1",
				primary:     true,
			},
			{
				dest:        "172.17.0.0/16",
				gateway:     "N/A",
				iface:       "eth0",
				learnedFrom: "direct1",
				primary:     true,
			},
		}
		routes, err := readBIRDRoutes(getMockBirdConn(IPFamilyV4, table))
		Expect(routes).To(HaveLen(8))

		Expect(routes).To(Equal(expectedRoutes))
		Expect(err).NotTo(HaveOccurred())

		// Check we can print peers.
		printRoutes(routes)
	})

	It("should be able to scan routes with multiple blackhole and unreachable routes", func() {

		table := `0001 BIRD v0.3.3+birdv1.6.8 ready.
1007-0.0.0.0/0          via 172.17.0.1 on eth0 [kernel1 20:10:57] * (10)
 192.168.69.128/26  blackhole [static1 09:23:20] * (200)
                   unreachable [Mesh_10_128_0_244 09:23:24 from 10.128.0.244] (100/-) [i]
                   blackhole [kernel1 09:23:21] (10)
 192.168.36.64/26   via 10.128.0.1 on ens4 [Mesh_10_128_0_241 09:23:23 from 10.128.0.241] * (100/?) [i]
                   unreachable [Mesh_10_128_0_244 09:23:24 from 10.128.0.244] (100/-) [i]
                   via 10.128.0.1 on ens4 [Mesh_10_128_0_241 09:23:23 from 10.128.0.241] (100/?) [i]
                   unreachable [Mesh_10_128_0_200 09:23:23 from 10.128.0.200] (100/-) [i]
                   via 192.168.36.64 on vxlan.calico [kernel1 09:23:21] (10)
0000
`
		expectedRoutes := []route{
			{
				dest:        "0.0.0.0/0",
				gateway:     "172.17.0.1",
				iface:       "eth0",
				learnedFrom: "kernel1",
				primary:     true,
			},
			{
				dest:        "192.168.69.128/26",
				gateway:     "N/A",
				iface:       "blackhole",
				learnedFrom: "static1",
				primary:     true,
			},
			{
				dest:        "192.168.69.128/26",
				gateway:     "N/A",
				iface:       "unreachable",
				learnedFrom: "Mesh_10_128_0_244",
				primary:     false,
			},
			{
				dest:        "192.168.69.128/26",
				gateway:     "N/A",
				iface:       "blackhole",
				learnedFrom: "kernel1",
				primary:     false,
			},
			{
				dest:        "192.168.36.64/26",
				gateway:     "10.128.0.1",
				iface:       "ens4",
				learnedFrom: "Mesh_10_128_0_241",
				primary:     true,
			},
			{
				dest:        "192.168.36.64/26",
				gateway:     "N/A",
				iface:       "unreachable",
				learnedFrom: "Mesh_10_128_0_244",
				primary:     false,
			},
			{
				dest:        "192.168.36.64/26",
				gateway:     "10.128.0.1",
				iface:       "ens4",
				learnedFrom: "Mesh_10_128_0_241",
				primary:     false,
			},
			{
				dest:        "192.168.36.64/26",
				gateway:     "N/A",
				iface:       "unreachable",
				learnedFrom: "Mesh_10_128_0_200",
				primary:     false,
			},
			{
				dest:        "192.168.36.64/26",
				gateway:     "192.168.36.64",
				iface:       "vxlan.calico",
				learnedFrom: "kernel1",
				primary:     false,
			},
		}
		routes, err := readBIRDRoutes(getMockBirdConn(IPFamilyV4, table))
		Expect(routes).To(HaveLen(9))

		Expect(routes).To(Equal(expectedRoutes))
		Expect(err).NotTo(HaveOccurred())

		// Check we can print peers.
		printRoutes(routes)
	})

	DescribeTable("Convert to v3 object",
		func(r *route, v3Route *v3.CalicoNodeRoute) {
			apiRoute, err := r.toNodeStatusAPI()
			Expect(err).ToNot(HaveOccurred())
			Expect(apiRoute).To(Equal(v3Route))
		},
		Entry(
			"mesh route fib",
			&route{
				dest:        "192.168.110.128/26",
				gateway:     "172.17.0.5",
				iface:       "eth0",
				learnedFrom: "Mesh_172_17_0_5",
				primary:     true,
			},
			&v3.CalicoNodeRoute{
				Type:        v3.RouteTypeFIB,
				Destination: "192.168.110.128/26",
				Gateway:     "172.17.0.5",
				Interface:   "eth0",
				LearnedFrom: v3.CalicoNodeRouteLearnedFrom{
					SourceType: v3.RouteSourceTypeNodeMesh,
					PeerIP:     "172.17.0.5",
				},
			},
		),
		Entry(
			"global route rib",
			&route{
				dest:        "192.168.110.128/26",
				gateway:     "172.17.0.5",
				iface:       "eth0",
				learnedFrom: "Global_172_17_0_5",
				primary:     false,
			},
			&v3.CalicoNodeRoute{
				Type:        v3.RouteTypeRIB,
				Destination: "192.168.110.128/26",
				Gateway:     "172.17.0.5",
				Interface:   "eth0",
				LearnedFrom: v3.CalicoNodeRouteLearnedFrom{
					SourceType: v3.RouteSourceTypeBGPPeer,
					PeerIP:     "172.17.0.5",
				},
			},
		),
		Entry(
			"kernel route",
			&route{
				dest:        "192.168.162.129/32",
				gateway:     "N/A",
				iface:       "calie58e37f9a7f",
				learnedFrom: "kernel1",
				primary:     true,
			},
			&v3.CalicoNodeRoute{
				Type:        v3.RouteTypeFIB,
				Destination: "192.168.162.129/32",
				Gateway:     "N/A",
				Interface:   "calie58e37f9a7f",
				LearnedFrom: v3.CalicoNodeRouteLearnedFrom{
					SourceType: v3.RouteSourceTypeKernel,
				},
			},
		),
		Entry(
			"direct route",
			&route{
				dest:        "172.17.0.0/16",
				gateway:     "N/A",
				iface:       "eth0",
				learnedFrom: "direct1",
				primary:     true,
			},
			&v3.CalicoNodeRoute{
				Type:        v3.RouteTypeFIB,
				Destination: "172.17.0.0/16",
				Gateway:     "N/A",
				Interface:   "eth0",
				LearnedFrom: v3.CalicoNodeRouteLearnedFrom{
					SourceType: v3.RouteSourceTypeDirect,
				},
			},
		),
	)
})
