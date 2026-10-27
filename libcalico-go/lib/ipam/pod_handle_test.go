// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package ipam_test

import (
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
)

var _ = Describe("Pod handle IDs", func() {
	runtimeID := strings.Repeat("0123456789abcdef", 4)

	DescribeTable("ParsePodHandleID",
		func(handle string, expect bool, containerID string) {
			parsed, ok := ipam.ParsePodHandleID(handle, "k8s-pod-network")
			Expect(ok).To(Equal(expect))
			if expect {
				Expect(parsed).To(Equal(ipam.PodHandle{Network: "k8s-pod-network", ContainerID: containerID}))
			}
		},
		Entry("an earlier sandbox of the same pod", "k8s-pod-network.old-container", true, "old-container"),
		Entry("a runtime-shaped container ID", "k8s-pod-network."+runtimeID, true, runtimeID),
		Entry("a trailing carriage return from the host-local migration", "k8s-pod-network.old-container\r", true, "old-container"),
		Entry("a different network", "other-network.old-container", false, ""),
		Entry("a handle carrying an interface component", "k8s-pod-network.old-container.eth0", false, ""),
		Entry("a pre-v3 workload handle", "k8s-pod-network.default.mypod", false, ""),
		Entry("a VM handle", "k8s-pod-network.vmi.default.vm1", false, ""),
		Entry("a tunnel address handle", "ipip-tunnel-addr-node1", false, ""),
		Entry("a load balancer handle", "lb-abc123", false, ""),
		Entry("the Windows reserved handle", "windows-reserved-ipam-handle", false, ""),
		Entry("an empty handle", "", false, ""),
		Entry("a network name with no container ID", "k8s-pod-network.", false, ""),
	)

	DescribeTable("ParsePodHandleIDAnyNetwork",
		func(handle string, expect bool, network string) {
			parsed, ok := ipam.ParsePodHandleIDAnyNetwork(handle)
			Expect(ok).To(Equal(expect))
			if expect {
				Expect(parsed).To(Equal(ipam.PodHandle{Network: network, ContainerID: runtimeID}))
			}
		},
		Entry("the default network", "k8s-pod-network."+runtimeID, true, "k8s-pod-network"),
		Entry("a network name containing dots", "secondary.network."+runtimeID, true, "secondary.network"),
		Entry("a network named vmi", "vmi."+runtimeID, true, "vmi"),
		Entry("a trailing carriage return from the host-local migration", "k8s-pod-network."+runtimeID+"\r", true, "k8s-pod-network"),
		Entry("a container ID that isn't runtime-shaped", "k8s-pod-network.old-container", false, ""),
		Entry("an upper-case container ID", "k8s-pod-network."+strings.ToUpper(runtimeID), false, ""),
		Entry("a truncated container ID", "k8s-pod-network."+runtimeID[:63], false, ""),
		Entry("a handle carrying an interface component", "k8s-pod-network."+runtimeID+".eth0", false, ""),
		Entry("a pre-v3 workload handle", "k8s-pod-network.default.mypod", false, ""),
		Entry("a container ID with no network", runtimeID, false, ""),
		Entry("an empty network", "."+runtimeID, false, ""),
		Entry("an empty handle", "", false, ""),
	)

	It("rejects both forms of VM handle on any network", func() {
		unhashed := vmipam.CreateVMHandleID("k8s-pod-network", "default", "vm1")
		hashed := vmipam.CreateVMHandleID("secondary.network", "default", strings.Repeat("v", 200))
		Expect(hashed).To(MatchRegexp(regexp.QuoteMeta(vmipam.VMHandleInfix)+"[0-9a-f]{64}$"), "the VM name should be long enough to hash")

		for _, handle := range []string{unhashed, hashed} {
			_, ok := ipam.ParsePodHandleIDAnyNetwork(handle)
			Expect(ok).To(BeFalse(), handle)
		}
	})

	It("parses what PodHandleID builds", func() {
		for _, network := range []string{"k8s-pod-network", "secondary.network"} {
			handle := ipam.PodHandleID(network, runtimeID)
			want := ipam.PodHandle{Network: network, ContainerID: runtimeID}

			parsed, ok := ipam.ParsePodHandleID(handle, network)
			Expect(ok).To(BeTrue(), handle)
			Expect(parsed).To(Equal(want))

			parsed, ok = ipam.ParsePodHandleIDAnyNetwork(handle)
			Expect(ok).To(BeTrue(), handle)
			Expect(parsed).To(Equal(want))
		}
	})
})
