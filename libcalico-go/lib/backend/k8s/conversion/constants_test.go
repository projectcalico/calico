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

package conversion

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("network-status annotation", func() {
	DescribeTable("AnnotationNetworkStatusForIface",
		func(iface, expected string) {
			Expect(AnnotationNetworkStatusForIface(iface)).To(Equal(expected))
		},
		Entry("empty", "", "cni.projectcalico.org/network-status"),
		Entry("eth0", "eth0", "cni.projectcalico.org/network-status"),
		Entry("net1", "net1", "cni.projectcalico.org/net1.network-status"),
	)

	It("should skip an empty status", func() {
		Expect(MarshalInterfaceStatus(NetworkStatus{})).To(BeEmpty())
	})

	It("should round-trip the netns", func() {
		val, err := MarshalInterfaceStatus(NetworkStatus{Netns: "/run/netns/cni-1234"})
		Expect(err).NotTo(HaveOccurred())
		Expect(val).To(Equal(`{"netns":"/run/netns/cni-1234"}`))

		ann := map[string]string{AnnotationNetworkStatusForIface("net1"): val}
		Expect(InterfaceStatusFromAnnotation(ann, "net1")).To(Equal(NetworkStatus{Netns: "/run/netns/cni-1234"}))
		Expect(InterfaceStatusFromAnnotation(ann, "eth0")).To(Equal(NetworkStatus{}))
	})

	It("should ignore unknown fields", func() {
		ann := map[string]string{AnnotationNetworkStatus: `{"unknown":"value","netns":"/run/netns/cni-1234"}`}
		Expect(InterfaceStatusFromAnnotation(ann, "eth0").Netns).To(Equal("/run/netns/cni-1234"))
	})
})
