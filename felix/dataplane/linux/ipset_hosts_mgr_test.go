// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("IPSet all-hosts manager", func() {
	var (
		manager *hostsIPSetManager
		ipSets  *dpsets.MockIPSets
	)

	const (
		externalCIDR = "10.10.10.0/24"
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		manager = newHostsIPSetManager(
			ipSets,
			4,
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{externalCIDR},
			},
		)
	})

	allHostsSet := func() set.Set[string] {
		logrus.Info(ipSets.Members)
		Expect(ipSets.Members).To(HaveLen(1))
		return ipSets.Members["all-hosts-net"]
	}

	It("should handle IPSet updates correctly", func() {
		By("checking the the IP set is not created until first call to CompleteDeferredWork()")
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		err := manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeTrue())

		By("adding host1")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.1",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("adding host2")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host2",
			Ipv4Addr: "10.0.0.2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("testing tolerance for duplicate ip")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host3",
			Ipv4Addr: "10.0.0.2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("removing the duplicate ip should keep the ip")
		manager.OnUpdate(&proto.HostMetadataV4V6Remove{
			Hostname: "host3",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("removing the initial copy of ip")
		manager.OnUpdate(&proto.HostMetadataV4V6Remove{
			Hostname: "host2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("adding/removing a duplicate IP in one batch")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host2",
			Ipv4Addr: "10.0.0.1",
		})
		manager.OnUpdate(&proto.HostMetadataV4V6Remove{
			Hostname: "host2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("changing ip of host1")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))

		By("sending a no-op batch")
		ipSets.AddOrReplaceCalled = false
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))
	})
})

var _ = Describe("IPSet all-hosts manager - IPv6", func() {
	var (
		manager *hostsIPSetManager
		ipSets  *dpsets.MockIPSets
	)

	const (
		externalCIDR = "ff::/124"
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		manager = newHostsIPSetManager(
			ipSets,
			6,
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{externalCIDR},
			},
		)
	})

	allHostsSet := func() set.Set[string] {
		logrus.Info(ipSets.Members)
		Expect(ipSets.Members).To(HaveLen(1))
		return ipSets.Members["all-hosts-net"]
	}

	It("should handle IPSet updates correctly", func() {
		By("checking the the IP set is not created until first call to CompleteDeferredWork()")
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		err := manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeTrue())

		By("adding host1")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host1",
			Ipv6Addr: "dead:beef::1",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		// With IPv6 version, we should ignore external nodes CIDR, since the list is only used for IPIP encapsulation,
		// which is not supported with IPv6.
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::1")))

		By("adding host2")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host2",
			Ipv6Addr: "dead:beef::2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::1", "dead:beef::2")))

		By("testing tolerance for duplicate ip")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host3",
			Ipv6Addr: "dead:beef::2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::1", "dead:beef::2")))

		By("removing the duplicate ip should keep the ip")
		manager.OnUpdate(&proto.HostMetadataV4V6Remove{
			Hostname: "host3",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::1", "dead:beef::2")))

		By("removing the initial copy of ip")
		manager.OnUpdate(&proto.HostMetadataV4V6Remove{
			Hostname: "host2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::1")))

		By("adding/removing a duplicate IP in one batch")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host2",
			Ipv6Addr: "dead:beef::1",
		})
		manager.OnUpdate(&proto.HostMetadataV4V6Remove{
			Hostname: "host2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::1")))

		By("changing ip of host1")
		manager.OnUpdate(&proto.HostMetadataV4V6Update{
			Hostname: "host1",
			Ipv6Addr: "dead:beef::2",
		})
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::2")))

		By("sending a no-op batch")
		ipSets.AddOrReplaceCalled = false
		err = manager.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		Expect(allHostsSet()).To(Equal(set.From("dead:beef::2")))
	})
})
