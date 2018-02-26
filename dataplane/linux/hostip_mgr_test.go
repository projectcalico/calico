// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/set"
)

var _ = Describe("Host ip manager", func() {
	var (
		hostIPMgr *hostIPManager
		ipSets    *mockIPSets
	)

	BeforeEach(func() {
		ipSets = newMockIPSets()
		hostIPMgr = newHostIPManager([]string{"cali"}, "this-host", ipSets, 1024)
	})

	Describe("after sending a replace", func() {
		BeforeEach(func() {
			hostIPMgr.OnUpdate(&ifaceAddrsUpdate{
				Name:  "eth0",
				Addrs: set.From("10.0.0.1", "10.0.0.2"),
			})
			hostIPMgr.CompleteDeferredWork()
		})
		It("should create the IP set", func() {
			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
		})
		It("should add the right members", func() {
			Expect(ipSets.Members).To(HaveLen(1))
			expIPs := set.From("10.0.0.1", "10.0.0.2")
			Expect(ipSets.Members["this-host"]).To(Equal(expIPs))
		})

		Describe("after sending a delete", func() {
			BeforeEach(func() {
				hostIPMgr.OnUpdate(&ifaceAddrsUpdate{
					Name: "eth0",
				})
				hostIPMgr.CompleteDeferredWork()
			})
			It("should remove the IP set", func() {
				Expect(ipSets.Members["this-host"]).To(Equal(set.New()))
			})
		})

		Describe("after sending a workload interface update", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				hostIPMgr.OnUpdate(&ifaceAddrsUpdate{
					Name:  "cali1234",
					Addrs: set.From("10.0.0.8", "10.0.0.9"),
				})
				hostIPMgr.CompleteDeferredWork()
			})
			It("should not create the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
			})
			It("should have old members", func() {
				Expect(ipSets.Members).To(HaveLen(1))
				expIPs := set.From("10.0.0.1", "10.0.0.2")
				Expect(ipSets.Members["this-host"]).To(Equal(expIPs))
			})
		})

		Describe("after sending update for new interface", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				hostIPMgr.OnUpdate(&ifaceAddrsUpdate{
					Name:  "eth1",
					Addrs: set.From("10.0.0.8", "10.0.0.9"),
				})
				hostIPMgr.CompleteDeferredWork()
			})
			It("should not create the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			})
			It("should have old members", func() {
				Expect(ipSets.Members).To(HaveLen(1))
				expIPs := set.From("10.0.0.1", "10.0.0.2", "10.0.0.8", "10.0.0.9")
				Expect(ipSets.Members["this-host"]).To(Equal(expIPs))
			})
		})

		Describe("after sending another replace", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				hostIPMgr.OnUpdate(&ifaceAddrsUpdate{
					Name:  "eth0",
					Addrs: set.From("10.0.0.2", "10.0.0.3"),
				})
				hostIPMgr.CompleteDeferredWork()
			})
			It("should replace the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			})
			It("should add the right members", func() {
				Expect(ipSets.Members).To(HaveLen(1))
				expIPs := set.From("10.0.0.2", "10.0.0.3")
				Expect(ipSets.Members["this-host"]).To(Equal(expIPs))
			})
		})
	})
})
