// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package azure

import (
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Azure Endpoint/Network tests", func() {
	BeforeEach(func() {
		// Before each test, make sure the networksDir is set to
		// a local cache, so we don't need write permission to /var/run/calico.
		networksDir = "./"
	})

	AfterEach(func() {
		// Delete the test networks directory created by the test.
		os.RemoveAll("./network")
	})

	It("should store and load networks and endpoints", func() {
		an := AzureNetwork{
			Name:    "network",
			Subnets: []string{"192.168.0.0/24"},
		}

		By("Writing a network to disk")
		err := an.Write()
		Expect(err).NotTo(HaveOccurred())

		ae := AzureEndpoint{
			Network:     "network",
			ContainerID: "containerid",
			Interface:   "eth0",
			Addresses:   []string{"192.168.0.0/32"},
		}

		By("Writing an endpoint within the network to disk")
		err = ae.Write()
		Expect(err).NotTo(HaveOccurred())

		By("Reading the contents of the network back")
		an = AzureNetwork{Name: "network"}
		err = an.Load()
		Expect(err).NotTo(HaveOccurred())
		Expect(an.Subnets[0]).To(Equal("192.168.0.0/24"))

		By("Reading the contents of the endpoint back")
		ae = AzureEndpoint{
			Network:     "network",
			ContainerID: "containerid",
			Interface:   "eth0",
		}
		err = ae.Load()
		Expect(err).NotTo(HaveOccurred())
		Expect(ae.Addresses[0]).To(Equal("192.168.0.0/32"))
	})
})

var _ = Describe("Config mutation tests (ADD)", func() {
	It("should not mutate configuration for an ADD with no CIDRs", func() {
		args := &skel.CmdArgs{}
		network := AzureNetwork{Name: "network"}
		err := MutateConfigAdd(args, network)
		Expect(err).NotTo(HaveOccurred())
		Expect(*args).To(Equal(skel.CmdArgs{}))
	})

	It("should mutate configuration for an ADD with CIDRs", func() {
		args := &skel.CmdArgs{}
		args.StdinData = []byte(`{"ipam": {}}`)
		network := AzureNetwork{Name: "network", Subnets: []string{"192.168.0.0/12"}}
		err := MutateConfigAdd(args, network)
		Expect(err).NotTo(HaveOccurred())

		// Expect the subnet to be populated in the args.
		exp := []byte(`{"ipam":{"subnet":"192.168.0.0/12"}}`)
		Expect(args.StdinData).To(Equal(exp))
	})
})

var _ = Describe("Config mutation tests (DEL)", func() {
	It("should not mutate configuration for a DEL with no network or endpoint CIDRs", func() {
		args := &skel.CmdArgs{}
		network := AzureNetwork{Name: "network"}
		endpoint := AzureEndpoint{}
		err := MutateConfigDel(args, network, endpoint)
		Expect(err).NotTo(HaveOccurred())
		Expect(*args).To(Equal(skel.CmdArgs{}))
	})

	It("should not mutate configuration for a DEL with no network CIDRs", func() {
		args := &skel.CmdArgs{}
		network := AzureNetwork{Name: "network"}
		endpoint := AzureEndpoint{Addresses: []string{"192.168.5.5"}}
		err := MutateConfigDel(args, network, endpoint)
		Expect(err).NotTo(HaveOccurred())
		Expect(*args).To(Equal(skel.CmdArgs{}))
	})

	It("should mutate configuration for a DEL with CIDRs", func() {
		args := &skel.CmdArgs{}
		args.StdinData = []byte(`{"ipam": {}}`)
		network := AzureNetwork{Name: "network", Subnets: []string{"192.168.0.0/12"}}
		endpoint := AzureEndpoint{Addresses: []string{"192.168.5.5/32"}}
		err := MutateConfigDel(args, network, endpoint)
		Expect(err).NotTo(HaveOccurred())

		// Expect the subnet and IP address to be populated in the args.
		exp := []byte(`{"ipam":{"ipAddress":"192.168.5.5","subnet":"192.168.0.0/12"}}`)
		Expect(args.StdinData).To(Equal(exp))
	})
})
