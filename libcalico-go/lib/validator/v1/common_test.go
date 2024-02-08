// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package v1_test

import (
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/scope"
)

var _ = Describe("Test ValidateMetadataIDsAssigned function", func() {
	Context("with BGP Peer Metadata", func() {
		var bgppeer *api.BGPPeer
		testIP := net.ParseIP("192.168.22.33")
		BeforeEach(func() {
			bgppeer = api.NewBGPPeer()
			bgppeer.Metadata.Scope = scope.Global
		})
		It("should fail if missing a Peer IP", func() {
			err := validator.ValidateMetadataIDsAssigned(bgppeer.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should fail if it is Node scope without specifying a node", func() {
			bgppeer.Metadata.PeerIP = *testIP
			bgppeer.Metadata.Scope = scope.Node
			err := validator.ValidateMetadataIDsAssigned(bgppeer.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should fail if the scope is Undefined", func() {
			bgppeer.Metadata.PeerIP = *testIP
			bgppeer.Metadata.Scope = scope.Undefined
			err := validator.ValidateMetadataIDsAssigned(bgppeer.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should pass if the Global scope is specified, even if a node is not specified", func() {
			bgppeer.Metadata.PeerIP = *testIP
			err := validator.ValidateMetadataIDsAssigned(bgppeer.Metadata)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("with Host Endpoint Metadata", func() {
		var hep *api.HostEndpoint
		BeforeEach(func() {
			hep = api.NewHostEndpoint()
			hep.Metadata.Name = "testHostEndpoint"
			hep.Metadata.Node = "testNode"
		})
		It("should fail if missing a Name", func() {
			hep.Metadata.Name = ""
			err := validator.ValidateMetadataIDsAssigned(hep.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should fail if missing a Node name", func() {
			hep.Metadata.Node = ""
			err := validator.ValidateMetadataIDsAssigned(hep.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should pass with both a Name and Node", func() {
			err := validator.ValidateMetadataIDsAssigned(hep.Metadata)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("with IP Pool Metadata", func() {
		var ipp *api.IPPool
		_, testCIDR, _ := net.ParseCIDR("192.168.22.0/24")
		BeforeEach(func() {
			ipp = api.NewIPPool()
		})
		It("should fail if missing CIDR", func() {
			err := validator.ValidateMetadataIDsAssigned(ipp.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should pass with a CIDR", func() {
			ipp.Metadata.CIDR = *testCIDR
			err := validator.ValidateMetadataIDsAssigned(ipp.Metadata)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("with Node Metadata", func() {
		var node *api.Node
		BeforeEach(func() {
			node = api.NewNode()
			node.Metadata.Name = "testNode"
		})
		It("should fail if missing Name", func() {
			node.Metadata.Name = ""
			err := validator.ValidateMetadataIDsAssigned(node.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should pass with a Name specified", func() {
			err := validator.ValidateMetadataIDsAssigned(node.Metadata)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("with Policy Metadata", func() {
		var policy *api.Policy
		BeforeEach(func() {
			policy = api.NewPolicy()
			policy.Metadata.Name = "testPolicy"
		})
		It("should fail if missing Name", func() {
			policy.Metadata.Name = ""
			err := validator.ValidateMetadataIDsAssigned(policy.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should pass with a Name specified", func() {
			err := validator.ValidateMetadataIDsAssigned(policy.Metadata)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("with Profile Metadata", func() {
		var profile *api.Profile
		BeforeEach(func() {
			profile = api.NewProfile()
			profile.Metadata.Name = "testProfile"
		})
		It("should fail if missing Name", func() {
			profile.Metadata.Name = ""
			err := validator.ValidateMetadataIDsAssigned(profile.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should pass with a Name specified", func() {
			err := validator.ValidateMetadataIDsAssigned(profile.Metadata)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("with Workload Endpoint Metadata", func() {
		var wep *api.WorkloadEndpoint
		BeforeEach(func() {
			wep = api.NewWorkloadEndpoint()
			wep.Metadata.Node = "testNode"
			wep.Metadata.Orchestrator = "testOrchestrator"
			wep.Metadata.Workload = "testWorkload"
			wep.Metadata.Name = "testWorkloadEndpoint"
		})
		It("should fail if missing Node", func() {
			wep.Metadata.Node = ""
			err := validator.ValidateMetadataIDsAssigned(wep.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should fail if missing Orchestrator", func() {
			wep.Metadata.Orchestrator = ""
			err := validator.ValidateMetadataIDsAssigned(wep.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should fail if missing Workload", func() {
			wep.Metadata.Workload = ""
			err := validator.ValidateMetadataIDsAssigned(wep.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should fail if missing Name", func() {
			wep.Metadata.Name = ""
			err := validator.ValidateMetadataIDsAssigned(wep.Metadata)
			Expect(err).To(HaveOccurred())
		})
		It("should pass with a Node, Orchestrator, Workload, and Name specified", func() {
			err := validator.ValidateMetadataIDsAssigned(wep.Metadata)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
