// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package client_test

import (
	"errors"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("WorkloadEndpoint tests", testutils.DatastoreEtcdV2, func(apiConfig api.CalicoAPIConfig) {
	cidr1 := cnet.MustParseNetwork("10.0.0.0/32")
	cidr2 := cnet.MustParseNetwork("20.0.0.0/32")
	cidr3 := cnet.MustParseNetwork("192.168.0.0/32")
	cidr4 := cnet.MustParseNetwork("172.56.0.0/32")
	mac1, _ := net.ParseMAC("01:23:45:67:89:ab")
	mac2, _ := net.ParseMAC("CA:FE:00:01:02:03")
	ipv41 := cnet.MustParseIP("10.0.0.0")
	ipv61 := cnet.MustParseIP("fe80::33")

	DescribeTable("WorkloadEndpoint e2e tests",
		func(meta1, meta2 api.WorkloadEndpointMetadata, spec1, spec2 api.WorkloadEndpointSpec) {
			c := testutils.CreateCleanClient(apiConfig)

			// Updating non-existent workloadEndpoint1 should return an error
			By("Updating the workloadEndpoint before it is created")
			_, err := c.WorkloadEndpoints().Update(&api.WorkloadEndpoint{Metadata: meta1, Spec: spec1})
			Expect(err.Error()).To(Equal(errors.New("resource does not exist: WorkloadEndpoint(node=node1, orchestrator=kubernetes, workload=workload1, name=ep1)").Error()))

			// Create a new workloadEndpoint1 with meta1 and spec1.  This should not error.
			By("Creating a new workloadEndpoint1")
			outWorkloadEndpoint, err := c.WorkloadEndpoints().Create(&api.WorkloadEndpoint{Metadata: meta1, Spec: spec1})
			Expect(err).NotTo(HaveOccurred())
			validateReturnedWorkloadEndpoint(outWorkloadEndpoint, meta1, spec1)

			// Failing to create the same resource.
			By("Creating a the same workloadEndpoint1 and checking for failure")
			_, err = c.WorkloadEndpoints().Create(&api.WorkloadEndpoint{Metadata: meta1, Spec: spec1})
			Expect(err.Error()).To(Equal(errors.New("resource already exists: WorkloadEndpoint(node=node1, orchestrator=kubernetes, workload=workload1, name=ep1)").Error()))

			// Apply a new workloadEndpoint2 with meta2 and spec2.  This should not error.
			By("Applying a new workloadEndpoint2")
			outWorkloadEndpoint, err = c.WorkloadEndpoints().Apply(&api.WorkloadEndpoint{Metadata: meta2, Spec: spec2})
			Expect(err).NotTo(HaveOccurred())
			validateReturnedWorkloadEndpoint(outWorkloadEndpoint, meta2, spec2)

			// Get workloadEndpoint1.  This should not error, spec should match spec1.
			By("Getting workloadEndpoint1 and comparing with spec1")
			outWorkloadEndpoint, err = c.WorkloadEndpoints().Get(meta1)
			Expect(err).NotTo(HaveOccurred())
			validateReturnedWorkloadEndpoint(outWorkloadEndpoint, meta1, spec1)

			// Store the returned workloadEndpoint - we will use this to attempt a working CAS
			// operation.
			// Revision should be set (currently revision is only supported on Get and Delete operations of
			// the workload endpoint).
			storedWorkloadEndpoint1 := outWorkloadEndpoint
			Expect(storedWorkloadEndpoint1.Metadata.Revision).NotTo(BeNil())

			// Get workloadEndpoint2  This should not error, spec should match spec1.
			By("Getting workloadEndpoint2 and comparing with spec2")
			outWorkloadEndpoint, err = c.WorkloadEndpoints().Get(meta2)
			validateReturnedWorkloadEndpoint(outWorkloadEndpoint, meta2, spec2)

			// Update workloadEndpoint1 with spec2.
			By("Updating workloadEndpoint1 with spec2 using CAS")
			storedWorkloadEndpoint1.Spec = spec2
			outWorkloadEndpoint, err = c.WorkloadEndpoints().Update(storedWorkloadEndpoint1)
			Expect(err).NotTo(HaveOccurred())
			validateReturnedWorkloadEndpoint(outWorkloadEndpoint, meta1, spec2)

			// Delete workloadEndpoint1 with the same revision as before (should fail CAS).
			By("Deleting workloadEndpoint1 with previous revision (should fail)")
			err = c.WorkloadEndpoints().Delete(storedWorkloadEndpoint1.Metadata)
			Expect(err).To(HaveOccurred())

			// Apply workloadEndpoint2 with spec1.
			By("Applying workloadEndpoint2 with spec1")
			outWorkloadEndpoint, err = c.WorkloadEndpoints().Update(&api.WorkloadEndpoint{Metadata: meta2, Spec: spec1})
			Expect(err).NotTo(HaveOccurred())
			validateReturnedWorkloadEndpoint(outWorkloadEndpoint, meta2, spec1)

			// Get workloadEndpoint with meta1.
			By("Getting workloadEndpoint1 and comparing with spec2")
			outWorkloadEndpoint, err = c.WorkloadEndpoints().Get(meta1)
			validateReturnedWorkloadEndpoint(outWorkloadEndpoint, meta1, spec2)

			// Get a list of workloadEndpoints.  This should not error.  Compare this
			// against the expected results - there are only two entries
			// so just use brute force comparison.
			By("Listing all the workloadEndpoints and comparing with expected")
			workloadEndpointList, err := c.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(workloadEndpointList.Items)).To(Equal(2))
			validateReturnedWorkloadEndpoint(&workloadEndpointList.Items[0], meta1, spec2)
			validateReturnedWorkloadEndpoint(&workloadEndpointList.Items[1], meta2, spec1)

			// Get a workloadEndpoint list with meta2.
			By("Listing a specific workloadEndpoint and comparing with expected")
			workloadEndpointList, err = c.WorkloadEndpoints().List(meta2)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(workloadEndpointList.Items)).To(Equal(1))
			validateReturnedWorkloadEndpoint(&workloadEndpointList.Items[0], meta2, spec1)

			// Get a workloadEndpoint with meta2 and compare against the list results.  This
			// checks the full output of List is the same as Get.
			outWorkloadEndpoint, err = c.WorkloadEndpoints().Get(meta2)
			Expect(err).NotTo(HaveOccurred())
			Expect(workloadEndpointList.Items[0]).To(Equal(*outWorkloadEndpoint))

			// Deleting workloadEndpoint1 should not error.
			By("Deleting workloadEndpoint1")
			err = c.WorkloadEndpoints().Delete(meta1)
			Expect(err).NotTo(HaveOccurred())

			// Get a workloadEndpoint with meta1.
			By("Getting workloadEndpoint1 and checking for error")
			_, err = c.WorkloadEndpoints().Get(meta1)
			Expect(err.Error()).To(Equal(errors.New("resource does not exist: WorkloadEndpoint(node=node1, orchestrator=kubernetes, workload=workload1, name=ep1)").Error()))

			// Delete workloadEndpoint2 should not error.
			By("Deleting workloadEndpoint2")
			err = c.WorkloadEndpoints().Delete(meta2)
			Expect(err).NotTo(HaveOccurred())

			// Both resources are deleted in the calls above, so listing the
			// resources should return no results.
			By("Listing resources and checking for empty list")
			workloadEndpointList, err = c.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(workloadEndpointList.Items)).To(Equal(0))
		},

		// Test 1: Pass two fully populated WorkloadEndpointSpecs and expect the series of operations to succeed.
		Entry("Two fully populated WorkloadEndpointSpecs",
			api.WorkloadEndpointMetadata{
				Name:             "ep1",
				Workload:         "workload1",
				ActiveInstanceID: "container-id-badbeef",
				Orchestrator:     "kubernetes",
				Node:             "node1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "no",
				}},
			api.WorkloadEndpointMetadata{
				Name:             "ep1/with_foo",
				Workload:         "workload2",
				ActiveInstanceID: "container-id-badc0ffee",
				Orchestrator:     "mesos",
				Node:             "node2",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "yes",
				}},
			api.WorkloadEndpointSpec{
				IPNetworks: []cnet.IPNet{cidr1, cidr2},
				IPNATs: []api.IPNAT{
					{
						InternalIP: cnet.MustParseIP("10.0.0.0"),
						ExternalIP: cnet.MustParseIP("20.0.0.0"),
					},
				},

				IPv4Gateway:   &cnet.IP{net.ParseIP("10.0.0.1")},
				IPv6Gateway:   &cnet.IP{net.ParseIP("fe80::33")},
				Profiles:      []string{"profile1", "profile2"},
				InterfaceName: "eth0",
				MAC:           &cnet.MAC{mac1},
			},
			api.WorkloadEndpointSpec{
				IPNetworks: []cnet.IPNet{cidr3, cidr4},
				IPNATs: []api.IPNAT{
					{
						InternalIP: cnet.MustParseIP("192.168.0.0"),
						ExternalIP: cnet.MustParseIP("192.168.1.1"),
					},
				},

				IPv4Gateway:   &cnet.IP{net.ParseIP("192.168.0.1")},
				IPv6Gateway:   &cnet.IP{net.ParseIP("fe80::33")},
				Profiles:      []string{"profile3", "profile4"},
				InterfaceName: "eth1",
				MAC:           &cnet.MAC{mac2},
			}),

		// Test 2: Pass one partially populated WorkloadEndpointSpec and another fully populated WorkloadEndpointSpec and expect the series of operations to succeed.
		Entry("One partially populated WorkloadEndpointSpec and another fully populated WorkloadEndpointSpec",
			api.WorkloadEndpointMetadata{
				Name:         "ep1",
				Workload:     "workload1",
				Orchestrator: "kubernetes",
				Node:         "node1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "no",
				}},
			api.WorkloadEndpointMetadata{
				Name:         "ep1",
				Workload:     "workload1/with.bar",
				Orchestrator: "kubernetes",
				Node:         "node1",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "yes",
				}},
			api.WorkloadEndpointSpec{
				IPNetworks: []cnet.IPNet{cidr1, cidr2},
				IPNATs: []api.IPNAT{
					{
						InternalIP: cnet.MustParseIP("10.0.0.0"),
						ExternalIP: cnet.MustParseIP("192.168.0.0"),
					},
				},
				InterfaceName: "eth1",
				MAC:           &cnet.MAC{mac2},
			},
			api.WorkloadEndpointSpec{
				IPNetworks: []cnet.IPNet{cidr3, cidr4},
				IPNATs: []api.IPNAT{
					{
						InternalIP: cnet.MustParseIP("192.168.0.0"),
						ExternalIP: cnet.MustParseIP("192.168.1.1"),
					},
				},

				IPv4Gateway:   &cnet.IP{net.ParseIP("192.168.0.1")},
				IPv6Gateway:   &cnet.IP{net.ParseIP("fe80::33")},
				Profiles:      []string{"profile3", "profile4"},
				InterfaceName: "eth1",
				MAC:           &cnet.MAC{mac2},
			}),

		// Test 3: Pass one fully populated WorkloadEndpointSpec and another empty WorkloadEndpointSpec and expect the series of operations to succeed.
		Entry("One fully populated WorkloadEndpointSpec and a (nearly) empty WorkloadEndpointSpec",
			api.WorkloadEndpointMetadata{
				Name:         "ep1",
				Workload:     "workload1",
				Orchestrator: "kubernetes",
				Node:         "node1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "no",
				}},
			api.WorkloadEndpointMetadata{
				Name:         "ep1",
				Workload:     "workload1",
				Orchestrator: "kubernetes/v2.2",
				Node:         "node1",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "yes",
				}},
			api.WorkloadEndpointSpec{
				IPNetworks: []cnet.IPNet{cidr1, cidr2},
				IPNATs: []api.IPNAT{
					{
						InternalIP: cnet.MustParseIP("10.0.0.0"),
						ExternalIP: cnet.MustParseIP("20.0.0.0"),
					},
				},

				IPv4Gateway:   &ipv41,
				IPv6Gateway:   &ipv61,
				Profiles:      []string{"profile1", "profile2"},
				InterfaceName: "eth0",
				MAC:           &cnet.MAC{mac1},
			},
			api.WorkloadEndpointSpec{
				InterfaceName: "eth1",
			}),
	)
})

// Validate the returned workloadEndpoint contains the expected data.
func validateReturnedWorkloadEndpoint(res *api.WorkloadEndpoint, expMeta api.WorkloadEndpointMetadata, expSpec api.WorkloadEndpointSpec) {
	//  Unset the Revision and then compare the Meta and Spec.
	rev := res.Metadata.Revision
	res.Metadata.Revision = nil
	Expect(res.Metadata).To(Equal(expMeta))
	Expect(res.Spec).To(Equal(expSpec))

	// Set it back so we can use the workloadEndpoint as original.
	res.Metadata.Revision = rev
}
