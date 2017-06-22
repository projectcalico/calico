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

// Test cases (HostEndpoint object e2e):
// Test 1: Pass two fully populated HostEndpointSpecs and expect the series of operations to succeed.
// Test 2: Pass one partially populated HostEndpointSpec and another fully populated HostEndpointSpec and expect the series of operations to succeed.
// Test 3: Pass one fully populated HostEndpointSpec and another empty HostEndpointSpec and expect the series of operations to succeed.
// Test 4: Pass two fully populated HostEndpointSpecs with two HostEndpointMetadata (one IPv4 and another IPv6) and expect the series of operations to succeed.

// Series of operations each test goes through:
// Update meta1 - check for failure (because it doesn't exist).
// Create meta1 with spec1.
// Apply meta2 with spec2.
// Get meta1 and meta2, compare spec1 and spec2.
// Update meta1 with spec2.
// Get meta1 compare spec2.
// List (empty Meta) ... Get meta1 and meta2.
// List (using Meta1) ... Get meta1.
// Delete meta1.
// Get meta1 ... fail.
// Delete meta2.
// List (empty Meta) ... Get no entries (should not error).

package client_test

import (
	"errors"
	"log"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("HostEndpoint tests", testutils.DatastoreEtcdV2, func(config api.CalicoAPIConfig) {

	DescribeTable("HostEndpoint e2e tests",
		func(meta1, meta2 api.HostEndpointMetadata, spec1, spec2 api.HostEndpointSpec) {
			// Create a new client.
			c := testutils.CreateCleanClient(config)
			By("Updating the HostEndpoint before it is created")
			_, outError := c.HostEndpoints().Update(&api.HostEndpoint{Metadata: meta1, Spec: spec1})

			// Should return an error.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: HostEndpoint(node=node1, name=ep1)").Error()))

			By("Create, Apply, Get and compare")

			// Create a HostEndpoint with meta1 and spec1.
			_, outError = c.HostEndpoints().Create(&api.HostEndpoint{Metadata: meta1, Spec: spec1})
			Expect(outError).NotTo(HaveOccurred())

			// Apply a HostEndpoint with meta2 and spec2.
			_, outError = c.HostEndpoints().Apply(&api.HostEndpoint{Metadata: meta2, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get HostEndpoint with meta1.
			outHostEndpoint1, outError1 := c.HostEndpoints().Get(meta1)
			log.Println("Out HostEndpoint object: ", outHostEndpoint1)

			// Get HostEndpoint with meta2.
			outHostEndpoint2, outError2 := c.HostEndpoints().Get(meta2)
			log.Println("Out HostEndpoint object: ", outHostEndpoint2)

			// Should match spec1 & outHostEndpoint1 and outHostEndpoint2 & spec2 and errors to be nil.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outError2).NotTo(HaveOccurred())
			Expect(outHostEndpoint1.Spec).To(Equal(spec1))
			Expect(outHostEndpoint2.Spec).To(Equal(spec2))

			By("Update, Get and compare")

			// Update meta1 HostEndpoint with spec2.
			_, outError = c.HostEndpoints().Update(&api.HostEndpoint{Metadata: meta1, Spec: spec2})
			Expect(outError).NotTo(HaveOccurred())

			// Get HostEndpoint with meta1.
			outHostEndpoint1, outError1 = c.HostEndpoints().Get(meta1)

			// Assert the Spec for HostEndpoint with meta1 matches spec2 and no error.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(outHostEndpoint1.Spec).To(Equal(spec2))

			By("List all the HostEndpoints and compare")

			// Get a list of HostEndpoints.
			hostEndpointList, outError := c.HostEndpoints().List(api.HostEndpointMetadata{})
			Expect(outError).NotTo(HaveOccurred())

			log.Println("Get HostEndpoint list returns: ", hostEndpointList.Items)
			metas := []api.HostEndpointMetadata{meta1, meta2}
			expectedHostEndpoints := []api.HostEndpoint{}
			// Go through meta list and append them to expectedHostEndpoints.
			for _, v := range metas {
				p, outError := c.HostEndpoints().Get(v)
				Expect(outError).NotTo(HaveOccurred())
				expectedHostEndpoints = append(expectedHostEndpoints, *p)
			}

			// Assert the returned hostEndpointList is has the meta1 and meta2 HostEndpoints.
			Expect(hostEndpointList.Items).To(Equal(expectedHostEndpoints))

			By("List a specific HostEndpoint and compare")

			// Get a HostEndpoint list with meta1.
			hostEndpointList, outError = c.HostEndpoints().List(meta1)
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get HostEndpoint list returns: ", hostEndpointList.Items)

			// Get a HostEndpoint with meta1.
			outHostEndpoint1, outError1 = c.HostEndpoints().Get(meta1)

			// Assert they are equal and no errors.
			Expect(outError1).NotTo(HaveOccurred())
			Expect(hostEndpointList.Items[0].Spec).To(Equal(outHostEndpoint1.Spec))

			By("Delete, Get and assert error")

			// Delete a HostEndpoint with meta1.
			outError1 = c.HostEndpoints().Delete(meta1)
			Expect(outError1).NotTo(HaveOccurred())

			// Get a HostEndpoint with meta1.
			_, outError = c.HostEndpoints().Get(meta1)

			// Expect an error since the HostEndpoint was deleted.
			Expect(outError.Error()).To(Equal(errors.New("resource does not exist: HostEndpoint(node=node1, name=ep1)").Error()))

			// Delete the second HostEndpoint with meta2.
			outError1 = c.HostEndpoints().Delete(meta2)
			Expect(outError1).NotTo(HaveOccurred())

			By("Delete all the HostEndpoints, Get HostEndpoint list and expect empty HostEndpoint list")

			// Both HostEndpoints are deleted in the calls above.
			// Get the list of all the HostEndpoints.
			hostEndpointList, outError = c.HostEndpoints().List(api.HostEndpointMetadata{})
			Expect(outError).NotTo(HaveOccurred())
			log.Println("Get HostEndpoint list returns: ", hostEndpointList.Items)

			// Create an empty HostEndpoint list.
			// Note: you can't use make([]api.HostEndpoint, 0) because it creates an empty underlying struct,
			// whereas new([]api.HostEndpoint) just returns a pointer without creating an empty struct.
			emptyhostEndpointList := new([]api.HostEndpoint)

			// Expect returned hostEndpointList to contain empty hostEndpointList.
			Expect(hostEndpointList.Items).To(Equal(*emptyhostEndpointList))

		},

		// Test 1: Pass two fully populated HostEndpointSpecs and expect the series of operations to succeed.
		Entry("Two fully populated HostEndpointSpecs",
			api.HostEndpointMetadata{
				Name: "ep1",
				Node: "node1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "no",
				}},
			api.HostEndpointMetadata{
				Name: "ep1/with_foo",
				Node: "node1",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "yes",
				}},
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				ExpectedIPs:   []cnet.IP{cnet.MustParseIP("10.0.0.0"), cnet.MustParseIP("20.0.0.0")},
				Profiles:      []string{"profile1", "profile2"},
			},
			api.HostEndpointSpec{
				InterfaceName: "eth1",
				ExpectedIPs:   []cnet.IP{cnet.MustParseIP("192.168.0.0"), cnet.MustParseIP("192.168.1.1")},
				Profiles:      []string{"profile3", "profile4"},
			}),

		// Test 2: Pass one partially populated HostEndpointSpec and another fully populated HostEndpointSpec and expect the series of operations to succeed.
		Entry("One partially populated HostEndpointSpec and another fully populated HostEndpointSpec",
			api.HostEndpointMetadata{
				Name: "ep1",
				Node: "node1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "no",
				}},
			api.HostEndpointMetadata{
				Name: "ep1/with.foo",
				Node: "node1",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "yes",
				}},
			api.HostEndpointSpec{
				InterfaceName: "eth0",
			},
			api.HostEndpointSpec{
				InterfaceName: "eth1",
				ExpectedIPs:   []cnet.IP{cnet.MustParseIP("192.168.0.0"), cnet.MustParseIP("192.168.1.1")},
				Profiles:      []string{"profile3", "profile4"},
			}),

		// Test 3: Pass one fully populated HostEndpointSpec and another empty HostEndpointSpec and expect the series of operations to succeed.
		Entry("One fully populated HostEndpointSpec and another (almost) empty HostEndpointSpec",
			api.HostEndpointMetadata{
				Name: "ep1",
				Node: "node1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "no",
				}},
			api.HostEndpointMetadata{
				Name: "ep1/with.foo/and.bar",
				Node: "node1",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "yes",
				}},
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				ExpectedIPs:   []cnet.IP{cnet.MustParseIP("10.0.0.0"), cnet.MustParseIP("20.0.0.0")},
				Profiles:      []string{"profile1", "profile2"},
			},
			api.HostEndpointSpec{
				InterfaceName: "eth0",
			}),

		// Test 4: Pass two fully populated HostEndpointSpecs with two HostEndpointMetadata (one IPv4 and another IPv6) and expect the series of operations to succeed.
		Entry("Two fully populated HostEndpointSpecs with two HostEndpointMetadata (one IPv4 and another IPv6)",
			api.HostEndpointMetadata{
				Name: "ep1",
				Node: "node1",
				Labels: map[string]string{
					"app":  "app-abc",
					"prod": "no",
				}},
			api.HostEndpointMetadata{
				Name: "ep2",
				Node: "node2",
				Labels: map[string]string{
					"app":  "app-xyz",
					"prod": "yes",
				}},
			api.HostEndpointSpec{
				InterfaceName: "eth0",
				ExpectedIPs:   []cnet.IP{cnet.MustParseIP("10.0.0.0"), cnet.MustParseIP("192.168.1.1")},
				Profiles:      []string{"profile1", "profile2"},
			},
			api.HostEndpointSpec{
				InterfaceName: "eth1",
				ExpectedIPs:   []cnet.IP{cnet.MustParseIP("fe80::00"), cnet.MustParseIP("fe80::33")},
				Profiles:      []string{"profile3", "profile4"},
			}),
	)

})
