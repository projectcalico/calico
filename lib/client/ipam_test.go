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

// AutoAssign one IP which should be from the only ipPool created at the time, second one
// should be from the same /26 block since they're both from the same host, then delete
// the ipPool and create a new ipPool, and AutoAssign 1 more IP for the same host - expect the
// assigned IP to be from the new ipPool that was created, this is to make sure the assigned IP
// doesn't come from the old affinedBlock even after the ipPool was deleted.
// Step-1: AutoAssign 1 IP without specifying a pool - expect the assigned IP is from pool1.
// Step-2: AutoAssign 1 more IP without specifying a pool - expect the assigned IP is from the same /26 block as the previous IP.
// Step-3: Delete pool1 - expect it to execute without any error.
// Step-4: Create a new IP Pool.
// Step-5: AutoAssign 1 IP without specifying a pool - expect the assigned IP is from pool2.

// IPAM AutoAssign from different pools:
// Step-1: AutoAssign 1 IP from pool1 - expect that the IP is from pool1.
// Step-2: AutoAssign 1 IP from pool2 - expect that the IP is from pool2.
// Step-3: AutoAssign 1 IP from pool1 (second time) - expect that the
// IP is from from the same block as the first IP from pool1.
// Step-4: AutoAssign 1 IP from pool2 (second time) - expect that the
// IP is from from the same block as the first IP from pool2.

// Test cases (AutoAssign):
// Test 1: AutoAssign 1 IPv4, 1 IPv6 - expect one of each to be returned.
// Test 2: AutoAssign 256 IPv4, 256 IPv6 - expect 256 IPv4 + IPv6 addresses
// Test 3: AutoAssign 257 IPv4, 0 IPv6 - expect 256 IPv4 addresses, no IPv6, and an error.
// Test 4: AutoAssign 0 IPv4, 257 IPv6 - expect 256 IPv6 addresses, no IPv6, and an error.
// Test 5: (use pool of size /25 so only two blocks are contained):
// - Assign 1 address on host A (Expect 1 address)
// - Assign 1 address on host B (Expect 1 address, different block)
// - Assign 64 more addresses on host A (Expect 63 addresses from host A's block, 1 address from host B's block)

// Test cases (AssignIP):
// Test 1: Assign 1 IPv4 from a configured pool - expect no error returned.
// Test 2: Assign 1 IPv6 from a configured pool - expect no error returned.
// Test 3: Assign 1 IPv4 from a non-configured pool - expect an error returned.
// Test 4: Assign 1 IPv4 from a configured pool twice:
// - Expect no error returned while assigning the IP for the first time.
// - Expect an error returned while assigning the SAME IP again.

// Test cases (ReleaseIPs):
// Test 1: release an IP that's not configured in any pools - expect a slice with the same IP as unallocatedIPs and no error.
// Test 2: release an IP that's not allocated in the pool - expect a slice with one (unallocatedIPs) and no error.
// Test 3: Assign 1 IPv4 with AssignIP from a configured pool and then release it.
// - Assign should not return an error.
// - ReleaseIP should return empty slice of IPs (unallocatedIPs) and no error.
// Test 4: Assign 66 IPs (across 2 blocks) with AutoAssign from a configured pool then release them.
// - Assign should not return an error.
// - ReleaseIPs should return an empty slice of IPs (unallocatedIPs) and no error.
// Test 5: Assign 1 IPv4 address with AssignIP then try to release 2 IPs.
// - Assign should not return no error.
// - ReleaseIPs should return a slice with one (unallocatedIPs) and no error.

// Test cases (ClaimAffinity):
// Test 1: claim affinity for an unclaimed IPNet of size 64 - expect 1 claimed blocks, 0 failed and expect no error.
// Test 2: claim affinity for an unclaimed IPNet of size smaller than 64 - expect 0 claimed blocks, 0 failed and expect an error error.
// Test 3: claim affinity for a IPNet that has an IP already assigned to another host.
// - Assign an IP with AssignIP to "host-A" from a configured pool - expect 0 claimed blocks, 0 failed and expect no error.
// - Claim affinity for "Host-B" to the block that IP belongs to - expect 3 claimed blocks and 1 failed.
// Test 4: claim affinity to a block twice from different hosts.
// - Claim affinity to an unclaimed block for "Host-A" - expect 4 claimed blocks, 0 failed and expect no error.
// - Claim affinity to the same block again but for "host-B" this time - expect 0 claimed blocks, 4 failed and expect no error.

package client_test

import (
	"errors"
	"fmt"
	"log"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	. "github.com/onsi/ginkgo/extensions/table"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

type testArgsClaimAff struct {
	inNet, host                 string
	cleanEnv                    bool
	pool                        []string
	assignIP                    net.IP
	expClaimedIPs, expFailedIPs int
	expError                    error
}

var _ = testutils.E2eDatastoreDescribe("IPAM tests", testutils.DatastoreEtcdV2, func(config api.CalicoAPIConfig) {

	// We're assigning one IP which should be from the only ipPool created at the time, second one
	// should be from the same /26 block since they're both from the same host, then delete
	// the ipPool and create a new ipPool, and AutoAssign 1 more IP for the same host - expect the
	// assigned IP to be from the new ipPool that was created, this is to make sure the assigned IP
	// doesn't come from the old affinedBlock even after the ipPool was deleted.
	Describe("IPAM AutoAssign from the default pool then delete the pool and assign again", func() {
		c := testutils.CreateCleanClient(config)
		ic := setupIPAMClient(c, true)

		host := "host-A"
		pool1 := cnet.MustParseNetwork("10.0.0.0/24")
		var block cnet.IPNet

		testutils.CreateNewIPPool(*c, "10.0.0.0/24", false, false, true)

		// Step-1: AutoAssign 1 IP without specifying a pool - expect the assigned IP is from pool1.
		Context("AutoAssign 1 IP without specifying a pool", func() {
			args := client.AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: host,
			}

			v4, _, outErr := ic.AutoAssign(args)

			blocks := getAffineBlocks(host)

			for _, b := range blocks {
				if pool1.Contains(b.IPNet.IP) {
					block = b
				}
			}

			It("assigned IP should be from pool1", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(pool1.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})

		// Step-2: AutoAssign 1 more IP without specifying a pool - expect the assigned IP
		// is from the same /26 block as the previous IP.
		Context("AutoAssign 1 IP without specifying a pool", func() {
			args := client.AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: host,
			}

			v4, _, outErr := ic.AutoAssign(args)

			It("assigned IP should be from pool1", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(block.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})

		// Step-3: Delete pool1 - expect it to execute without any error.
		Context("Delete pool1", func() {
			outErr := c.IPPools().Delete(api.IPPoolMetadata{
				CIDR: pool1,
			})

			It("should delete the ipPool without any error", func() {
				Expect(outErr).NotTo(HaveOccurred())
			})
		})

		// Step-4: Create a new IP Pool.
		pool2 := cnet.MustParseNetwork("20.0.0.0/24")
		testutils.CreateNewIPPool(*c, "20.0.0.0/24", false, false, true)

		// Step-5: AutoAssign 1 IP without specifying a pool - expect the assigned IP is from pool2.
		Context("AutoAssign 1 IP without specifying a pool", func() {
			args := client.AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: host,
			}

			v4, _, outErr := ic.AutoAssign(args)

			It("assigned IP should be from pool2", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(pool2.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})
	})

	Describe("IPAM AutoAssign from any pool", func() {
		c := testutils.CreateCleanClient(config)
		ic := setupIPAMClient(c, true)

		testutils.CreateNewIPPool(*c, "10.0.0.0/24", false, false, true)
		testutils.CreateNewIPPool(*c, "20.0.0.0/24", false, false, true)

		// Assign an IP address, don't pass a pool, make sure we can get an
		// address.
		Context("AutoAssign 1 IP from any pool", func() {
			args := client.AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: "test-host",
			}
			// Call once in order to assign an IP address and create a block.
			v4, _, outErr := ic.AutoAssign(args)
			It("should have assigned an IP address with no error", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4) == 1).To(BeTrue())
			})

			// Call again to trigger an assignment from the newly created block.
			v4, _, outErr = ic.AutoAssign(args)
			It("should have assigned an IP address with no error", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4) == 1).To(BeTrue())
			})
		})
	})

	Describe("IPAM AutoAssign from different pools", func() {
		c := testutils.CreateCleanClient(config)
		ic := setupIPAMClient(c, true)

		host := "host-A"
		pool1 := cnet.MustParseNetwork("10.0.0.0/24")
		pool2 := cnet.MustParseNetwork("20.0.0.0/24")
		var block1, block2 cnet.IPNet

		testutils.CreateNewIPPool(*c, "10.0.0.0/24", false, false, true)
		testutils.CreateNewIPPool(*c, "20.0.0.0/24", false, false, true)

		// Step-1: AutoAssign 1 IP from pool1 - expect that the IP is from pool1.
		Context("AutoAssign 1 IP from pool1", func() {
			args := client.AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1},
			}

			v4, _, outErr := ic.AutoAssign(args)

			blocks := getAffineBlocks(host)

			for _, b := range blocks {
				if pool1.Contains(b.IPNet.IP) {
					block1 = b
				}
			}

			It("should be from pool1", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(pool1.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})

		// Step-2: AutoAssign 1 IP from pool2 - expect that the IP is from pool2.
		Context("AutoAssign 1 IP from pool2", func() {
			args := client.AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool2},
			}

			v4, _, outErr := ic.AutoAssign(args)

			blocks := getAffineBlocks(host)

			for _, b := range blocks {
				if pool2.Contains(b.IPNet.IP) {
					block2 = b
				}
			}

			It("should be from pool2", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(block2.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})

		// Step-3: AutoAssign 1 IP from pool1 (second time) - expect that the
		// IP is from from the same block as the first IP from pool1.
		Context("AutoAssign 1 IP from pool1 (second time)", func() {
			args := client.AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1},
			}

			v4, _, outErr := ic.AutoAssign(args)

			It("should be a from the same block as the first IP from pool1", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(block1.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})

		// Step-4: AutoAssign 1 IP from pool2 (second time) - expect that the
		// IP is from from the same block as the first IP from pool2.
		Context("AutoAssign 1 IP from pool2 (second time)", func() {
			args := client.AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool2},
			}

			v4, _, outErr := ic.AutoAssign(args)

			It("should be a from the same block as the first IP pool2", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(block2.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})
	})

	Describe("IPAM AutoAssign from different pools - multi", func() {
		c := testutils.CreateCleanClient(config)
		ic := setupIPAMClient(c, true)

		host := "host-A"
		pool1 := cnet.MustParseNetwork("10.0.0.0/24")
		pool2 := cnet.MustParseNetwork("20.0.0.0/24")
		pool3 := cnet.MustParseNetwork("30.0.0.0/24")
		pool4_v6 := cnet.MustParseNetwork("fe80::11/120")
		pool5_doesnot_exist := cnet.MustParseNetwork("40.0.0.0/24")

		testutils.CreateNewIPPool(*c, "10.0.0.0/24", false, false, true)
		testutils.CreateNewIPPool(*c, "20.0.0.0/24", false, false, true)
		testutils.CreateNewIPPool(*c, "30.0.0.0/24", false, false, false)
		testutils.CreateNewIPPool(*c, "fe80::11/120", false, false, true)

		// Step-1: Try to AutoAssign an IP from 2 pools  passed in IPv4Pools field with
		// the second IP Pool in the list being an IPv6 IP Pool.
		// Expect a non-nil error returned.
		Context("AutoAssign 1 IP from 2 pools with the first IPPool disabled", func() {
			args := client.AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool4_v6},
			}

			_, _, outErr := ic.AutoAssign(args)

			It("should have failed with a non-nil error", func() {
				Expect(outErr).To(HaveOccurred())
			})
		})

		// Step-2: Try to AutoAssign an IP from 2 pools  passed in IPv6Pools field with
		// the second IP Pool in the list being an IPv4 IP Pool.
		// Expect a non-nil error returned.
		Context("AutoAssign 1 IP from 2 pools with the first IPPool disabled", func() {
			args := client.AutoAssignArgs{
				Num4:      0,
				Num6:      1,
				Hostname:  host,
				IPv6Pools: []cnet.IPNet{pool4_v6, pool1},
			}

			_, _, outErr := ic.AutoAssign(args)

			It("should have failed with a non-nil error", func() {
				Expect(outErr).To(HaveOccurred())
			})
		})

		// Step-3: AutoAssign an IP from 2 pools with the first IP Pool in the list disabled.
		// Expect the returned IP is from the second IP Pool in the list.
		Context("AutoAssign 1 IP from 2 pools with the first IPPool disabled", func() {
			args := client.AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool3, pool2},
			}

			v4, _, outErr := ic.AutoAssign(args)
			log.Println("IPAM returned: %v", v4)

			It("should not have failed, and the returned IP is from the second IPPool in the list", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(1))
				Expect(pool2.Contains(v4[0].IP)).To(BeTrue())
			})
		})

		// Step-4: AutoAssign 300 IPs from 2 pools
		// Expect that the IPs are from both pools
		Context("AutoAssign 300 IPs from 2 pools", func() {
			args := client.AutoAssignArgs{
				Num4:      300,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool2},
			}

			v4, _, outErr := ic.AutoAssign(args)
			log.Println("v4: %d IPs", len(v4))

			It("should not have failed", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(300))
			})
		})

		// Step-5: AutoAssign 300 IPs from both pools again.
		// This time we should run out of IPs, so we should only get the remaining 209 IPs
		Context("AutoAssign 300 IPs from both pools - none left this time", func() {
			args := client.AutoAssignArgs{
				Num4:      300,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool2},
			}

			v4, _, outErr := ic.AutoAssign(args)
			log.Println("v4: %d IPs", len(v4))

			It("should have returned the remaining 209 IPs", func() {
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).NotTo(Equal(209))
			})
		})

		// Step-6: AutoAssign an IPv4 address. Request the IP from 2 IP Pools one of which doesn't exist.
		// This should return an error.
		Context("AutoAssign an IP from two pools - one valid one doesn't exist", func() {
			args := client.AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool5_doesnot_exist},
			}

			v4, _, err := ic.AutoAssign(args)
			log.Println("v4: %d IPs", len(v4))

			It("should return an error and no IPs", func() {
				Expect(err.Error()).Should(Equal("The given pool (40.0.0.0/24) does not exist"))
				Expect(len(v4)).To(Equal(0))
			})
		})
	})

	DescribeTable("AutoAssign: requested IPs vs returned IPs",
		func(host string, cleanEnv bool, pool []string, usePool string, inv4, inv6, expv4, expv6 int, expError error) {
			outv4, outv6, outError := testIPAMAutoAssign(inv4, inv6, host, cleanEnv, pool, usePool, config)
			Expect(outv4).To(Equal(expv4))
			Expect(outv6).To(Equal(expv6))
			if expError != nil {
				Expect(outError).To(HaveOccurred())
			}
		},

		// Test 1: AutoAssign 1 IPv4, 1 IPv6 - expect one of each to be returned.
		Entry("1 v4 1 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, "192.168.1.0/24", 1, 1, 1, 1, nil),

		// Test 2: AutoAssign 256 IPv4, 256 IPv6 - expect 256 IPv4 + IPv6 addresses.
		Entry("256 v4 256 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, "192.168.1.0/24", 256, 256, 256, 256, nil),

		// Test 3: AutoAssign 257 IPv4, 0 IPv6 - expect 256 IPv4 addresses, no IPv6, and no error.
		Entry("257 v4 0 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, "192.168.1.0/24", 257, 0, 256, 0, nil),

		// Test 4: AutoAssign 0 IPv4, 257 IPv6 - expect 256 IPv6 addresses, no IPv6, and no error.
		Entry("0 v4 257 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, "192.168.1.0/24", 0, 257, 0, 256, nil),

		// Test 5: (use pool of size /25 so only two blocks are contained):
		// - Assign 1 address on host A (Expect 1 address).
		Entry("1 v4 0 v6 host-A", "host-A", true, []string{"10.0.0.1/25", "fd80:24e2:f998:72d6::/121"}, "10.0.0.1/25", 1, 0, 1, 0, nil),

		// - Assign 1 address on host B (Expect 1 address, different block).
		Entry("1 v4 0 v6 host-B", "host-B", false, []string{"10.0.0.1/25", "fd80:24e2:f998:72d6::/121"}, "10.0.0.1/25", 1, 0, 1, 0, nil),

		// - Assign 64 more addresses on host A (Expect 63 addresses from host A's block, 1 address from host B's block).
		Entry("64 v4 0 v6 host-A", "host-A", false, []string{"10.0.0.1/25", "fd80:24e2:f998:72d6::/121"}, "10.0.0.1/25", 64, 0, 64, 0, nil),
	)

	DescribeTable("AssignIP: requested IP vs returned error",
		func(inIP net.IP, host string, cleanEnv bool, pool []string, expError error) {
			outError := testIPAMAssignIP(inIP, host, pool, cleanEnv, config)
			if expError != nil {
				Expect(outError).To(HaveOccurred())
				Expect(outError).To(Equal(expError))
			}
		},

		// Test 1: Assign 1 IPv4 from a configured pool - expect no error returned.
		Entry("Assign 1 IPv4 from a configured pool", net.ParseIP("192.168.1.0"), "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, nil),

		// Test 2: Assign 1 IPv6 from a configured pool - expect no error returned.
		Entry("Assign 1 IPv6 from a configured pool", net.ParseIP("fd80:24e2:f998:72d6::"), "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, nil),

		// Test 3: Assign 1 IPv4 from a non-configured pool - expect an error returned.
		Entry("Assign 1 IPv4 from a non-configured pool", net.ParseIP("1.1.1.1"), "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, errors.New("The provided IP address is not in a configured pool\n")),

		// Test 4: Assign 1 IPv4 from a configured pool twice:
		// - Expect no error returned while assigning the IP for the first time.
		Entry("Assign 1 IPv4 from a configured pool twice (first time)", net.ParseIP("192.168.1.0"), "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, nil),

		// - Expect an error returned while assigning the SAME IP again.
		Entry("Assign 1 IPv4 from a configured pool twice (second time)", net.ParseIP("192.168.1.0"), "testHost", false, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, errors.New("Address already assigned in block")),
	)

	DescribeTable("ReleaseIPs: requested IPs to be released vs actual unallocated IPs",
		func(inIP net.IP, cleanEnv bool, pool []string, assignIP net.IP, autoAssignNumIPv4 int, expUnallocatedIPs []cnet.IP, expError error) {
			unallocatedIPs, outError := testIPAMReleaseIPs(inIP, pool, cleanEnv, assignIP, autoAssignNumIPv4, config)

			// Expect returned slice of unallocatedIPs to be equal to expected expUnallocatedIPs.
			Expect(unallocatedIPs).To(Equal(expUnallocatedIPs))

			// Assert if an error was expected.
			if expError != nil {
				Expect(outError).To(HaveOccurred())
				Expect(outError).To(Equal(expError))
			}
		},

		// Test cases (ReleaseIPs):
		// Test 1: release an IP that's not configured in any pools - expect a slice with the same IP as unallocatedIPs and no error.
		Entry("Release an IP that's not configured in any pools", net.ParseIP("1.1.1.1"), true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, []cnet.IP{cnet.IP{net.ParseIP("1.1.1.1")}}, nil),

		// Test 2: release an IP that's not allocated in the pool - expect a slice with one (unallocatedIPs) and no error.
		Entry("Release an IP that's not allocated in the pool", net.ParseIP("192.168.1.0"), true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, []cnet.IP{cnet.IP{net.ParseIP("192.168.1.0")}}, nil),

		// Test 3: Assign 1 IPv4 with AssignIP from a configured pool and then release it.
		// - Assign should not return an error.
		// - ReleaseIP should return empty slice of IPs (unallocatedIPs) and no error.
		Entry("Assign 1 IPv4 with AssignIP from a configured pool and then release it", net.IP{}, true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.ParseIP("192.168.1.0"), 0, []cnet.IP{}, nil),

		// Test 4: Assign 66 IPs (across 2 blocks) with AutoAssign from a configured pool then release them.
		// - Assign should not return an error.
		// - ReleaseIPs should return an empty slice of IPs (unallocatedIPs) and no error.
		Entry("Assign 66 IPs (across 2 blocks) with AutoAssign from a configured pool then release them", net.IP{}, true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 66, []cnet.IP{}, nil),

		// Test 5: Assign 1 IPv4 address with AssignIP then try to release 2 IPs.
		// - Assign should not return no error.
		// - ReleaseIPs should return a slice with one (unallocatedIPs) and no error.
		Entry("Assign 1 IPv4 address with AssignIP then try to release 2 IPs (assign one and release it)", net.IP{}, true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.ParseIP("192.168.1.0"), 0, []cnet.IP{}, nil),
		Entry("Assign 1 IPv4 address with AssignIP then try to release 2 IPs (release a second one)", net.ParseIP("192.168.1.1"), false, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, []cnet.IP{cnet.IP{net.ParseIP("192.168.1.1")}}, nil),
	)

	DescribeTable("ClaimAffinity: claim IPNet vs actual number of blocks claimed",
		func(args testArgsClaimAff) {
			inIPNet := cnet.MustParseNetwork(args.inNet)
			c := testutils.CreateClient(config)

			// Wipe clean etcd, create a new client, and pools when cleanEnv flag is true.
			if args.cleanEnv {
				testutils.CleanDatastore(config)
				for _, v := range args.pool {
					testutils.CreateNewIPPool(*c, v, false, false, true)
				}
			}

			ic := setupIPAMClient(c, args.cleanEnv)

			assignIPutil(ic, args.assignIP, "Host-A")

			outClaimed, outFailed, outError := ic.ClaimAffinity(inIPNet, args.host)
			log.Println("Claimed IP blocks: ", outClaimed)
			log.Println("Failed to claim IP blocks: ", outFailed)

			// Expect returned slice of claimed IPNet to be equal to expected claimed.
			Expect(len(outClaimed)).To(Equal(args.expClaimedIPs))

			// Expect returned slice of failed IPNet to be equal to expected failed.
			Expect(len(outFailed)).To(Equal(args.expFailedIPs))

			// Assert if an error was expected.
			if args.expError != nil {
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal(args.expError.Error()))
			}
		},

		// Test cases (ClaimAffinity):
		// Test 1: claim affinity for an unclaimed IPNet of size 64 - expect 1 claimed blocks, 0 failed and expect no error.
		Entry("Claim affinity for an unclaimed IPNet of size 64", testArgsClaimAff{"192.168.1.0/26", "host-A", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 1, 0, nil}),

		// Test 2: claim affinity for an unclaimed IPNet of size smaller than 64 - expect 0 claimed blocks, 0 failed and expect an error error.
		Entry("Claim affinity for an unclaimed IPNet of size smaller than 64", testArgsClaimAff{"192.168.1.0/27", "host-A", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, 0, errors.New("The requested CIDR (192.168.1.0/27) is smaller than the minimum.")}),

		// Test 3: claim affinity for a IPNet that has an IP already assigned to another host.
		// - Assign an IP with AssignIP to "Host-A" from a configured pool
		// - Claim affinity for "Host-B" to the block that IP belongs to - expect 3 claimed blocks and 1 failed.
		Entry("Claim affinity for a IPNet that has an IP already assigned to another host (Claim affinity for Host-B)", testArgsClaimAff{"10.0.0.0/24", "host-B", true, []string{"10.0.0.0/24", "fd80:24e2:f998:72d6::/120"}, net.ParseIP("10.0.0.1"), 3, 1, nil}),

		// Test 4: claim affinity to a block twice from different hosts.
		// - Claim affinity to an unclaimed block for "Host-A" - expect 4 claimed blocks, 0 failed and expect no error.
		Entry("Claim affinity to an unclaimed block for Host-A", testArgsClaimAff{"10.0.0.0/24", "host-A", true, []string{"10.0.0.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 4, 0, nil}),

		// - Claim affinity to the same block again but for "host-B" this time - expect 0 claimed blocks, 4 failed and expect no error.
		Entry("Claim affinity to the same block again but for Host-B this time", testArgsClaimAff{"10.0.0.0/24", "host-B", false, []string{"10.0.0.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, 4, nil}),
	)
})

// testIPAMReleaseIPs takes an IP, slice of string with IP pools to setup, cleanEnv flag means  setup a new environment.
// assignIP is if you want to assign a single IP before releasing an IP, and AutoAssign is to assign IPs in bulk before releasing any.
func testIPAMReleaseIPs(inIP net.IP, poolSubnet []string, cleanEnv bool, assignIP net.IP, autoAssignNumIPv4 int, config api.CalicoAPIConfig) ([]cnet.IP, error) {

	inIPs := []cnet.IP{cnet.IP{inIP}}
	if cleanEnv {
		c := testutils.CreateCleanClient(config)
		for _, v := range poolSubnet {
			testutils.CreateNewIPPool(*c, v, false, false, true)
		}
	}
	c := testutils.CreateClient(config)
	ic := setupIPAMClient(c, cleanEnv)

	if len(assignIP) != 0 {
		err := ic.AssignIP(client.AssignIPArgs{
			IP: cnet.IP{assignIP},
		})
		if err != nil {
			Fail(fmt.Sprintf("Error assigning IP %s", assignIP))
		}

		// Re-initialize it to an empty slice to flush out any IP if passed in by mistake.
		inIPs = []cnet.IP{}

		inIPs = append(inIPs, cnet.IP{assignIP})

	}

	if autoAssignNumIPv4 != 0 {
		assignedIPv4, _, _ := ic.AutoAssign(client.AutoAssignArgs{
			Num4: autoAssignNumIPv4,
		})
		inIPs = assignedIPv4
	}

	unallocatedIPs, outErr := ic.ReleaseIPs(inIPs)
	if outErr != nil {
		log.Println(outErr)
	}
	return unallocatedIPs, outErr
}

// testIPAMAssignIP takes an IPv4 or IPv6 IP with a hostname and pool name and calls AssignIP.
// Set cleanEnv to true to wipe clean etcd and reset IPAM config.
func testIPAMAssignIP(inIP net.IP, host string, poolSubnet []string, cleanEnv bool, config api.CalicoAPIConfig) error {
	args := client.AssignIPArgs{
		IP:       cnet.IP{inIP},
		Hostname: host,
	}
	if cleanEnv {
		c := testutils.CreateCleanClient(config)
		for _, v := range poolSubnet {
			testutils.CreateNewIPPool(*c, v, false, false, true)
		}
	}
	c := testutils.CreateClient(config)
	ic := setupIPAMClient(c, cleanEnv)
	outErr := ic.AssignIP(args)

	if outErr != nil {
		log.Println(outErr)
	}
	return outErr
}

// testIPAMAutoAssign takes number of requested IPv4 and IPv6, and hostname, and setus up/cleans up client and etcd,
// then it calls AutoAssign (function under test) and returns the number of returned IPv4 and IPv6 addresses and returned error.
func testIPAMAutoAssign(inv4, inv6 int, host string, cleanEnv bool, poolSubnet []string, usePool string, config api.CalicoAPIConfig) (int, int, error) {
	fromPool := cnet.MustParseNetwork(usePool)
	args := client.AutoAssignArgs{
		Num4:      inv4,
		Num6:      inv6,
		Hostname:  host,
		IPv4Pools: []cnet.IPNet{fromPool},
	}

	if cleanEnv {
		c := testutils.CreateCleanClient(config)
		for _, v := range poolSubnet {
			testutils.CreateNewIPPool(*c, v, false, false, true)
		}
	}
	c := testutils.CreateClient(config)
	ic := setupIPAMClient(c, cleanEnv)
	v4, v6, outErr := ic.AutoAssign(args)

	if outErr != nil {
		log.Println(outErr)
	}

	return len(v4), len(v6), outErr
}

// setupIPAMClient sets up a client, and returns IPAMInterface.
// It also resets IPAM config if cleanEnv is true.
func setupIPAMClient(c *client.Client, cleanEnv bool) client.IPAMInterface {
	ic := c.IPAM()
	if cleanEnv {
		ic.SetIPAMConfig(client.IPAMConfig{
			StrictAffinity:     false,
			AutoAllocateBlocks: true,
		})
	}
	return ic
}

// assignIPutil is a utility function to help with assigning a single IP address to a hostname passed in.
func assignIPutil(ic client.IPAMInterface, assignIP net.IP, host string) {
	if len(assignIP) != 0 {
		err := ic.AssignIP(client.AssignIPArgs{
			IP:       cnet.IP{assignIP},
			Hostname: host,
		})
		log.Printf("Assigning IP: %s\n", assignIP)
		if err != nil {
			Fail(fmt.Sprintf("Error assigning IP %s", assignIP))
		}
	}
}

// getAffineBlocks gets all the blocks affined to the host passed in.
func getAffineBlocks(host string) []cnet.IPNet {
	opts := model.BlockAffinityListOptions{Host: host, IPVersion: 4}
	c, _ := client.LoadClientConfig("")
	compatClient, err := backend.NewClient(*c)

	datastoreObjs, err := compatClient.List(opts)
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.Printf("No affined blocks found")
		} else {
			Expect(err).NotTo(HaveOccurred(), "Error getting affine blocks: %s", err)
		}
	}

	// Iterate through and extract the block CIDRs.
	blocks := []cnet.IPNet{}
	for _, o := range datastoreObjs {
		k := o.Key.(model.BlockAffinityKey)
		blocks = append(blocks, k.CIDR)
	}
	return blocks
}
