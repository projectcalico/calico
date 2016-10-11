// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package client_test

import (
	"errors"
	"fmt"
	"log"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/extensions/table"

	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend/etcd"
	"github.com/tigera/libcalico-go/lib/client"
	cnet "github.com/tigera/libcalico-go/lib/net"
	"github.com/tigera/libcalico-go/lib/testutils"
)

// Setting BackendType to etcdv2 which is the only supported backend at the moment.
var etcdType api.BackendType = "etcdv2"

// Setting localhost as the etcd endpoint location since that's where `make run-etcd` runs it.
var etcdConfig = etcd.EtcdConfig{
	EtcdEndpoints: "http://127.0.0.1:2379",
}

var _ = Describe("IPAM tests", func() {

	DescribeTable("AutoAssign: requested IPs vs returned IPs",
		func(host string, cleanEnv bool, pool []string, inv4, inv6, expv4, expv6 int, expError error) {
			outv4, outv6, outError := testIPAMAutoAssign(inv4, inv6, host, cleanEnv, pool)
			Expect(outv4).To(Equal(expv4))
			Expect(outv6).To(Equal(expv6))
			if expError != nil {
				Expect(outError).To(HaveOccurred())
			}
		},

		// Test 1: AutoAssign 1 IPv4, 1 IPv6 - expect one of each to be returned.
		Entry("1 v4 1 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, 1, 1, 1, 1, nil),

		// Test 2: AutoAssign 256 IPv4, 256 IPv6 - expect 256 IPv4 + IPv6 addresses.
		Entry("256 v4 256 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, 256, 256, 256, 256, nil),

		// Test 3: AutoAssign 257 IPv4, 0 IPv6 - expect 256 IPv4 addresses, no IPv6, and no error.
		Entry("257 v4 0 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, 257, 0, 256, 0, nil),

		// Test 4: AutoAssign 0 IPv4, 257 IPv6 - expect 256 IPv6 addresses, no IPv6, and no error.
		Entry("0 v4 257 v6", "testHost", true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, 0, 257, 0, 256, nil),

		// Test 5: (use pool of size /25 so only two blocks are contained):
		// - Assign 1 address on host A (Expect 1 address).
		Entry("1 v4 0 v6 host-A", "host-A", true, []string{"10.0.0.1/25", "fd80:24e2:f998:72d6::/121"}, 1, 0, 1, 0, nil),

		// - Assign 1 address on host B (Expect 1 address, different block).
		Entry("1 v4 0 v6 host-B", "host-B", false, []string{"10.0.0.1/25", "fd80:24e2:f998:72d6::/121"}, 1, 0, 1, 0, nil),

		// - Assign 64 more addresses on host A (Expect 63 addresses from host A's block, 1 address from host B's block).
		Entry("64 v4 0 v6 host-A", "host-A", false, []string{"10.0.0.1/25", "fd80:24e2:f998:72d6::/121"}, 64, 0, 64, 0, nil),
	)

	DescribeTable("AssignIP: requested IP vs returned error",
		func(inIP net.IP, host string, cleanEnv bool, pool []string, expError error) {
			outError := testIPAMAssignIP(inIP, host, pool, cleanEnv)
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
			unallocatedIPs, outError := testIPAMReleaseIPs(inIP, pool, cleanEnv, assignIP, autoAssignNumIPv4)

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

})

// testIPAMReleaseIPs takes an IP, slice of string with IP pools to setup, cleanEnv flag means  setup a new environment.
// assignIP is if you want to assign a single IP before releasing an IP, and AutoAssign is to assign IPs in bulk before releasing any.
func testIPAMReleaseIPs(inIP net.IP, poolSubnet []string, cleanEnv bool, assignIP net.IP, autoAssignNumIPv4 int) ([]cnet.IP, error) {

	inIPs := []cnet.IP{cnet.IP{inIP}}
	if cleanEnv {
		testutils.CleanEtcd()
		c, _ := testutils.NewClient("")
		for _, v := range poolSubnet {
			testutils.CreateNewPool(*c, v, false, false, true)
		}
	}
	ic := setupIPMAClient(cleanEnv)

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
func testIPAMAssignIP(inIP net.IP, host string, poolSubnet []string, cleanEnv bool) error {
	args := client.AssignIPArgs{
		IP:       cnet.IP{inIP},
		Hostname: host,
	}
	if cleanEnv {
		testutils.CleanEtcd()
		c, _ := testutils.NewClient("")
		for _, v := range poolSubnet {
			testutils.CreateNewPool(*c, v, false, false, true)
		}
	}
	ic := setupIPMAClient(cleanEnv)
	outErr := ic.AssignIP(args)

	if outErr != nil {
		log.Println(outErr)
	}
	return outErr
}

// testIPAMAutoAssign takes number of requested IPv4 and IPv6, and hostname, and setus up/cleans up client and etcd,
// then it calls AutoAssign (function under test) and returns the number of returned IPv4 and IPv6 addresses and returned error.
func testIPAMAutoAssign(inv4, inv6 int, host string, cleanEnv bool, poolSubnet []string) (int, int, error) {

	args := client.AutoAssignArgs{
		Num4:     inv4,
		Num6:     inv6,
		Hostname: host,
	}

	if cleanEnv {
		testutils.CleanEtcd()
		c, _ := testutils.NewClient("")
		for _, v := range poolSubnet {
			testutils.CreateNewPool(*c, v, false, false, true)
		}
	}
	ic := setupIPMAClient(cleanEnv)
	v4, v6, outErr := ic.AutoAssign(args)

	if outErr != nil {
		log.Println(outErr)
	}

	return len(v4), len(v6), outErr
}

// setupIPMAClient sets up a client, and returns IPAMInterface.
// It also resets IPAM config if cleanEnv is true.
func setupIPMAClient(cleanEnv bool) client.IPAMInterface {
	ac := api.ClientConfig{BackendType: etcdType, BackendConfig: &etcdConfig}

	bc, err := client.New(ac)
	if err != nil {
		panic(err)
	}

	ic := bc.IPAM()
	if cleanEnv {
		ic.SetIPAMConfig(client.IPAMConfig{
			StrictAffinity:     false,
			AutoAllocateBlocks: true,
		})
	}
	return ic
}
