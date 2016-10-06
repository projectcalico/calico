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

// Test cases:
// Test 1: AutoAssign 1 IPv4, 1 IPv6 - expect one of each to be returned.
// Test 2: AutoAssign 256 IPv4, 256 IPv6 - expect 256 IPv4 + IPv6 addresses
// Test 3: AutoAssign 257 IPv4, 0 IPv6 - expect 256 IPv4 addresses, no IPv6, and an error.
// Test 4: AutoAssign 0 IPv4, 257 IPv6 - expect 256 IPv6 addresses, no IPv6, and an error.
// Test 5: (use pool of size /25 so only two blocks are contained):
// - Assign 1 address on host A (Expect 1 address)
// - Assign 1 address on host B (Expect 1 address, different block)
// - Assign 64 more addresses on host A (Expect 63 addresses from host A's block, 1 address from host B's block)

package client_test

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/extensions/table"

	"github.com/tigera/libcalico-go/calicoctl/commands"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend/etcd"
	"github.com/tigera/libcalico-go/lib/client"
)

var etcdType api.BackendType

var _ = Describe("IPAM", func() {

	DescribeTable("Requested IPs vs returned IPs",
		func(host string, cleanEtcd bool, pool string, inv4, inv6, expv4, expv6 int, expError error) {
			outv4, outv6, outError := testIPAM(inv4, inv6, host, cleanEtcd, pool)
			Expect(outv4).To(Equal(expv4))
			Expect(outv6).To(Equal(expv6))
			if expError != nil {
				//This should be Ω(outError).Should(HaveOccurred()), but since AutoAssign only returns nil, we can't really check for returned error
				Ω(outError).ShouldNot(HaveOccurred())
			}
		},

		// Test 1: AutoAssign 1 IPv4, 1 IPv6 - expect one of each to be returned.
		Entry("1 v4 1 v6", "testHost", true, "pool1", 1, 1, 1, 1, nil),

		// Test 2: AutoAssign 256 IPv4, 256 IPv6 - expect 256 IPv4 + IPv6 addresses.
		Entry("256 v4 256 v6", "testHost", true, "pool1", 256, 256, 256, 256, nil),

		// Test 3: AutoAssign 257 IPv4, 0 IPv6 - expect 256 IPv4 addresses, no IPv6, and an error.
		Entry("257 v4 0 v6", "testHost", true, "pool1", 257, 0, 256, 0, errors.New("some error")),

		// Test 4: AutoAssign 0 IPv4, 257 IPv6 - expect 256 IPv6 addresses, no IPv6, and an error.
		Entry("0 v4 257 v6", "testHost", true, "pool1", 0, 257, 0, 256, errors.New("some error")),

		// Test 5: (use pool of size /25 (/test/pool2.yaml) so only two blocks are contained):
		// - Assign 1 address on host A (Expect 1 address)
		Entry("1 v4 0 v6 host-A", "host-A", true, "pool2", 1, 0, 1, 0, nil),

		// - Assign 1 address on host B (Expect 1 address, different block)
		Entry("1 v4 0 v6 host-B", "host-B", false, "pool2", 1, 0, 1, 0, nil),

		// - Assign 64 more addresses on host A (Expect 63 addresses from host A's block, 1 address from host B's block)
		Entry("64 v4 0 v6 host-A", "host-A", false, "pool2", 64, 0, 63, 0, errors.New("some error")),
	)
})

// testIPAM takes number of requested IPv4 and IPv6, and hostname, and setus up/cleans up client and etcd,
// then it calls AutoAssign (function under test) and returns the number of returned IPv4 and IPv6 addresses and returned error.
func testIPAM(inv4, inv6 int, host string, cleanEtcd bool, pool string) (int, int, error) {

	etcdType = "etcdv2"

	etcdConfig := etcd.EtcdConfig{
		EtcdEndpoints: "http://127.0.0.1:2379",
	}
	ac := api.ClientConfig{BackendType: etcdType, BackendConfig: &etcdConfig}

	bc, err := client.New(ac)
	if err != nil {
		panic(err)
	}

	ic := bc.IPAM()

	entry := client.AutoAssignArgs{
		Num4:     inv4,
		Num6:     inv6,
		Hostname: host,
	}

	setupEnv(cleanEtcd, pool)

	v4, v6, outErr := ic.AutoAssign(entry)

	if outErr != nil {
		log.Println(outErr)
	}

	return len(v4), len(v6), outErr

}

// setupEnv cleans up etcd if cleanEtcd flag is passed and then creates IP pool based on the pool name passed to it.
func setupEnv(cleanEtcd bool, pool string) {
	if cleanEtcd {
		etcdArgs := strings.Fields("rm /calico --recursive")
		if err := exec.Command("etcdctl", etcdArgs...).Run(); err != nil {
			log.Println(err)
		}
	}

	argsPool := strings.Fields(fmt.Sprintf("create -f ../../test/%s.yaml", pool))
	if err := commands.Create(argsPool); err != nil {
		log.Println(err)
	}
}
