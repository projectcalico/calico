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

package client_test

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/onsi/ginkgo/extensions/table"

	"github.com/tigera/libcalico-go/calicoctl/commands"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend/etcd"
	"github.com/tigera/libcalico-go/lib/client"
)

var etcdType api.BackendType

func testIPAM(inv4, inv6 int, host string, setup bool) (int, int) {
	fmt.Println("in func")

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
	if setup {
		setupEnv()
	}

	v4, v6, outErr := ic.AutoAssign(entry)

	if outErr != nil {
		fmt.Print("printing error.... ")
		fmt.Println(outErr)
	}

	return len(v4), len(v6)

}

var _ = Describe("IPAM", func() {

	DescribeTable("requested IPs vs got IPs",
		func(host string, setup bool, inv4, inv6, expv4, expv6 int) {
			outv4, outv6 := testIPAM(inv4, inv6, host, setup)
			Expect(outv4).To(Equal(expv4))
			Expect(outv6).To(Equal(expv6))
		},
		Entry("1 v4 1 v6", "testHost", true, 1, 1, 1, 1),
		Entry("256 v4 256 v6", "testHost", true, 256, 256, 256, 256),
		Entry("257 v4 0 v6", "testHost", true, 257, 0, 256, 0),
		Entry("0 v4 257 v6", "testHost", true, 0, 257, 0, 256),
	)
})

func setupEnv() {

	cmd := "docker"
	argsRm := []string{"rm", "-f", "calico-etcd", "||", "true"}
	if err := exec.Command(cmd, argsRm...).Run(); err != nil {
		log.Println(err)
	}

	argsRun := []string{"run", "--detach", "-p", "2379:2379", "--name", "calico-etcd", "quay.io/coreos/etcd:v2.3.6", "--advertise-client-urls", "http://127.0.0.1:2379,http://127.0.0.1:4001", "--listen-client-urls", "http://0.0.0.0:2379,http://0.0.0.0:4001"}
	if err := exec.Command(cmd, argsRun...).Run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	argsPool := []string{"create", "-f", "../../test/pool1.yaml"}
	if err := commands.Create(argsPool); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
