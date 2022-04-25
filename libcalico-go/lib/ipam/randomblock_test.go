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
package ipam

import (
	"fmt"
	"math/big"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("Random Block Generator", func() {

	DescribeTable("Test random block generator with different CIDRs",
		func(cidr string, blockSize int) {
			poolTest(cidr, blockSize)
		},

		Entry("IPv4 CIDR - default block size", "10.10.0.0/24", 26),
		Entry("IPv6 CIDR - default block size", "fd80:24e2:f998:72d6::/120", 122),
		Entry("IPv4 CIDR - maximum block size", "10.10.0.0/16", 20),
		Entry("IPv6 CIDR - maximum block size", "fd80:24e2:f998:72d6::/114", 116),
		Entry("IPv4 CIDR - minimum block size", "10.10.0.0/24", 32),
		Entry("IPv6 CIDR - minimum block size", "fd80:24e2:f998:72d6::/120", 128),
	)
})

func poolTest(cidr string, blockSize int) {
	pools := []v3.IPPool{{Spec: v3.IPPoolSpec{CIDR: cidr, BlockSize: blockSize}}}
	host := "testHost"

	_, pool, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())

	ones, size := pool.Mask.Size()
	prefixLen := size - ones
	numIP := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(prefixLen)), nil)
	blocks := randomBlockGenerator(pools[0], host)

	var numAddresses *big.Int

	blockCount := big.NewInt(0)
	for blk := blocks(); blk != nil; blk = blocks() {
		blockCount.Add(blockCount, big.NewInt(1))
		ip, sn, err := net.ParseCIDR(blk.String())
		Expect(err).NotTo(HaveOccurred())

		for ip := ip.Mask(sn.Mask); sn.Contains(ip); increment(ip) {
			Expect(pool.Contains(ip)).To(BeTrue())
		}

		// Store off the number of addresses - this will only record the value for the last block but that's fine.
		ones, size := blk.Mask.Size()
		numAddresses = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(size-ones)), nil)
	}

	By(fmt.Sprintf("Checking the block count has the correct number of blocks"))

	numBlocks := new(big.Int)
	numBlocks.Div(numIP, numAddresses)
	Expect(blockCount).To(Equal(numBlocks))
}

func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
