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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Describe("Random Block Generator", func() {

	Describe("IPv4 pool", func() {
		poolTest("10.10.0.0/24")
	})

	Describe("IPv6 pool", func() {
		poolTest("fd80:24e2:f998:72d6::/120")
	})

})

func poolTest(cidr string) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(GinkgoWriter, "Error parsing subnet %v\n", err)
	}
	var pools []cnet.IPNet
	pools = []cnet.IPNet{{*subnet}}
	host := "testHost"

	for _, pool := range pools {

		ones, size := pool.Mask.Size()
		prefixLen := size - ones
		numIP := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(prefixLen)), nil)
		blocks := randomBlockGenerator(pool, host)

		blockCount := big.NewInt(0)
		for blk := blocks(); blk != nil; blk = blocks() {

			blockCount.Add(blockCount, big.NewInt(1))
			ip, sn, err := net.ParseCIDR(blk.String())
			if err != nil {
				fmt.Fprintf(GinkgoWriter, "Error parsing subnet %v\n", err)
			}

			fmt.Fprintf(GinkgoWriter, "Getting block: %s\n", blk.String())
			Context("For IP within the block range", func() {
				It("should be within the pool range", func() {
					for ip := ip.Mask(sn.Mask); sn.Contains(ip); increment(ip) {
						Expect(pool.Contains(ip)).To(BeTrue())
					}
				})
			})
		}
		Context("For the given pool size", func() {
			It("number of blocks should be poolSize/blockSize", func() {
				numBlocks := new(big.Int)
				numBlocks.Div(numIP, big.NewInt(blockSize))
				Expect(blockCount).To(Equal(numBlocks))
			})
		})
	}
}

func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
