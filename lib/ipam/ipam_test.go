// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

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
	"context"
	"errors"
	"fmt"
	"net"
	"sort"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

// Implement an IP pools accessor for the IPAM client.  This is a "mock" version
// of the accessor that we populate directly, rather than requiring the pool
// data to be persisted in etcd.
type ipPoolAccessor struct {
	pools map[string]pool
}

type pool struct {
	cidr         string
	blockSize    int
	enabled      bool
	nodeSelector string
}

func (i *ipPoolAccessor) GetEnabledPools(ipVersion int) ([]v3.IPPool, error) {
	sorted := make([]string, 0)
	// Get a sorted list of enabled pool CIDR strings.
	for p, e := range i.pools {
		if e.enabled {
			sorted = append(sorted, p)
		}
	}
	sort.Strings(sorted)

	// Convert to IPNets and sort out the correct IP versions.  Sorting the results
	// mimics more closely the behavior of etcd and allows the tests to be
	// deterministic.
	pools := make([]v3.IPPool, 0)
	for _, p := range sorted {
		c := cnet.MustParseCIDR(p)
		if c.Version() == ipVersion {
			pool := v3.IPPool{Spec: v3.IPPoolSpec{CIDR: p, NodeSelector: i.pools[p].nodeSelector}}
			if i.pools[p].blockSize == 0 {
				if ipVersion == 4 {
					pool.Spec.BlockSize = 26
				} else {
					pool.Spec.BlockSize = 122
				}

			} else {
				pool.Spec.BlockSize = i.pools[p].blockSize
			}
			pools = append(pools, pool)
		}
	}

	log.Infof("GetEnabledPools returns: %v", pools)

	return pools, nil
}

var (
	ipPools = &ipPoolAccessor{pools: map[string]pool{}}
)

type testArgsClaimAff struct {
	inNet, host                 string
	cleanEnv                    bool
	pool                        []string
	assignIP                    net.IP
	expClaimedIPs, expFailedIPs int
	expError                    error
}

var _ = testutils.E2eDatastoreDescribe("IPAM tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {
	// Create a new backend client and an IPAM Client using the IP Pools Accessor.
	// Tests that need to ensure a clean datastore should invoke Clean() on the datastore at the start of the
	// tests.
	var bc bapi.Client
	var ic Interface
	BeforeEach(func() {
		var err error
		bc, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		ic = NewIPAMClient(bc, ipPools)
	})

	Context("Measuring allocation performance", func() {
		hostname := "host-perf"

		var pool20, pool32, pool26 []cnet.IPNet
		// Create many pools
		for i := 0; i < 100; i++ {
			cidr := fmt.Sprintf("10.%d.0.0/16", i)
			ipPools.pools[cidr] = pool{enabled: true, blockSize: 26}
			pool26 = append(pool26, cnet.MustParseCIDR(cidr))
		}

		for i := 0; i < 100; i++ {
			cidr := fmt.Sprintf("11.%d.0.0/16", i)
			ipPools.pools[cidr] = pool{enabled: true, blockSize: 32}
			pool32 = append(pool32, cnet.MustParseCIDR(cidr))
		}

		for i := 0; i < 50; i++ {
			cidr := fmt.Sprintf("12.%d.0.0/16", i)
			ipPools.pools[cidr] = pool{enabled: true, blockSize: 20}
			pool20 = append(pool20, cnet.MustParseCIDR(cidr))
		}

		BeforeEach(func() {
			applyNode(bc, hostname, map[string]string{"foo": "bar"})
		})

		AfterEach(func() {
			deleteNode(bc, hostname)
		})

		Measure("It should be able to allocate a single address quickly - blocksize 32", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				v4, _, outErr := ic.AutoAssign(context.Background(), AutoAssignArgs{Num4: 1, IPv4Pools: pool32, Hostname: hostname})
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(1))
			})

			Expect(runtime.Seconds()).Should(BeNumerically("<", 1))
		}, 100)

		Measure("It should be able to allocate a single address quickly - blocksize 26", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				v4, _, outErr := ic.AutoAssign(context.Background(), AutoAssignArgs{Num4: 1, IPv4Pools: pool26, Hostname: hostname})
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(1))
			})

			Expect(runtime.Seconds()).Should(BeNumerically("<", 1))
		}, 100)

		Measure("It should be able to allocate a single address quickly - blocksize 20", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				v4, _, outErr := ic.AutoAssign(context.Background(), AutoAssignArgs{Num4: 1, IPv4Pools: pool20, Hostname: hostname})
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(1))
			})

			Expect(runtime.Seconds()).Should(BeNumerically("<", 1))
		}, 100)

		Measure("It should be able to allocate a lot of addresses quickly", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				v4, _, outErr := ic.AutoAssign(context.Background(), AutoAssignArgs{Num4: 64, IPv4Pools: pool20, Hostname: hostname})
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(64))
			})

			Expect(runtime.Seconds()).Should(BeNumerically("<", 1))
		}, 20)

		Measure("It should be able to allocate and release addresses quickly", func(b Benchmarker) {
			runtime := b.Time("runtime", func() {
				v4, _, outErr := ic.AutoAssign(context.Background(), AutoAssignArgs{Num4: 1, Hostname: hostname})
				v4IP := make([]cnet.IP, 0, 0)
				for _, ipNets := range v4 {
					IP, _, _ := cnet.ParseCIDR(ipNets.String())
					v4IP = append(v4IP, *IP)
				}
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4IP)).To(Equal(1))
				v4IP, outErr = ic.ReleaseIPs(context.Background(), v4IP)
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4IP)).To(Equal(0))
			})

			Expect(runtime.Seconds()).Should(BeNumerically("<", 1))
		}, 20)
	})

	// We're assigning one IP which should be from the only ipPool created at the time, second one
	// should be from the same /26 block since they're both from the same host, then delete
	// the ipPool and create a new ipPool, and AutoAssign 1 more IP for the same host - expect the
	// assigned IP to be from the new ipPool that was created, this is to make sure the assigned IP
	// doesn't come from the old affinedBlock even after the ipPool was deleted.
	Describe("IPAM AutoAssign from the default pool then delete the pool and assign again", func() {
		hostA := "host-A"
		hostB := "host-B"
		pool1 := cnet.MustParseNetwork("10.0.0.0/24")
		pool2 := cnet.MustParseNetwork("20.0.0.0/24")
		var block cnet.IPNet

		Context("AutoAssign a single IP without specifying a pool", func() {

			It("should auto-assign from the only available pool", func() {
				bc.Clean()
				deleteAllPools()

				applyNode(bc, hostA, nil)
				applyNode(bc, hostB, nil)
				applyPool("10.0.0.0/24", true, "")

				args := AutoAssignArgs{
					Num4:     1,
					Num6:     0,
					Hostname: hostA,
				}

				v4, _, outErr := ic.AutoAssign(context.Background(), args)

				blocks := getAffineBlocks(bc, hostA)
				for _, b := range blocks {
					if pool1.Contains(b.IPNet.IP) {
						block = b
					}
				}
				Expect(outErr).NotTo(HaveOccurred())
				Expect(pool1.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})

			It("should auto-assign another IP from the same pool into the same allocation block", func() {
				args := AutoAssignArgs{
					Num4:     1,
					Num6:     0,
					Hostname: hostA,
				}

				v4, _, outErr := ic.AutoAssign(context.Background(), args)
				Expect(outErr).NotTo(HaveOccurred())
				Expect(block.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})

			It("should assign from a new pool for a new host (old pool is removed)", func() {
				deleteAllPools()
				applyPool("20.0.0.0/24", true, "")

				p, _ := ipPools.GetEnabledPools(4)
				Expect(len(p)).To(Equal(1))
				Expect(p[0].Spec.CIDR).To(Equal(pool2.String()))
				p, _ = ipPools.GetEnabledPools(6)
				Expect(len(p)).To(BeZero())

				args := AutoAssignArgs{
					Num4:     1,
					Num6:     0,
					Hostname: hostB,
				}
				v4, _, outErr := ic.AutoAssign(context.Background(), args)
				Expect(outErr).NotTo(HaveOccurred())
				Expect(pool2.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})

			It("should not assign from an existing affine block for the first host since the pool is removed)", func() {
				args := AutoAssignArgs{
					Num4:     1,
					Num6:     0,
					Hostname: hostA,
				}
				v4, _, outErr := ic.AutoAssign(context.Background(), args)
				Expect(outErr).NotTo(HaveOccurred())
				Expect(pool2.IPNet.Contains(v4[0].IP)).To(BeTrue())
			})
		})
	})

	Describe("IPAM AutoAssign from any pool", func() {
		// Assign an IP address, don't pass a pool, make sure we can get an
		// address.
		args := AutoAssignArgs{
			Num4:     1,
			Num6:     0,
			Hostname: "test-host",
		}

		BeforeEach(func() {
			applyNode(bc, args.Hostname, nil)
		})

		AfterEach(func() {
			deleteNode(bc, args.Hostname)
		})

		// Call once in order to assign an IP address and create a block.
		It("should have assigned an IP address with no error", func() {
			deleteAllPools()

			applyPool("10.0.0.0/24", true, "")
			applyPool("20.0.0.0/24", true, "")

			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			Expect(outErr).NotTo(HaveOccurred())
			Expect(len(v4) == 1).To(BeTrue())
		})

		// Call again to trigger an assignment from the newly created block.
		It("should have assigned an IP address with no error", func() {
			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			Expect(outErr).NotTo(HaveOccurred())
			Expect(len(v4)).To(Equal(1))
		})
	})

	Describe("IPAM AutoAssign from different pools", func() {
		host := "host-A"
		pool1 := cnet.MustParseNetwork("10.0.0.0/24")
		pool2 := cnet.MustParseNetwork("20.0.0.0/24")
		var block1, block2 cnet.IPNet

		It("should get an IP from pool1 when explicitly requesting from that pool", func() {
			bc.Clean()
			deleteAllPools()

			applyNode(bc, host, nil)
			applyPool("10.0.0.0/24", true, "")
			applyPool("20.0.0.0/24", true, "")

			args := AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1},
			}

			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			blocks := getAffineBlocks(bc, host)
			for _, b := range blocks {
				if pool1.Contains(b.IPNet.IP) {
					block1 = b
				}
			}

			Expect(outErr).NotTo(HaveOccurred())
			Expect(pool1.IPNet.Contains(v4[0].IP)).To(BeTrue())
		})

		It("should get an IP from pool2 when explicitly requesting from that pool", func() {
			args := AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool2},
			}

			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			blocks := getAffineBlocks(bc, host)
			for _, b := range blocks {
				if pool2.Contains(b.IPNet.IP) {
					block2 = b
				}
			}

			Expect(outErr).NotTo(HaveOccurred())
			Expect(block2.IPNet.Contains(v4[0].IP)).To(BeTrue())
		})

		It("should get an IP from pool1 in the same allocation block as the first IP from pool1", func() {
			args := AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1},
			}
			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			Expect(outErr).NotTo(HaveOccurred())
			Expect(block1.IPNet.Contains(v4[0].IP)).To(BeTrue())
		})

		It("should get an IP from pool2 in the same allocation block as the first IP from pool2", func() {
			args := AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool2},
			}

			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			Expect(outErr).NotTo(HaveOccurred())
			Expect(block2.IPNet.Contains(v4[0].IP)).To(BeTrue())
		})

		It("should have strict IP pool affinity", func() {
			// Assign the rest of the addresses in pool2.
			// A /24 has 256 addresses. We've assigned 2 already, so assign 254 more.
			args := AutoAssignArgs{
				Num4:      254,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool2},
			}

			By("allocating the rest of the IPs in the pool", func() {
				v4, _, outErr := ic.AutoAssign(context.Background(), args)
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(254))

				// Expect all the IPs to be in pool2.
				for _, a := range v4 {
					Expect(pool2.IPNet.Contains(a.IP)).To(BeTrue(), fmt.Sprintf("%s not in pool %s", a.IP, pool2))
				}
			})

			By("attempting to allocate an IP when there are no more left in the pool", func() {
				args.Num4 = 1
				v4, _, outErr := ic.AutoAssign(context.Background(), args)
				Expect(outErr).NotTo(HaveOccurred())
				Expect(len(v4)).To(Equal(0))
			})
		})
	})

	Describe("IPAM AutoAssign using ip pool node selectors", func() {
		It("should only assign ips from the ip pool whose node selector matches the host's node labels", func() {
			host := "host"
			pool1 := cnet.MustParseNetwork("10.0.0.0/24")
			pool2 := cnet.MustParseNetwork("20.0.0.0/24")

			bc.Clean()
			deleteAllPools()

			applyNode(bc, host, map[string]string{"foo": "bar"})
			applyPool(pool1.String(), true, `foo == "bar"`)
			applyPool(pool2.String(), true, `foo != "bar"`)

			// Attempt to assign 300 ips but only the 256 ips from pool1 should be used.
			v4, _, outErr := ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     300,
				Num6:     0,
				Hostname: host,
			})
			Expect(outErr).NotTo(HaveOccurred())
			Expect(len(v4)).To(Equal(256))

			// Expect all the IPs to be from pool1.
			for _, a := range v4 {
				Expect(pool1.IPNet.Contains(a.IP)).To(BeTrue(), fmt.Sprintf("%s not in pool %s", a.IP, pool1))
			}
		})

		// This test validates the behavior of changing node selectors on IP pools. Specifically, it
		// ensures that when a node used to be selected by an IP pool but is no longer selected, we
		// properly release block affinities so that the block can be reassigned to a node that is
		// actually selected by the IP pool.
		It("should handle changing node selectors and release affinity appropriately (ReleaseIPs)", func() {
			host := "host"
			pool1 := cnet.MustParseNetwork("10.0.0.0/24")

			bc.Clean()
			deleteAllPools()

			applyNode(bc, host, map[string]string{"foo": "bar"})
			applyPool(pool1.String(), true, `foo == "bar"`)

			// Assign three addresses to the node.
			v4nets, _, err := ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     3,
				Num6:     0,
				Hostname: host,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(v4nets)).To(Equal(3))

			// Should have one affine block to this host.
			blocks := getAffineBlocks(bc, host)
			Expect(len(blocks)).To(Equal(1))

			// Expect all the IPs to be from pool1.
			var v4IPs []cnet.IP
			for _, a := range v4nets {
				Expect(pool1.IPNet.Contains(a.IP)).To(BeTrue(), fmt.Sprintf("%s not in pool %s", a.IP, pool1))
				v4IPs = append(v4IPs, cnet.IP{a.IP})
			}

			// Release one of the IPs.
			unallocated, err := ic.ReleaseIPs(context.Background(), v4IPs[0:1])
			Expect(len(unallocated)).To(Equal(0))
			Expect(err).NotTo(HaveOccurred())

			// Should still have one affine block to this host.
			blocks = getAffineBlocks(bc, host)
			Expect(len(blocks)).To(Equal(1))

			// Change the selector for the IP pool so that it no longer matches node1.
			applyPool(pool1.String(), true, `foo != "bar"`)

			// Release another one of the IPs.
			unallocated, err = ic.ReleaseIPs(context.Background(), v4IPs[1:2])
			Expect(len(unallocated)).To(Equal(0))
			Expect(err).NotTo(HaveOccurred())

			// The block should no longer have an affinity to this host.
			Expect(len(getAffineBlocks(bc, host))).To(Equal(0))

			// But it should still exist.
			opts := model.BlockListOptions{IPVersion: 4}
			out, err := bc.List(context.Background(), opts, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(out.KVPairs)).To(Equal(1))

			// Release the last IP.
			unallocated, err = ic.ReleaseIPs(context.Background(), v4IPs[2:3])
			Expect(len(unallocated)).To(Equal(0))
			Expect(err).NotTo(HaveOccurred())

			// The block now has no affinity, and no IPs, so it should be deleted.
			out, err = bc.List(context.Background(), opts, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(out.KVPairs)).To(Equal(0))
		})

		// Same test as above but using the ReleaseByHandle IPAM method
		It("should handle changing node selectors and release affinity appropriately (ReleaseByHandle)", func() {
			host := "host"
			pool1 := cnet.MustParseNetwork("10.0.0.0/24")

			bc.Clean()
			deleteAllPools()

			applyNode(bc, host, map[string]string{"foo": "bar"})
			applyPool(pool1.String(), true, `foo == "bar"`)

			handleID1 := "handle1"
			handleID2 := "handle2"
			handleID3 := "handle3"

			// Assign three addresses to the node.
			v4net1, _, err := ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: host,
				HandleID: &handleID1,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(v4net1)).To(Equal(1))

			v4net2, _, err := ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: host,
				HandleID: &handleID2,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(v4net2)).To(Equal(1))

			v4net3, _, err := ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: host,
				HandleID: &handleID3,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(len(v4net3)).To(Equal(1))

			// Should have one affine block to this host.
			blocks := getAffineBlocks(bc, host)
			Expect(len(blocks)).To(Equal(1))

			// Expect all the IPs to be from pool1.
			Expect(pool1.IPNet.Contains(v4net1[0].IP)).To(BeTrue(), fmt.Sprintf("%s not in pool %s", v4net1[0].IP, pool1))
			Expect(pool1.IPNet.Contains(v4net2[0].IP)).To(BeTrue(), fmt.Sprintf("%s not in pool %s", v4net2[0].IP, pool1))
			Expect(pool1.IPNet.Contains(v4net3[0].IP)).To(BeTrue(), fmt.Sprintf("%s not in pool %s", v4net3[0].IP, pool1))

			// Release one of the IPs.
			err = ic.ReleaseByHandle(context.Background(), handleID1)
			Expect(err).NotTo(HaveOccurred())

			// Should still have one affine block to this host.
			blocks = getAffineBlocks(bc, host)
			Expect(len(blocks)).To(Equal(1))

			// Change the selector for the IP pool so that it no longer matches node1.
			applyPool(pool1.String(), true, `foo != "bar"`)

			// Release another one of the IPs.
			err = ic.ReleaseByHandle(context.Background(), handleID2)
			Expect(err).NotTo(HaveOccurred())

			// The block should no longer have an affinity to this host.
			Expect(len(getAffineBlocks(bc, host))).To(Equal(0))

			// But it should still exist.
			opts := model.BlockListOptions{IPVersion: 4}
			out, err := bc.List(context.Background(), opts, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(out.KVPairs)).To(Equal(1))

			// Release the last IP.
			err = ic.ReleaseByHandle(context.Background(), handleID3)
			Expect(err).NotTo(HaveOccurred())

			// The block now has no affinity, and no IPs, so it should be deleted.
			out, err = bc.List(context.Background(), opts, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(len(out.KVPairs)).To(Equal(0))
		})

		// Tests behavior when there are no more blocks available. For nodes which are selected by an
		// IP pool, addresses should be borrowed from other blocks within the pool. For nodes which are
		// not selected by that IP pool, an error should be returned and addresses should no be borrowed.
		It("should handle changing node selectors between two nodes with no available blocks", func() {
			node1 := "host1"
			node2 := "host2"
			pool1 := cnet.MustParseNetwork("10.0.0.0/30")

			bc.Clean()
			deleteAllPools()

			applyNode(bc, node1, map[string]string{"foo": "bar"})
			applyNode(bc, node2, nil)
			applyPoolWithBlockSize(pool1.String(), true, `foo == "bar"`, 30)

			// Assign 3 of the 4 total addresses to node1.
			v4, _, err := ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     3,
				Num6:     0,
				Hostname: node1,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(len(v4)).To(Equal(3))

			// Should have one affine block to node1.
			blocks := getAffineBlocks(bc, node1)
			Expect(len(blocks)).To(Equal(1))

			// Switch labels so that ip pool selects node2.
			applyNode(bc, node1, nil)
			applyNode(bc, node2, map[string]string{"foo": "bar"})

			// Assign 1 address to node1, expect an error.
			v4, _, err = ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: node1,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("no configured Calico pools for node host1"))
			Expect(len(v4)).To(Equal(0))

			// Assign 1 address to node2.
			v4, _, err = ic.AutoAssign(context.Background(), AutoAssignArgs{
				Num4:     1,
				Num6:     0,
				Hostname: node2,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(len(v4)).To(Equal(1))

			// The block should still be affine to node 1.
			blocks = getAffineBlocks(bc, node1)
			Expect(len(blocks)).To(Equal(1))

			// The address assigned to node2 should come from the block affine to node1.
			node2IP := v4[0].IP
			Expect(pool1.IPNet.Contains(node2IP)).To(BeTrue(), fmt.Sprintf("%s not in pool %s", node2IP, pool1))
		})
	})

	Describe("IPAM AutoAssign from different pools - multi", func() {
		host := "host-A"
		pool1 := cnet.MustParseNetwork("10.0.0.0/24")
		pool2 := cnet.MustParseNetwork("20.0.0.0/24")
		pool3 := cnet.MustParseNetwork("30.0.0.0/24")
		pool4_v6 := cnet.MustParseNetwork("fe80::11/120")
		pool5_doesnot_exist := cnet.MustParseNetwork("40.0.0.0/24")

		It("should fail to AutoAssign 1 IPv4 when requesting a disabled IPv4 in the list of requested pools", func() {
			args := AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool3},
			}
			bc.Clean()
			deleteAllPools()

			applyNode(bc, host, nil)
			applyPool(pool1.String(), true, "")
			applyPool(pool2.String(), true, "")
			applyPool(pool3.String(), false, "")
			applyPool(pool4_v6.String(), true, "")
			_, _, outErr := ic.AutoAssign(context.Background(), args)
			Expect(outErr).To(HaveOccurred())
		})

		It("should fail to AutoAssign when specifying an IPv6 pool in the IPv4 requested pools", func() {
			args := AutoAssignArgs{
				Num4:      0,
				Num6:      1,
				Hostname:  host,
				IPv6Pools: []cnet.IPNet{pool4_v6, pool1},
			}
			_, _, outErr := ic.AutoAssign(context.Background(), args)
			Expect(outErr).To(HaveOccurred())
		})

		It("should allocate an IP from the first requested pool when two valid pools are requested", func() {
			args := AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool2},
			}
			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			log.Printf("IPAM returned: %v\n", v4)

			Expect(outErr).NotTo(HaveOccurred())
			Expect(len(v4)).To(Equal(1))
			Expect(pool1.Contains(v4[0].IP)).To(BeTrue())
		})

		It("should allocate 300 IP addresses from two enabled pools that contain sufficient addresses", func() {
			args := AutoAssignArgs{
				Num4:      300,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool2},
			}
			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			log.Printf("v4: %d IPs\n", len(v4))

			Expect(outErr).NotTo(HaveOccurred())
			Expect(len(v4)).To(Equal(300))
		})

		It("should fail to allocate another 300 IP addresses from the same pools due to lack of addresses (partial allocation)", func() {
			args := AutoAssignArgs{
				Num4:      300,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool2},
			}
			v4, _, outErr := ic.AutoAssign(context.Background(), args)
			log.Printf("v4: %d IPs\n", len(v4))

			// Expect 211 entries since we have a total of 512, we requested 1 + 300 already.
			Expect(outErr).NotTo(HaveOccurred())
			Expect(v4).To(HaveLen(211))
		})

		It("should fail to allocate any address when requesting an invalid pool and a valid pool", func() {
			args := AutoAssignArgs{
				Num4:      1,
				Num6:      0,
				Hostname:  host,
				IPv4Pools: []cnet.IPNet{pool1, pool5_doesnot_exist},
			}
			v4, _, err := ic.AutoAssign(context.Background(), args)
			log.Printf("v4: %d IPs\n", len(v4))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("the given pool (40.0.0.0/24) does not exist, or is not enabled"))
			Expect(len(v4)).To(Equal(0))
		})
	})

	DescribeTable("AutoAssign: requested IPs vs returned IPs",
		func(host string, cleanEnv bool, pools []pool, usePool string, inv4, inv6, expv4, expv6 int, blockLimit int, expError error) {

			if cleanEnv {
				bc.Clean()
				deleteAllPools()
			}
			applyNode(bc, host, nil)
			defer deleteNode(bc, host)

			for _, v := range pools {
				ipPools.pools[v.cidr] = pool{cidr: v.cidr, enabled: v.enabled, blockSize: v.blockSize}
			}

			fromPool := cnet.MustParseNetwork(usePool)
			args := AutoAssignArgs{
				Num4:             inv4,
				Num6:             inv6,
				Hostname:         host,
				IPv4Pools:        []cnet.IPNet{fromPool},
				MaxBlocksPerHost: blockLimit,
			}

			outv4, outv6, outErr := ic.AutoAssign(context.Background(), args)
			if expError != nil {
				Expect(outErr).To(HaveOccurred())
			} else {
				Expect(outErr).ToNot(HaveOccurred())
			}
			Expect(outv4).To(HaveLen(expv4))
			Expect(outv6).To(HaveLen(expv6))
		},

		// Test 1a: AutoAssign 1 IPv4, 1 IPv6 with tiny block - expect one of each to be returned.
		Entry("1 v4 1 v6 - tiny block", "testHost", true, []pool{{"192.168.1.0/24", 32, true, ""}, {"fd80:24e2:f998:72d6::/120", 128, true, ""}}, "192.168.1.0/24", 1, 1, 1, 1, 0, nil),

		// Test 1b: AutoAssign 1 IPv4, 1 IPv6 with massive block - expect one of each to be returned.
		Entry("1 v4 1 v6 - big block", "testHost", true, []pool{{"192.168.0.0/16", 20, true, ""}, {"fd80:24e2:f998:72d6::/110", 116, true, ""}}, "192.168.0.0/16", 1, 1, 1, 1, 0, nil),

		// Test 1c: AutoAssign 1 IPv4, 1 IPv6 with default block - expect one of each to be returned.
		Entry("1 v4 1 v6 - default block", "testHost", true, []pool{{"192.168.1.0/24", 26, true, ""}, {"fd80:24e2:f998:72d6::/120", 122, true, ""}}, "192.168.1.0/24", 1, 1, 1, 1, 0, nil),

		// Test 2a: AutoAssign 256 IPv4, 256 IPv6 with default blocksize- expect 256 IPv4 + IPv6 addresses.
		Entry("256 v4 256 v6", "testHost", true, []pool{{"192.168.1.0/24", 26, true, ""}, {"fd80:24e2:f998:72d6::/120", 122, true, ""}}, "192.168.1.0/24", 256, 256, 256, 256, 0, nil),

		// Test 2b: AutoAssign 256 IPv4, 256 IPv6 with small blocksize- expect 256 IPv4 + IPv6 addresses.
		Entry("256 v4 256 v6 - small blocks", "testHost", true, []pool{{"192.168.1.0/24", 30, true, ""}, {"fd80:24e2:f998:72d6::/120", 126, true, ""}}, "192.168.1.0/24", 256, 256, 256, 256, 0, nil),

		// Test 2a: AutoAssign 256 IPv4, 256 IPv6 with num blocks limit expect 64 IPv4 + IPv6 addresses.
		Entry("256 v4 0 v6 block limit", "testHost", true, []pool{{"192.168.1.0/24", 26, true, ""}, {"fd80:24e2:f998:72d6::/120", 122, true, ""}}, "192.168.1.0/24", 256, 0, 64, 0, 1, ErrBlockLimit),
		Entry("256 v4 0 v6 block limit 2", "testHost", true, []pool{{"192.168.1.0/24", 26, true, ""}, {"fd80:24e2:f998:72d6::/120", 122, true, ""}}, "192.168.1.0/24", 256, 0, 128, 0, 2, ErrBlockLimit),
		Entry("0 v4 256 v6 block limit", "testHost", true, []pool{{"192.168.1.0/24", 26, true, ""}, {"fd80:24e2:f998:72d6::/120", 122, true, ""}}, "192.168.1.0/24", 0, 256, 0, 64, 1, ErrBlockLimit),

		// Test 3: AutoAssign 257 IPv4, 0 IPv6 - expect 256 IPv4 addresses, no IPv6, and no error.
		Entry("257 v4 0 v6", "testHost", true, []pool{{"192.168.1.0/24", 26, true, ""}, {"fd80:24e2:f998:72d6::/120", 122, true, ""}}, "192.168.1.0/24", 257, 0, 256, 0, 0, nil),

		// Test 4: AutoAssign 0 IPv4, 257 IPv6 - expect 256 IPv6 addresses, no IPv6, and no error.
		Entry("0 v4 257 v6", "testHost", true, []pool{{"192.168.1.0/24", 26, true, ""}, {"fd80:24e2:f998:72d6::/120", 122, true, ""}}, "192.168.1.0/24", 0, 257, 0, 256, 0, nil),

		// Test 5: (use pool of size /25 so only two blocks are contained):
		// - Assign 1 address on host A (Expect 1 address).
		Entry("1 v4 0 v6 host-A", "host-A", true, []pool{{"10.0.0.0/25", 26, true, ""}, {"fd80:24e2:f998:72d6::/121", 122, true, ""}}, "10.0.0.0/25", 1, 0, 1, 0, 0, nil),

		// - Assign 1 address on host B (Expect 1 address, different block).
		Entry("1 v4 0 v6 host-B", "host-B", false, []pool{{"10.0.0.0/25", 26, true, ""}, {"fd80:24e2:f998:72d6::/121", 122, true, ""}}, "10.0.0.0/25", 1, 0, 1, 0, 0, nil),

		// - Assign 64 more addresses on host A (Expect 63 addresses from host A's block, 1 address from host B's block).
		Entry("64 v4 0 v6 host-A", "host-A", false, []pool{{"10.0.0.0/25", 26, true, ""}, {"fd80:24e2:f998:72d6::/121", 122, true, ""}}, "10.0.0.0/25", 64, 0, 64, 0, 0, nil),
	)

	DescribeTable("AssignIP: requested IP vs returned error",
		func(inIP net.IP, host string, cleanEnv bool, pool []string, expError error) {
			args := AssignIPArgs{
				IP:       cnet.IP{inIP},
				Hostname: host,
			}
			if cleanEnv {
				bc.Clean()
				deleteAllPools()
			}

			applyNode(bc, host, nil)
			defer deleteNode(bc, host)

			for _, v := range pool {
				applyPool(v, true, "")
			}

			outError := ic.AssignIP(context.Background(), args)
			if expError != nil {
				Expect(outError).To(HaveOccurred())
				Expect(outError).To(Equal(expError))
			} else {
				Expect(outError).ToNot(HaveOccurred())
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
			inIPs := []cnet.IP{{inIP}}
			hostname := "host-release"

			// If we cleaned the datastore then recreate the pools.
			if cleanEnv {
				bc.Clean()
				deleteAllPools()
			}

			applyNode(bc, hostname, nil)
			defer deleteNode(bc, hostname)

			for _, v := range pool {
				applyPool(v, true, "")
			}

			if len(assignIP) != 0 {
				err := ic.AssignIP(context.Background(), AssignIPArgs{
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
				assignedIPv4, _, err := ic.AutoAssign(context.Background(), AutoAssignArgs{
					Num4:     autoAssignNumIPv4,
					Hostname: hostname,
				})
				Expect(err).ToNot(HaveOccurred())
				for _, ipnet := range assignedIPv4 {
					inIPs = append(inIPs, cnet.MustParseIP(ipnet.IP.String()))
				}
				inIPs = inIPs[1:]
			}

			unallocatedIPs, outErr := ic.ReleaseIPs(context.Background(), inIPs)
			if outErr != nil {
				log.Println(outErr)
			}

			// Expect returned slice of unallocatedIPs to be equal to expected expUnallocatedIPs.
			Expect(unallocatedIPs).To(Equal(expUnallocatedIPs))

			// Assert if an error was expected.
			if expError != nil {
				Expect(outErr).To(HaveOccurred())
				Expect(outErr).To(Equal(expError))
			} else {
				Expect(outErr).ToNot(HaveOccurred())
			}
		},

		// Test cases (ReleaseIPs):
		// Test 1: release an IP that's not configured in any pools - expect a slice with the same IP as unallocatedIPs and no error.
		Entry("Release an IP that's not configured in any pools", net.ParseIP("1.1.1.1"), true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, []cnet.IP{{net.ParseIP("1.1.1.1")}}, nil),

		// Test 2: release an IP that's not allocated in the pool - expect a slice with one (unallocatedIPs) and no error.
		Entry("Release an IP that's not allocated in the pool", net.ParseIP("192.168.1.0"), true, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, []cnet.IP{{net.ParseIP("192.168.1.0")}}, nil),

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
		Entry("Assign 1 IPv4 address with AssignIP then try to release 2 IPs (release a second one)", net.ParseIP("192.168.1.1"), false, []string{"192.168.1.0/24", "fd80:24e2:f998:72d6::/120"}, net.IP{}, 0, []cnet.IP{{net.ParseIP("192.168.1.1")}}, nil),
	)

	DescribeTable("ClaimAffinity: claim IPNet vs actual number of blocks claimed",
		func(args testArgsClaimAff) {
			inIPNet := cnet.MustParseNetwork(args.inNet)

			if args.cleanEnv {
				bc.Clean()
				deleteAllPools()
			}

			applyNode(bc, args.host, nil)
			defer deleteNode(bc, args.host)

			for _, v := range args.pool {
				applyPool(v, true, "")
			}

			assignIPutil(ic, args.assignIP, "Host-A")

			outClaimed, outFailed, outError := ic.ClaimAffinity(context.Background(), inIPNet, args.host)
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

		// Test 2: claim affinity for an unclaimed IPNet of size smaller than 64 - expect 0 claimed blocks, 0 failed and expect an error.
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

// Tests for determining IP pools to use.
var _ = DescribeTable("determinePools tests",
	func(pool1Enabled, pool2Enabled bool, pool1Selector, pool2Selector string, requestPool1, requestPool2 bool, expectation []string, expectErr bool) {
		// Seed data
		ipPools.pools = map[string]pool{
			"10.0.0.0/24": pool{enabled: pool1Enabled, nodeSelector: pool1Selector},
			"20.0.0.0/24": pool{enabled: pool2Enabled, nodeSelector: pool2Selector},
		}
		// Create a new IPAM client, giving a nil datastore client since determining pools
		// doesn't require datastore access (we mock out the IP pool accessor).
		ic := NewIPAMClient(nil, ipPools)

		// Create a node object for the test.
		node := v3.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}}

		// Prep input data
		reqPools := []cnet.IPNet{}
		if requestPool1 {
			cidr := cnet.MustParseCIDR("10.0.0.0/24")
			reqPools = append(reqPools, cidr)
		}
		if requestPool2 {
			cidr := cnet.MustParseCIDR("20.0.0.0/24")
			reqPools = append(reqPools, cidr)
		}

		// Call determinePools
		pools, err := ic.(*ipamClient).determinePools(reqPools, 4, node)

		// Assert on any returned error.
		if expectErr {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).NotTo(HaveOccurred())
		}

		// Check that the expected pools match the returned.
		actual := []string{}
		for _, pool := range pools {
			actual = append(actual, pool.Spec.CIDR)
		}
		Expect(actual).To(Equal(expectation))
	},
	Entry("Both pools enabled, none with node selector, no requested pools", true, true, "", "", false, false, []string{"10.0.0.0/24", "20.0.0.0/24"}, false),
	Entry("Both pools enabled, none with node selector, pool1 requested", true, true, "", "", true, false, []string{"10.0.0.0/24"}, false),

	Entry("Both pools enabled, pool1 matching selector, no requested pools", true, true, `foo == "bar"`, `foo != "bar"`, false, false, []string{"10.0.0.0/24"}, false),
	Entry("Both pools enabled, pool1 matching node selector, pool1 requested", true, true, `foo == "bar"`, `foo != "bar"`, true, false, []string{"10.0.0.0/24"}, false),

	Entry("Both pools enabled, pool1 mismatching node selector, no requested pools", true, true, `foo != "bar"`, "all()", false, false, []string{"20.0.0.0/24"}, false),
	Entry("Both pools enabled, pool1 mismatching node selector, pool1 requested", true, true, `foo != "bar"`, "", true, false, []string{"10.0.0.0/24"}, false),

	Entry("Both pools enabled, pool1 matching node selector, pool2 requested", true, true, `foo == "bar"`, "", false, true, []string{"20.0.0.0/24"}, false),

	Entry("pool1 disabled, none with node selector, no requested pools", false, true, "", "", false, false, []string{"20.0.0.0/24"}, false),
	Entry("pool1 disabled, none with node selector, pool1 requested", false, true, "", "", true, false, []string{}, true),
	Entry("pool1 disabled, none with node selector, pool2 requested", false, true, "", "", false, true, []string{"20.0.0.0/24"}, false),

	Entry("pool1 disabled, pool2 matching node selector, no requested pools", false, true, "", `foo == "bar"`, false, false, []string{"20.0.0.0/24"}, false),
	Entry("pool1 disabled, pool2 matching node selector, pool2 requested", false, true, "", `foo == "bar"`, false, true, []string{"20.0.0.0/24"}, false),
	Entry("pool1 disabled, pool2 mismatching node selector, no requested pools", false, true, "", `foo != "bar"`, false, false, []string{}, false),
	Entry("pool1 disabled, pool2 mismatching node selector, pool2 requested", false, true, "", `foo != "bar"`, false, true, []string{"20.0.0.0/24"}, false),
)

// assignIPutil is a utility function to help with assigning a single IP address to a hostname passed in.
func assignIPutil(ic Interface, assignIP net.IP, host string) {
	if len(assignIP) != 0 {
		err := ic.AssignIP(context.Background(), AssignIPArgs{
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
func getAffineBlocks(backend bapi.Client, host string) []cnet.IPNet {
	opts := model.BlockAffinityListOptions{Host: host, IPVersion: 4}
	datastoreObjs, err := backend.List(context.Background(), opts, "")
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.Printf("No affined blocks found")
		} else {
			Expect(err).NotTo(HaveOccurred(), "Error getting affine blocks: %v", err)
		}
	}

	// Iterate through and extract the block CIDRs.
	var blocks []cnet.IPNet
	for _, o := range datastoreObjs.KVPairs {
		k := o.Key.(model.BlockAffinityKey)
		blocks = append(blocks, k.CIDR)
	}
	return blocks
}

func deleteAllPools() {
	log.Infof("Deleting all pools")
	ipPools.pools = map[string]pool{}
}

func applyPool(cidr string, enabled bool, nodeSelector string) {
	ipPools.pools[cidr] = pool{enabled: enabled, nodeSelector: nodeSelector}
}

func applyPoolWithBlockSize(cidr string, enabled bool, nodeSelector string, blockSize int) {
	ipPools.pools[cidr] = pool{enabled: enabled, nodeSelector: nodeSelector, blockSize: blockSize}
}

func applyNode(c bapi.Client, host string, labels map[string]string) {
	c.Apply(context.Background(), &model.KVPair{
		Key: model.ResourceKey{Name: host, Kind: v3.KindNode},
		Value: v3.Node{
			ObjectMeta: metav1.ObjectMeta{Labels: labels},
			Spec: v3.NodeSpec{OrchRefs: []v3.OrchRef{
				v3.OrchRef{Orchestrator: "k8s", NodeName: host},
			}},
		},
	})
}

func deleteNode(c bapi.Client, host string) {
	c.Delete(context.Background(), &model.ResourceKey{Name: host, Kind: v3.KindNode}, "")
}
