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
	"fmt"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

func newFakeClient() *fakeClient {
	return &fakeClient{
		createFuncs: map[string]func(ctx context.Context, object *model.KVPair) (*model.KVPair, error){},
		updateFuncs: map[string]func(ctx context.Context, object *model.KVPair) (*model.KVPair, error){},
		getFuncs:    map[string]func(ctx context.Context, key model.Key, revision string) (*model.KVPair, error){},
		deleteFuncs: map[string]func(ctx context.Context, key model.Key, revision string) (*model.KVPair, error){},
		listFuncs:   map[string]func(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error){},
	}
}

// fakeClient implements the backend api.Client interface.
type fakeClient struct {
	createFuncs map[string]func(ctx context.Context, object *model.KVPair) (*model.KVPair, error)
	updateFuncs map[string]func(ctx context.Context, object *model.KVPair) (*model.KVPair, error)
	getFuncs    map[string]func(ctx context.Context, key model.Key, revision string) (*model.KVPair, error)
	deleteFuncs map[string]func(ctx context.Context, key model.Key, revision string) (*model.KVPair, error)
	listFuncs   map[string]func(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error)
}

// We don't implement any of the CRUD related methods, just the Watch method to return
// a fake watcher that the test code will drive.
func (c *fakeClient) Create(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	if f, ok := c.createFuncs[fmt.Sprintf("%s", object.Key)]; ok {
		return f(ctx, object)
	} else if f, ok := c.createFuncs["default"]; ok {
		return f(ctx, object)
	}

	panic(fmt.Sprintf("Create called on unexpected object: %+v", object))
	return nil, nil
}
func (c *fakeClient) Update(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	if f, ok := c.updateFuncs[fmt.Sprintf("%s", object.Key)]; ok {
		return f(ctx, object)
	} else if f, ok := c.updateFuncs["default"]; ok {
		return f(ctx, object)
	}
	panic(fmt.Sprintf("Create called on unexpected object: %+v", object))
	return nil, nil

}
func (c *fakeClient) Apply(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	panic("should not be called")
	return nil, nil
}
func (c *fakeClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	if f, ok := c.deleteFuncs[fmt.Sprintf("%s", key)]; ok {
		return f(ctx, key, revision)
	} else if f, ok := c.deleteFuncs["default"]; ok {
		return f(ctx, key, revision)
	}

	panic(fmt.Sprintf("Delete called on unexpected object: %+v", key))
	return nil, nil
}
func (c *fakeClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	if f, ok := c.getFuncs[fmt.Sprintf("%s", key)]; ok {
		return f(ctx, key, revision)
	} else if f, ok := c.getFuncs["default"]; ok {
		return f(ctx, key, revision)
	}
	panic(fmt.Sprintf("Get called on unexpected object: %+v", key))
	return nil, nil
}
func (c *fakeClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	panic("should not be called")
	return nil
}
func (c *fakeClient) EnsureInitialized() error {
	panic("should not be called")
	return nil
}
func (c *fakeClient) Clean() error {
	panic("should not be called")
	return nil
}

func (c *fakeClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	if f, ok := c.listFuncs[fmt.Sprintf("%s", list)]; ok {
		return f(ctx, list, revision)
	} else if f, ok := c.listFuncs["default"]; ok {
		return f(ctx, list, revision)
	}
	panic(fmt.Sprintf("List called on unexpected object: %+v", list))
	return nil, nil
}

func (c *fakeClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	panic("should not be called")
	return nil, nil
}

var _ = testutils.E2eDatastoreDescribe("IPAM affine block allocation tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	log.SetLevel(log.DebugLevel)

	Context("IPAM block allocation race conditions", func() {

		var (
			bc           api.Client
			net          *cnet.IPNet
			ctx          context.Context
			hostA, hostB string
			fc           *fakeClient
			pools        *ipPoolAccessor
			rw           blockReaderWriter
			ic           *ipamClient
		)

		BeforeEach(func() {
			var err error

			// Make the client and clean the data store.
			bc, err = backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			bc.Clean()

			hostA = "hostA"
			hostB = "hostB"

			pools = &ipPoolAccessor{pools: map[string]pool{"10.0.0.0/26": {enabled: true}}}

			ctx = context.Background()

			_, net, err = cnet.ParseCIDR("10.0.0.0/26")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle multiple racing block affinity claims from different hosts", func() {
			By("setting up the client for the test", func() {
				// Pool has room for 16 blocks.
				pls := &ipPoolAccessor{pools: map[string]pool{"10.0.0.0/22": {enabled: true}}}
				rw = blockReaderWriter{client: bc, pools: pls}
				ic = &ipamClient{
					client:            bc,
					pools:             pls,
					blockReaderWriter: rw,
				}
			})

			By("assigning from host twice the number of available blocks all at once", func() {
				wg := sync.WaitGroup{}
				var testErr error

				for i := 0; i < 32; i++ {
					wg.Add(1)
					j := i
					go func() {
						defer GinkgoRecover()

						testhost := fmt.Sprintf("host-%d", j)
						ips, err := ic.autoAssign(ctx, 1, &testhost, nil, nil, 4, testhost, 0)
						if err != nil {
							log.WithError(err).Errorf("Auto assign failed for host %s", testhost)
							testErr = err
						}
						if len(ips) != 1 {
							// All hosts should get an IP, although some will be from non-affine blocks.
							log.WithError(err).Errorf("No IPs assigned for host %s", testhost)
							testErr = fmt.Errorf("No IPs assigned to %s", testhost)
						}

						wg.Done()
					}()
				}

				// Wait for allocations to finish, then assert success.
				wg.Wait()
				Expect(testErr).NotTo(HaveOccurred())
			})

			By("correctly allocating affinities", func() {
				affs, err := bc.List(ctx, model.BlockAffinityListOptions{}, "")
				Expect(err).NotTo(HaveOccurred())

				// Each block in the IP pool should have exactly one corresponding affinity.
				Expect(len(affs.KVPairs)).To(Equal(16))

				// Validate the affinities.
				for _, a := range affs.KVPairs {
					log.Infof("Validaing affinity: %+v", a)
					b, err := bc.Get(ctx, model.BlockKey{CIDR: a.Key.(model.BlockAffinityKey).CIDR}, "")
					Expect(err).NotTo(HaveOccurred())

					// Each affinity should match the block it points to.
					Expect(*b.Value.(*model.AllocationBlock).Affinity).To(Equal(fmt.Sprintf("host:%s", a.Key.(model.BlockAffinityKey).Host)))

					// Each affinity should be confirmed.
					Expect(a.Value.(*model.BlockAffinity).State).To(Equal(model.StateConfirmed))
				}
			})

			By("checking each allocated IP is within the correct block for that host", func() {
				// Iterate through all the hosts. If the host has an affine block,
				// make sure the IPs assigned to that host are within the block.
				for i := 0; i < 32; i++ {
					hostname := fmt.Sprintf("host-%d", i)
					affs, err := bc.List(ctx, model.BlockAffinityListOptions{Host: hostname}, "")
					Expect(err).NotTo(HaveOccurred())
					if len(affs.KVPairs) != 0 {
						// This host has an affine block. Check the IP allocation is from it.
						// Get the IPs assigned to this host.
						ips, err := ic.IPsByHandle(ctx, hostname)
						Expect(err).NotTo(HaveOccurred())
						Expect(len(ips)).To(Equal(1))

						// Expect that the IP address is within the affine block.
						cidr := affs.KVPairs[0].Key.(model.BlockAffinityKey).CIDR
						ip := ips[0]
						Expect(cidr.Contains(ip.IP)).To(BeTrue())
					}
				}
			})
		})

		It("should handle multiple racing block affinity claims from the same host", func() {
			By("setting up the client for the test", func() {
				// Pool has room for 16 blocks.
				pls := &ipPoolAccessor{pools: map[string]pool{"10.0.0.0/25": {enabled: true}}}
				rw = blockReaderWriter{client: bc, pools: pls}
				ic = &ipamClient{
					client:            bc,
					pools:             pls,
					blockReaderWriter: rw,
				}
			})

			By("assigning from host twice the number of available blocks all at once", func() {
				wg := sync.WaitGroup{}
				var testErr error

				for i := 0; i < 4; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()

						testhost := "single-host"
						ips, err := ic.autoAssign(ctx, 1, nil, nil, nil, 4, testhost, 0)
						if err != nil {
							log.WithError(err).Errorf("Auto assign failed for host %s", testhost)
							testErr = err
						}
						if len(ips) != 1 {
							// All hosts should get an IP, although some will be from non-affine blocks.
							log.WithError(err).Errorf("No IPs assigned for host %s", testhost)
							testErr = fmt.Errorf("No IPs assigned to %s", testhost)
						}

						wg.Done()
					}()
				}

				// Wait for allocations to finish, then assert success.
				wg.Wait()
				Expect(testErr).NotTo(HaveOccurred())
			})

			By("correctly allocating affinities", func() {
				affs, err := bc.List(ctx, model.BlockAffinityListOptions{}, "")
				Expect(err).NotTo(HaveOccurred())

				// Should only have a single affinity, for the test host.
				Expect(len(affs.KVPairs)).To(Equal(1))

				// For each affinity, expect the corresponding block to have the same affinity.
				for _, a := range affs.KVPairs {
					log.Infof("Validaing affinity: %+v", a)
					b, err := bc.Get(ctx, model.BlockKey{CIDR: a.Key.(model.BlockAffinityKey).CIDR}, "")
					Expect(err).NotTo(HaveOccurred())
					Expect(*b.Value.(*model.AllocationBlock).Affinity).To(Equal(fmt.Sprintf("host:%s", a.Key.(model.BlockAffinityKey).Host)))

					// Each affinity should be confirmed.
					Expect(a.Value.(*model.BlockAffinity).State).To(Equal(model.StateConfirmed))
				}
			})
		})

		It("should handle multiple racing claims for the same affinity", func() {
			By("setting up the client for the test", func() {
				// Pool has room for 16 blocks.
				pls := &ipPoolAccessor{pools: map[string]pool{"10.0.0.0/22": {enabled: true}}}
				rw = blockReaderWriter{client: bc, pools: pls}
				ic = &ipamClient{
					client:            bc,
					pools:             pls,
					blockReaderWriter: rw,
				}

				var err error
				_, net, err = cnet.ParseCIDR("10.0.0.0/22")
				Expect(err).NotTo(HaveOccurred())
			})

			By("racing to claim the same cidr on the same host", func() {
				wg := sync.WaitGroup{}
				var testErr error

				for i := 0; i < 4; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()

						testhost := "same-host"
						success, failed, err := ic.ClaimAffinity(ctx, *net, testhost)
						if err != nil {
							log.WithError(err).Errorf("ClaimAffinity failed for host %s", testhost)
							testErr = err
						}
						if len(failed) != 0 || len(success) != 16 {
							s := fmt.Sprintf("%s failed to claim affinity for %v, succeeded on %v", testhost, failed, success)
							log.WithError(err).Error(s)
							testErr = fmt.Errorf(s)
						}

						wg.Done()
					}()
				}

				// Wait for allocations to finish, then assert success.
				wg.Wait()
				Expect(testErr).NotTo(HaveOccurred())
			})

			By("correctly allocating affinities", func() {
				affs, err := bc.List(ctx, model.BlockAffinityListOptions{}, "")
				Expect(err).NotTo(HaveOccurred())

				// Each block in the IP pool should have exactly one corresponding affinity.
				Expect(len(affs.KVPairs)).To(Equal(16))

				// Validate the affinities.
				for _, a := range affs.KVPairs {
					log.Infof("Validaing affinity: %+v", a)
					b, err := bc.Get(ctx, model.BlockKey{CIDR: a.Key.(model.BlockAffinityKey).CIDR}, "")
					Expect(err).NotTo(HaveOccurred())

					// Each affinity should match the block it points to.
					Expect(*b.Value.(*model.AllocationBlock).Affinity).To(Equal(fmt.Sprintf("host:%s", a.Key.(model.BlockAffinityKey).Host)))

					// Each affinity should be confirmed.
					Expect(a.Value.(*model.BlockAffinity).State).To(Equal(model.StateConfirmed))
				}
			})

			By("racing to release the affinities", func() {
				wg := sync.WaitGroup{}
				var testErr error

				for i := 0; i < 4; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()

						testhost := "same-host"
						err := ic.ReleaseAffinity(ctx, *net, testhost)
						if err != nil {
							log.WithError(err).Errorf("Failed to release affinity for host %s", testhost)
							testErr = err
						}

						wg.Done()
					}()
				}

				// Wait for releases to finish, then assert success.
				wg.Wait()
				Expect(testErr).NotTo(HaveOccurred())
			})
		})

		It("should handle releasing an affinity while another claim has created the block", func() {
			// Tests the scenario where:
			// - hostA proc1 marks the affinity pending
			// - hostA proc1 creates the block
			// - hostA proc2 marks the affinity pending delete.
			// - hostA proc2 deletes the block
			// - hostA proc1 tries to confirm the affinity.
			// - hostA proc2 deletes the affinity (not included in test).
			// Expect that hostA proc 1 fails to confirm the affinity, leaving it in pending state.

			blockKVP := model.KVPair{
				Key:   model.BlockKey{CIDR: *net},
				Value: &model.AllocationBlock{},
			}
			affinityKVP := model.KVPair{
				Key:   model.BlockAffinityKey{Host: hostA, CIDR: *net},
				Value: &model.BlockAffinity{},
			}

			By("setting up the client for the test", func() {
				fc = newFakeClient()

				// Sneak in a side-effect such that when hostA-proc1 tries to create the block,
				// it actually simulates the other process marking the affinity as pending delete
				// and deletes the block.
				fc.createFuncs[fmt.Sprintf("%s", blockKVP.Key)] = func(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
					// Mark the affinity pending deletion.
					affinityKVP.Value.(*model.BlockAffinity).State = model.StatePendingDeletion
					_, err := bc.Apply(ctx, &affinityKVP)
					if err != nil {
						panic(err)
					}

					// Don't actually create the block (simulates another process deleting it), but return it
					// so the calling code thinks it succeeded.
					return object, nil
				}

				// For any other objects, just create/update them as normal.
				fc.createFuncs["default"] = func(ctx context.Context, object *model.KVPair) (*model.KVPair, error) { return bc.Create(ctx, object) }
				fc.updateFuncs["default"] = func(ctx context.Context, object *model.KVPair) (*model.KVPair, error) { return bc.Update(ctx, object) }
				fc.getFuncs["default"] = func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) { return bc.Get(ctx, k, r) }

				rw = blockReaderWriter{client: fc, pools: pools}
				ic = &ipamClient{
					client:            bc,
					pools:             pools,
					blockReaderWriter: rw,
				}
			})

			By("attempting to claim the block", func() {
				pa, err := rw.getPendingAffinity(ctx, hostA, *net)
				Expect(err).NotTo(HaveOccurred())

				config := IPAMConfig{}
				_, err = rw.claimAffineBlock(ctx, pa, config)
				Expect(err).NotTo(BeNil())

				// Should hit a resource update conflict.
				_, ok := err.(cerrors.ErrorResourceUpdateConflict)
				Expect(ok).To(BeTrue())
			})

			By("verifying that hostA was not able to claim the affinity as confirmed", func() {
				// On a real system, the releasing process would delete the affinity, but since this
				// is a mock the best we can do is assert that the affinity hasn't been confirmed by the
				// affinity claim request.
				a, err := bc.Get(ctx, affinityKVP.Key, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(a.Value.(*model.BlockAffinity).State).NotTo(Equal(model.StateConfirmed))
			})
		})

		It("should handle claiming an affinity while it is being deleted", func() {
			// Tests the scenario where:
			// - hostA proc1 marks the affinity pending deletion.
			// - hostA proc1 deletes the block.
			// - hostA proc2 marks the affinity pending.
			// - hostA proc2 creates the block.
			// - hostA proc1 tries to delete the affinity.

			var (
				blockKVP, affinityKVP model.KVPair
			)

			By("setting up the client for the test", func() {
				b := newBlock(*net)
				blockKVP = model.KVPair{
					Key:   model.BlockKey{CIDR: *net},
					Value: &b,
				}
				affinityKVP = model.KVPair{
					Key:   model.BlockAffinityKey{Host: hostA, CIDR: *net},
					Value: &model.BlockAffinity{},
				}

				fc = newFakeClient()

				// Sneak in a side-effect such that when hostA-proc1 tries to delete the block,
				// it actually simulates the other process marking the affinity as pending
				// and creating the block.
				fc.deleteFuncs[fmt.Sprintf("%s", blockKVP.Key)] = func(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
					// Mark the affinity pending.
					affinityKVP.Value.(*model.BlockAffinity).State = model.StatePending
					_, err := bc.Apply(ctx, &affinityKVP)
					if err != nil {
						panic(err)
					}

					// Delete the block, but then immediately create it again to simulate another process claiming
					// the block.
					kvp, err := bc.Delete(ctx, key, revision)
					bc.Create(ctx, kvp)
					return kvp, err
				}

				// For any other objects, just create/update/delete them as normal.
				fc.createFuncs["default"] = func(ctx context.Context, object *model.KVPair) (*model.KVPair, error) { return bc.Create(ctx, object) }
				fc.updateFuncs["default"] = func(ctx context.Context, object *model.KVPair) (*model.KVPair, error) { return bc.Update(ctx, object) }
				fc.deleteFuncs["default"] = func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) { return bc.Delete(ctx, k, r) }
				fc.getFuncs["default"] = func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) { return bc.Get(ctx, k, r) }

				rw = blockReaderWriter{client: fc, pools: pools}
				ic = &ipamClient{
					client:            bc,
					pools:             pools,
					blockReaderWriter: rw,
				}
			})

			By("creating the affinity and block", func() {
				_, err := bc.Create(ctx, &affinityKVP)
				Expect(err).To(BeNil())

				_, err = bc.Create(ctx, &blockKVP)
				Expect(err).To(BeNil())
			})

			By("attempting to release the block", func() {
				err := rw.releaseBlockAffinity(ctx, hostA, *net)
				Expect(err).NotTo(BeNil())

				// Should hit a resource update conflict.
				_, ok := err.(cerrors.ErrorResourceUpdateConflict)
				Expect(ok).To(BeTrue())
			})
		})

		It("should support multiple async block affinity claims on the same block", func() {
			affStrA := fmt.Sprintf("host:%s", hostA)
			affStrB := fmt.Sprintf("host:%s", hostB)

			// Configure a fake client such that we successfully create the
			// block affininty, but fail to create the actual block.
			fc := newFakeClient()

			// Creation function for a block affinity - actually create it.
			affKVP := &model.KVPair{
				Key:   model.BlockAffinityKey{Host: hostA, CIDR: *net},
				Value: model.BlockAffinity{},
			}
			affKVP2 := &model.KVPair{
				Key:   model.BlockAffinityKey{Host: hostB, CIDR: *net},
				Value: model.BlockAffinity{State: model.StateConfirmed},
			}

			fc.createFuncs[fmt.Sprintf("%s", affKVP.Key)] = func(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
				// Create the affinity for the other racing host.
				_, err := bc.Create(ctx, affKVP2)
				if err != nil {
					return nil, err
				}

				// And create it for the host requesting it.
				return bc.Create(ctx, object)
			}

			// Creation function for the actual block - should return an error indicating the block
			// was already taken by another host.
			b := newBlock(*net)
			b.Affinity = &affStrA
			b.StrictAffinity = false
			blockKVP := &model.KVPair{
				Key:   model.BlockKey{*net},
				Value: b.AllocationBlock,
			}

			b2 := newBlock(*net)
			b2.Affinity = &affStrB
			b2.StrictAffinity = false
			blockKVP2 := &model.KVPair{
				Key:   model.BlockKey{*net},
				Value: b2.AllocationBlock,
			}
			fc.createFuncs[fmt.Sprintf("%s", blockKVP.Key)] = func(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
				// Create the "stolen" affinity from the other racing host.
				_, err := bc.Create(ctx, blockKVP2)
				if err != nil {
					return nil, err
				}

				// Return that the object already exists.
				return nil, cerrors.ErrorResourceAlreadyExists{}
			}

			// Get function for the block. The first time, it should return nil to indicate nobody has the block. On subsequent calls,
			// return the real data from etcd representing the block belonging to another host.
			calls := 0
			fc.getFuncs[fmt.Sprintf("%s", blockKVP.Key)] = func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) {
				return func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) {
					calls = calls + 1

					if calls == 1 {
						// First time the block doesn't exist yet.
						return nil, cerrors.ErrorResourceDoesNotExist{}
					}
					return bc.Get(ctx, k, r)
				}(ctx, k, r)
			}

			fc.getFuncs["default"] = func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) {
				return bc.Get(ctx, k, r)
			}

			// Delete function for the affinity - this should fail, triggering the scenario under test where two hosts now think they
			// have affinity to the block.
			deleteCalls := 0
			fc.deleteFuncs[fmt.Sprintf("%s", affKVP.Key)] = func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) {
				return func(ctx context.Context, k model.Key, r string) (*model.KVPair, error) {
					deleteCalls = deleteCalls + 1

					if deleteCalls == 1 {
						// First time around, the delete fails - this triggers the scenario.
						return nil, fmt.Errorf("block affinity deletion failure")
					}

					// Subsequent calls succeed.
					return bc.Delete(ctx, k, r)
				}(ctx, k, r)
			}

			// List function should behave normally.
			fc.listFuncs["default"] = func(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
				return bc.List(ctx, list, revision)
			}

			// Create the block reader / writer which will simulate the failure scenario.
			rw = blockReaderWriter{client: fc, pools: pools}
			ic = &ipamClient{
				client:            bc,
				pools:             pools,
				blockReaderWriter: rw,
			}

			By("attempting to claim the block on multiple hosts at the same time", func() {
				ips, err := ic.autoAssign(ctx, 1, nil, nil, nil, 4, hostA, 0)

				// Shouldn't return an error.
				Expect(err).NotTo(HaveOccurred())

				// Should return a single IP.
				Expect(len(ips)).To(Equal(1))
			})

			By("checking that the other host has the affinity", func() {
				// The block should have the affinity field set properly.
				opts := model.BlockAffinityListOptions{Host: hostB}
				objs, err := rw.client.List(ctx, opts, "")
				Expect(err).NotTo(HaveOccurred())

				// Should be a single block affinity, assigned to the other host.
				Expect(len(objs.KVPairs)).To(Equal(1))
				Expect(objs.KVPairs[0].Value.(*model.BlockAffinity).State).To(Equal(model.StateConfirmed))
			})

			By("checking that the test host has a pending affinity", func() {
				// The block should have the affinity field set properly.
				opts := model.BlockAffinityListOptions{Host: hostA}
				objs, err := rw.client.List(ctx, opts, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(len(objs.KVPairs)).To(Equal(1))
				Expect(objs.KVPairs[0].Value.(*model.BlockAffinity).State).To(Equal(model.StatePending))
			})

			By("attempting to claim another address", func() {
				ips, err := ic.autoAssign(ctx, 1, nil, nil, nil, 4, hostA, 0)

				// Shouldn't return an error.
				Expect(err).NotTo(HaveOccurred())

				// Should return a single IP.
				Expect(len(ips)).To(Equal(1))
			})

			By("checking that the pending affinity was cleaned up", func() {
				// The block should have the affinity field set properly.
				opts := model.BlockAffinityListOptions{Host: hostA}
				objs, err := rw.client.List(ctx, opts, "")
				Expect(err).NotTo(HaveOccurred())

				// Should be a single block affinity, assigned to the other host.
				Expect(len(objs.KVPairs)).To(Equal(0))
			})
		})
	})

	Context("test claiming / releasing affinities", func() {
		var (
			rw   blockReaderWriter
			p    *ipPoolAccessor
			bc   api.Client
			ctx  context.Context
			host string
			net  *cnet.IPNet
		)

		BeforeEach(func() {
			var err error

			// Make the client and clean the data store.
			bc, err = backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			bc.Clean()

			// Create a fake client which we can use to simulate data store
			// error situations.
			// fc := newFakeClient()

			// Configure a BRW with a real datastore client.
			rw = blockReaderWriter{
				client: bc,
				pools:  p,
			}
			p = &ipPoolAccessor{pools: map[string]pool{}}
			ctx = context.Background()

			_, net, err = cnet.ParseCIDR("10.1.0.0/26")
			Expect(err).NotTo(HaveOccurred())

			host = "test-hostname"
		})

		It("should claim and release a block affinity", func() {
			By("claiming an affinity for a host", func() {
				pa, err := rw.getPendingAffinity(ctx, host, *net)
				Expect(err).NotTo(HaveOccurred())

				config := IPAMConfig{}
				_, err = rw.claimAffineBlock(ctx, pa, config)
				Expect(err).NotTo(HaveOccurred())
			})

			By("claiming the existing affinity again", func() {
				pa, err := rw.getPendingAffinity(ctx, host, *net)
				Expect(err).NotTo(HaveOccurred())

				config := IPAMConfig{}
				_, err = rw.claimAffineBlock(ctx, pa, config)
				Expect(err).NotTo(HaveOccurred())
			})

			By("checking the affinity exists", func() {
				k := model.BlockAffinityKey{Host: host, CIDR: *net}
				aff, err := bc.Get(ctx, k, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(aff.Value.(*model.BlockAffinity).State).To(Equal(model.StateConfirmed))
			})

			By("checking the block exists", func() {
				k := model.BlockKey{CIDR: *net}
				_, err := bc.Get(ctx, k, "")
				Expect(err).NotTo(HaveOccurred())
			})

			By("releasing the affinity", func() {
				err := rw.releaseBlockAffinity(ctx, host, *net)
				Expect(err).NotTo(HaveOccurred())
			})

			By("checking the affinity no longer exists", func() {
				k := model.BlockAffinityKey{Host: host, CIDR: *net}
				_, err := bc.Get(ctx, k, "")
				Expect(err).To(HaveOccurred())
			})

			By("checking the block no longer exists", func() {
				k := model.BlockKey{CIDR: *net}
				_, err := bc.Get(ctx, k, "")
				Expect(err).To(HaveOccurred())
			})

			By("releasing the affinity again", func() {
				err := rw.releaseBlockAffinity(ctx, host, *net)
				Expect(err).To(HaveOccurred())
				_, ok := err.(cerrors.ErrorResourceDoesNotExist)
				Expect(ok).To(BeTrue())
			})
		})
	})
})
