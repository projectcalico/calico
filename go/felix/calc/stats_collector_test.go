// Copyright (c) 2016 Tigera, Inc. All rights reserved.
//
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

package calc_test

import (
	"errors"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/felix/go/felix/calc"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	. "github.com/projectcalico/libcalico-go/lib/backend/model"
)

var (
	localHostIPKey  = HostIPKey{localHostname}
	remoteHostIPKey = HostIPKey{remoteHostname}
)

var _ = Describe("Stats collector", func() {
	var sc *StatsCollector
	var lastStatsUpdate *StatsUpdate
	var updateErr error

	BeforeEach(func() {
		sc = NewStatsCollector(func(upd StatsUpdate) error {
			lastStatsUpdate = &upd
			return updateErr
		})
		lastStatsUpdate = nil
		updateErr = nil
	})

	Describe("before in-sync", func() {
		It("should do nothing on IP update", func() {
			sc.OnUpdate(api.Update{
				KVPair{Key: localHostIPKey},
				api.UpdateTypeKVNew,
			})
			Expect(lastStatsUpdate).To(BeNil())
		})
		It("should do nothing on workload update", func() {
			sc.OnUpdate(api.Update{
				KVPair{Key: localWlEpKey1},
				api.UpdateTypeKVNew,
			})
			Expect(lastStatsUpdate).To(BeNil())
		})
	})

	Describe("after in-sync", func() {
		BeforeEach(func() {
			sc.OnStatusUpdate(api.InSync)
		})
		It("should count an IP create", func() {
			sc.OnUpdate(api.Update{KVPair{Key: localHostIPKey}, api.UpdateTypeKVNew})
			Expect(*lastStatsUpdate).To(Equal(StatsUpdate{NumHosts: 1}))
		})
		It("should count a workload create", func() {
			sc.OnUpdate(api.Update{KVPair{Key: localWlEpKey1}, api.UpdateTypeKVNew})
			Expect(*lastStatsUpdate).To(Equal(StatsUpdate{
				NumHosts:             1,
				NumWorkloadEndpoints: 1,
			}))
		})
		It("should count a host endpoint create", func() {
			sc.OnUpdate(api.Update{KVPair{Key: hostEpWithNameKey}, api.UpdateTypeKVNew})
			Expect(*lastStatsUpdate).To(Equal(StatsUpdate{
				NumHosts:         1,
				NumHostEndpoints: 1,
			}))
		})
		It("should count a host config create", func() {
			sc.OnUpdate(api.Update{KVPair{Key: HostConfigKey{localHostname, "foo"}}, api.UpdateTypeKVNew})
			Expect(*lastStatsUpdate).To(Equal(StatsUpdate{
				NumHosts: 1,
			}))
		})

		It("should ignore malformed updates", func() {
			lastStatsUpdate = nil
			sc.OnUpdate(api.Update{KVPair{}, api.UpdateTypeKVNew})
			Expect(lastStatsUpdate).To(BeNil())
		})
		It("should ignore idempotent updates", func() {
			sc.OnUpdate(api.Update{KVPair{Key: localHostIPKey}, api.UpdateTypeKVNew})
			Expect(*lastStatsUpdate).To(Equal(StatsUpdate{NumHosts: 1}))
			lastStatsUpdate = nil
			sc.OnUpdate(api.Update{KVPair{Key: localHostIPKey}, api.UpdateTypeKVUpdated})
			Expect(lastStatsUpdate).To(BeNil())
		})
		It("should handle errors from the callback", func() {
			updateErr = errors.New("dummy error")
			sc.OnUpdate(api.Update{KVPair{Key: localHostIPKey}, api.UpdateTypeKVNew})
			Expect(*lastStatsUpdate).To(Equal(StatsUpdate{NumHosts: 1}))
			lastStatsUpdate = nil
			// Now send an update, which would normally not call the callback.
			sc.OnUpdate(api.Update{KVPair{Key: localHostIPKey}, api.UpdateTypeKVUpdated})
			Expect(*lastStatsUpdate).To(Equal(StatsUpdate{NumHosts: 1}))
		})

		Describe("after adding a local and remote workload", func() {
			BeforeEach(func() {
				sc.OnUpdate(api.Update{KVPair{Key: localWlEpKey1}, api.UpdateTypeKVNew})
				sc.OnUpdate(api.Update{KVPair{Key: remoteWlEpKey1}, api.UpdateTypeKVNew})
			})
			It("should say there are two hosts", func() {
				Expect(*lastStatsUpdate).To(Equal(StatsUpdate{
					NumHosts:             2,
					NumWorkloadEndpoints: 2,
				}))
			})
			Describe("after updating one workload", func() {
				BeforeEach(func() {
					sc.OnUpdate(api.Update{KVPair{Key: localWlEpKey1}, api.UpdateTypeKVUpdated})
				})
				It("should say there are two hosts", func() {
					Expect(*lastStatsUpdate).To(Equal(StatsUpdate{
						NumHosts:             2,
						NumWorkloadEndpoints: 2,
					}))
				})
				Describe("after removing one workload", func() {
					BeforeEach(func() {
						sc.OnUpdate(api.Update{KVPair{Key: localWlEpKey1}, api.UpdateTypeKVDeleted})
					})
					It("should say there is one host", func() {
						Expect(*lastStatsUpdate).To(Equal(StatsUpdate{
							NumHosts:             1,
							NumWorkloadEndpoints: 1,
						}))
					})
					Describe("after removing other workload", func() {
						BeforeEach(func() {
							sc.OnUpdate(api.Update{KVPair{Key: remoteWlEpKey1}, api.UpdateTypeKVDeleted})
						})
						It("should say there are no hosts", func() {
							Expect(*lastStatsUpdate).To(Equal(StatsUpdate{}))
						})
					})
				})
			})
		})
	})
})
