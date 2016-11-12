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

package backend_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	"github.com/projectcalico/libcalico-go/lib/backend/etcd"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

// Setting localhost as the etcd endpoint location since that's where `make run-etcd` runs it.
var etcdConfig = &etcd.EtcdConfig{
	EtcdEndpoints: "http://127.0.0.1:2379",
}

var _ = Describe("Backend tests", func() {
	Describe("etcd GET/List Revision values", func() {
		testutils.CleanEtcd()

		etcdClient, _ := etcd.NewEtcdClient(etcdConfig)

		Context("CREATE a Block", func() {
			block := &model.KVPair{
				Key: model.BlockKey{
					CIDR: testutils.MustParseCIDR("10.0.0.0/26"),
				},
				Value: model.AllocationBlock{
					CIDR: testutils.MustParseCIDR("10.0.0.0/26"),
				},
			}

			_, cErr := etcdClient.Create(block)

			It("should succeed without an error", func() {
				Expect(cErr).NotTo(HaveOccurred())
			})
		})

		Context("GET BlockKey", func() {
			key := model.BlockKey{
				CIDR: testutils.MustParseCIDR("10.0.0.0/26"),
			}
			b, bErr := etcdClient.Get(key)
			It("Revision field should not be nil", func() {
				Expect(bErr).NotTo(HaveOccurred())
				Expect(b.Revision).NotTo(BeNil())
			})
		})

		Context("LIST BlockKey", func() {
			blockListOpt := model.BlockListOptions{
				IPVersion: 4,
			}
			bl, blErr := etcdClient.List(blockListOpt)
			for _, blv := range bl {
				It("Revision field should not be nil", func() {
					Expect(blErr).NotTo(HaveOccurred())
					Expect(blv.Revision).NotTo(BeNil())
				})
			}
		})
	})
})
