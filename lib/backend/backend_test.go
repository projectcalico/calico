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

	"github.com/projectcalico/libcalico-go/lib/backend/etcd"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

// Setting localhost as the etcd endpoint location since that's where `make run-etcd` runs it.
var etcdConfig = &etcd.EtcdConfig{
	EtcdEndpoints: "http://127.0.0.1:2379",
}

var _ = Describe("Backend tests", func() {
	etcdClient, _ := etcd.NewEtcdClient(etcdConfig)

	var (
		block model.KVPair
		err   error
	)

	BeforeEach(func() {
		testutils.CleanEtcd()

		block = model.KVPair{
			Key: model.BlockKey{
				CIDR: testutils.MustParseNetwork("10.0.0.0/26"),
			},
			Value: model.AllocationBlock{
				CIDR: testutils.MustParseNetwork("10.0.0.0/26"),
			},
		}

		_, err = etcdClient.Create(&block)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("Create", func() {

		It("persists a new kv pair", func() {
			kv, err := etcdClient.Get(block.Key)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(*model.AllocationBlock).CIDR
			persitedCIRD := block.Value.(model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIRD))
		})

		It("sets revision field", func() {
			kv, err := etcdClient.Get(block.Key)

			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Revision).NotTo(BeNil())
		})

	})

	Describe("Update", func() {

		It("updates a kv pair", func() {
			block.Value = model.AllocationBlock{
				CIDR: testutils.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := etcdClient.Update(&block)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(model.AllocationBlock).CIDR
			persitedCIRD := block.Value.(model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIRD))
		})

		It("sets revision field", func() {
			kv, err := etcdClient.Update(&block)

			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Revision).NotTo(BeNil())
		})

		It("validates revision field", func() {
			block.Revision = uint64(1000)
			_, err := etcdClient.Update(&block)
			Expect(err).To(HaveOccurred())
		})

	})

	Describe("Apply", func() {

		It("updates a kv pair", func() {
			block.Value = model.AllocationBlock{
				CIDR: testutils.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := etcdClient.Apply(&block)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(model.AllocationBlock).CIDR
			persitedCIRD := block.Value.(model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIRD))
		})

		It("creates a kv pair", func() {
			block.Key = model.BlockKey{
				CIDR: testutils.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := etcdClient.Apply(&block)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(model.AllocationBlock).CIDR
			persitedCIRD := block.Value.(model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIRD))
		})

		It("sets revision field", func() {
			block.Value = model.AllocationBlock{
				CIDR: testutils.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := etcdClient.Apply(&block)

			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Revision).NotTo(BeNil())
		})

		It("validates revision field", func() {
			block.Revision = uint64(1000)
			_, err := etcdClient.Apply(&block)
			Expect(err).NotTo(HaveOccurred())
		})

	})

	Describe("Delete", func() {

		It("deletes the kv pair", func() {
			err := etcdClient.Delete(&block)
			Expect(err).NotTo(HaveOccurred())

			_, err = etcdClient.Get(block.Key)
			Expect(err).To(HaveOccurred())
		})

	})

	Describe("List", func() {
		blockListOpt := model.BlockListOptions{
			IPVersion: 4,
		}

		bl, err := etcdClient.List(blockListOpt)

		for _, blv := range bl {
			It("sets revision field", func() {
				Expect(err).NotTo(HaveOccurred())
				Expect(blv.Revision).NotTo(BeNil())
			})
		}

	})

})
