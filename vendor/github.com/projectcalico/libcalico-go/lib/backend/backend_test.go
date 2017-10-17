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

package backend_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("Backend tests", testutils.DatastoreEtcdV2, func(config api.CalicoAPIConfig) {
	var (
		block  model.KVPair
		client bapi.Client
		err    error
	)

	BeforeEach(func() {
		c := testutils.CreateCleanClient(config)
		client = c.Backend
		block = model.KVPair{
			Key: model.BlockKey{
				CIDR: net.MustParseNetwork("10.0.0.0/26"),
			},
			Value: &model.AllocationBlock{
				CIDR: net.MustParseNetwork("10.0.0.0/26"),
			},
		}

		_, err = client.Create(&block)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("Create", func() {

		It("persists a new kv pair", func() {
			kv, err := client.Get(block.Key)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(*model.AllocationBlock).CIDR
			persitedCIDR := block.Value.(*model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIDR))
		})

		It("sets revision field", func() {
			kv, err := client.Get(block.Key)

			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Revision).NotTo(BeNil())
		})

	})

	Describe("Update", func() {

		It("updates a kv pair", func() {
			block.Value = &model.AllocationBlock{
				CIDR: net.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := client.Update(&block)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(*model.AllocationBlock).CIDR
			persitedCIDR := block.Value.(*model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIDR))
		})

		It("sets revision field", func() {
			kv, err := client.Update(&block)

			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Revision).NotTo(BeNil())
		})

		It("validates revision field", func() {
			block.Revision = uint64(1000)
			_, err := client.Update(&block)
			Expect(err).To(HaveOccurred())
		})

	})

	Describe("Apply", func() {

		It("updates a kv pair", func() {
			block.Value = &model.AllocationBlock{
				CIDR: net.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := client.Apply(&block)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(*model.AllocationBlock).CIDR
			persitedCIDR := block.Value.(*model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIDR))
		})

		It("creates a kv pair", func() {
			block.Key = model.BlockKey{
				CIDR: net.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := client.Apply(&block)
			Expect(err).NotTo(HaveOccurred())

			expectedCIDR := kv.Value.(*model.AllocationBlock).CIDR
			persitedCIDR := block.Value.(*model.AllocationBlock).CIDR

			Expect(expectedCIDR).To(Equal(persitedCIDR))
		})

		It("sets revision field", func() {
			block.Value = &model.AllocationBlock{
				CIDR: net.MustParseNetwork("192.168.0.0/26"),
			}

			kv, err := client.Apply(&block)

			Expect(err).NotTo(HaveOccurred())
			Expect(kv.Revision).NotTo(BeNil())
		})

		It("validates revision field", func() {
			block.Revision = uint64(1000)
			_, err := client.Apply(&block)
			Expect(err).NotTo(HaveOccurred())
		})

	})

	Describe("Delete", func() {

		It("deletes the kv pair", func() {
			err := client.Delete(&block)
			Expect(err).NotTo(HaveOccurred())

			_, err = client.Get(block.Key)
			Expect(err).To(HaveOccurred())
		})

	})

	Describe("List", func() {
		blockListOpt := model.BlockListOptions{
			IPVersion: 4,
		}

		It("List", func() {
			bl, err := client.List(blockListOpt)
			Expect(err).NotTo(HaveOccurred())

			for _, blv := range bl {
				Expect(blv.Revision).NotTo(BeNil())
			}
		})
	})
})
