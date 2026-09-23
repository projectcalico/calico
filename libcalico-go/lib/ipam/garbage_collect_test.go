// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("GarbageCollectColdIPs", func() {
	var (
		ctx      context.Context
		fc       *fakeClient
		ic       *ipamClient
		blockKVP *model.KVPair
		updated  []*model.KVPair
		coldOrd  = 31
		liveOrd  = 52
		blockUID = types.UID("block-uid")
		blockRev = "block-revision"
	)

	BeforeEach(func() {
		ctx = context.Background()

		// Build a block with one cold (released long ago) allocation and one
		// live allocation that should be left untouched.
		tb := makeTestBlock()
		tb.allocateAttrib([]int{coldOrd}, model.AllocationAttribute{
			HandleID:   new("cold"),
			ReleasedAt: new(v1.NewTime(time.Now().Add(-time.Hour))),
		})
		tb.allocate([]int{liveOrd}, "live")

		blockKVP = &model.KVPair{
			Key:      model.BlockKey{CIDR: model.PrefixFromIPNet(tb.CIDR)},
			Value:    tb.AllocationBlock,
			Revision: blockRev,
			UID:      &blockUID,
		}

		// Capture everything written through Update.
		updated = nil
		fc = newFakeClient()
		fc.updateFuncs["default"] = func(_ context.Context, object *model.KVPair) (*model.KVPair, error) {
			updated = append(updated, object)
			return object, nil
		}

		// GarbageCollectColdIPs only exercises the blockReaderWriter's client.
		ic = &ipamClient{blockReaderWriter: blockReaderWriter{client: fc}}
	})

	It("writes back the GC'd block preserving the original Revision and UID", func() {
		err := ic.GarbageCollectColdIPs(ctx, &IPAMConfig{IPCooldownSeconds: 30}, blockKVP)
		Expect(err).NotTo(HaveOccurred())

		// The block must actually be written back.
		Expect(updated).To(HaveLen(1), "expected the GC'd block to be written back")
		written := updated[0]

		// The write must carry the original Revision and UID so the update is a
		// safe compare-and-swap against the block we read.
		Expect(written.Key).To(Equal(blockKVP.Key))
		Expect(written.Revision).To(Equal(blockRev))
		Expect(written.UID).To(Equal(&blockUID))

		// The written value must be the *GC'd* block, not the original: the cold
		// ordinal is now unallocated and its attribute removed, while the live
		// allocation is retained.
		wb := written.Value.(*model.AllocationBlock)
		Expect(wb.Allocations[coldOrd]).To(BeNil(), "cold IP should be deallocated")
		Expect(wb.Allocations[liveOrd]).NotTo(BeNil(), "live IP should be retained")
		Expect(wb.Unallocated).To(ContainElement(coldOrd))
		Expect(wb.Attributes).To(HaveLen(1), "the cold allocation's attribute should be removed")

		// Sanity: the caller's original KVPair must be untouched.
		ob := blockKVP.Value.(*model.AllocationBlock)
		Expect(ob.Allocations[coldOrd]).NotTo(BeNil(), "original block must not be mutated")
		Expect(ob.Attributes).To(HaveLen(2))
	})

	It("does not write the block when there is nothing to collect", func() {
		// With a long cooldown the released IP is still cooling down, so no
		// garbage collection occurs and no write should happen.
		err := ic.GarbageCollectColdIPs(ctx, &IPAMConfig{IPCooldownSeconds: 100000}, blockKVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeEmpty(), "no write expected when nothing is collected")
	})
})
