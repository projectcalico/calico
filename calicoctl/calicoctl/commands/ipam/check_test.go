// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("validateBlock", func() {
	cidr := net.MustParseCIDR("10.0.0.0/30")

	It("returns no error for an empty block", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).To(Succeed())
	})

	It("returns an error when an allocation references an invalid attr index", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{new(99), nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("allocation 0 indexes a nonexistent attribute 99"))
	})

	It("returns an error when an allocation references a negative attr index", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{new(-1), nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("allocation 0 indexes a nonexistent attribute -1"))
	})

	It("returns an error when an attribute is not pointed to by an allocation", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{HandleID: new("uhoh")},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("attribute index 0 exists but is not indexed by an allocation"))
	})

	It("returns an error when an an attribute has ReleasedAt in the future", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{new(0), nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{ReleasedAt: new(v1.NewTime(time.Now().Add(time.Minute)))},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("attribute index 0 has releasedAt in the future, suggesting clock skew"))
	})

	It("returns an error when an ordinal appears twice in Unallocated", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("ordinal 1 appears more than once in Unallocated array"))
	})

	It("returns an error when an allocated ordinal appears in Unallocated", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, new(0), nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{HandleID: new("allocated")},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("ordinal 1 is allocated but appears in Unallocated"))
	})

	It("returns an error when an unallocated ordinal is too large", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 2, 3, 99},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("ordinal 99 appears in the Unallocated array but is out of the block"))
	})

	It("returns an error if size of allocated an unallocated does not sum to NumAddresses", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, new(0), new(0), nil},
			Unallocated: []int{0},
			Attributes: []model.AllocationAttribute{
				{HandleID: new("hello")},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("expected 4 addresses in this block, but Unallocated (1) + Allocated (2) = 3"))
	})
})
