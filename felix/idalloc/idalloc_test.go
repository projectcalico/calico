// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package idalloc_test

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/idalloc"
)

const (
	collidingValue1 = "d17cf4aefa59f7de"
	collidingValue2 = "db841982800ad28c"
)

func TestIPSetAllocator(t *testing.T) {
	RegisterTestingT(t)
	ipSetAlloc := idalloc.New()

	const wellKnownID uint64 = 1
	ipSetAlloc.ReserveWellKnownID("well-known-purpose", wellKnownID)
	Expect(func() { ipSetAlloc.ReserveWellKnownID("other-purpose", wellKnownID) }).To(Panic())
	Expect(func() { ipSetAlloc.ReserveWellKnownID("well-known-purpose", wellKnownID+1) }).To(Panic())

	Expect(ipSetAlloc.GetOrAlloc("foobar")).To(Equal(ipSetAlloc.GetOrAlloc("foobar")),
		"Same input should give same output")
	Expect(ipSetAlloc.GetOrAlloc("foobar")).NotTo(Equal(ipSetAlloc.GetOrAlloc("baz")),
		"Different input should not give same output")

	freshIPSetAlloc := idalloc.New()
	id1 := ipSetAlloc.GetOrAlloc(collidingValue1)
	id2 := freshIPSetAlloc.GetOrAlloc(collidingValue2)
	Expect(id1).To(Equal(id2), "Saved collision no longer collides; maybe the hash algorithm was changed?")

	id2a := ipSetAlloc.GetOrAlloc(collidingValue2)
	Expect(id2a).NotTo(Equal(id1),
		"Same allocator should give different outputs even for colliding inputs")
	Expect(freshIPSetAlloc.GetOrAlloc(collidingValue1)).NotTo(Equal(id1),
		"Same allocator should give different outputs even for colliding inputs")

	id3 := ipSetAlloc.GetAndRelease(collidingValue1)
	Expect(id3).To(Equal(id1), "GetAndRelease should return the correct ID")

	Expect(ipSetAlloc.GetOrAlloc(collidingValue2)).To(Equal(id2a),
		"Removing first value shouldn't affect stored hash")

	id4 := ipSetAlloc.GetAndRelease(collidingValue2)
	Expect(id4).To(Equal(id2a), "GetAndRelease should return the correct ID")

	Expect(ipSetAlloc.GetOrAlloc(collidingValue2)).To(Equal(id2),
		"After clearing out all state, re-adding second value should return the n=0 hash")
}
