// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestByteArrayToByteArrayMap(t *testing.T) {
	RegisterTestingT(t)

	m := NewByteArrayToByteArrayMap(2, 4)

	Expect(m.Get([]byte{1, 2})).To(BeNil(), "New map should not contain a value")
	m.Set([]byte{1, 2}, []byte{1, 2, 3, 4})
	Expect(m.Get([]byte{1, 2})).To(Equal([]byte{1, 2, 3, 4}), "Map should contain set value")
	m.Set([]byte{1, 2}, []byte{1, 2, 3, 5})
	Expect(m.Get([]byte{1, 2})).To(Equal([]byte{1, 2, 3, 5}), "Map should record updates")
	m.Set([]byte{3, 4}, []byte{1, 2, 3, 6})
	Expect(m.Get([]byte{3, 4})).To(Equal([]byte{1, 2, 3, 6}), "Map should record updates")

	seenValues := map[string][]byte{}
	m.Iter(func(k, v []byte) {
		Expect(k).To(HaveLen(2))
		Expect(v).To(HaveLen(4))
		seenValues[string(k)] = v
	})
	Expect(seenValues).To(Equal(map[string][]byte{
		string([]byte{1, 2}): {1, 2, 3, 5},
		string([]byte{3, 4}): {1, 2, 3, 6},
	}))

	m.Delete([]byte{1, 2})
	Expect(m.Get([]byte{1, 2})).To(BeNil(), "Deletion should remove the value")
}
