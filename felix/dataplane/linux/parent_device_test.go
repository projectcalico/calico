// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type parentDeviceChanged bool

func (c parentDeviceChanged) OnParentDeviceUpdate(string) bool {
	return bool(c)
}

var _ = Describe("Parent device updates", func() {
	It("should mark the dataplane dirty only when the parent device changes", func() {
		dp := &InternalDataplane{}

		dp.onParentDeviceUpdate(parentDeviceChanged(true), "eth0")
		Expect(dp.dataplaneNeedsSync).To(BeTrue())

		dp.dataplaneNeedsSync = false
		dp.onParentDeviceUpdate(parentDeviceChanged(false), "eth0")
		Expect(dp.dataplaneNeedsSync).To(BeFalse())
	})
})
