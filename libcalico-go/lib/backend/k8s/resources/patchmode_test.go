// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package resources

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PatchMode", func() {
	Context("PatchMode", func() {

		It("patchMode round-trips", func() {
			ctx := ContextWithPatchMode(context.Background(), PatchModeCNI)
			patchMode := PatchModeOf(ctx)
			Expect(patchMode).To(Equal(PatchModeCNI))
		})

		It("patchMode handles unspecified value", func() {
			ctx := context.Background()
			patchMode := PatchModeOf(ctx)
			Expect(patchMode).To(Equal(PatchModeUnspecified))
		})

		It("patchMode handles unexpected value", func() {
			ctx := ContextWithPatchMode(context.Background(), "patchModeSomething")
			patchMode := PatchModeOf(ctx)
			Expect(patchMode).To(Equal(PatchModeUnspecified))
		})
	})
})
