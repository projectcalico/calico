// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package builder

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Release version determination tests", func(prev, expected string, expectErr bool) {
	r := &ReleaseBuilder{}
	out, err := r.determineReleaseVersion(prev)
	if expectErr {
		Expect(err).To(HaveOccurred())
	} else {
		Expect(err).NotTo(HaveOccurred())
	}
	Expect(out).To(Equal(expected))
},

	Entry("from a -0.dev tag", "v3.22.0-0.dev", "v3.22.0", false),
	Entry("from a .0 patch release", "v3.22.0", "v3.22.1", false),
	Entry("from a .10 patch release", "v3.22.10", "v3.22.11", false),
	Entry("from a random string", "ahg5da29a", "", true),
)
