// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package migrator

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("UT for checking the version for migration.", func() {

	DescribeTable("Checking canMigrate.",
		func(ver string, result bool, resultHasError bool) {
			yes, err := versionRequiresMigration(ver)

			if resultHasError {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).NotTo(HaveOccurred())
				Expect(yes).To(Equal(result))
			}
		},

		Entry("Expect v2.6.4 to migrate", "v2.6.4", true, false),
		Entry("Expect v2.6.4-rc1 to migrate", "v2.6.4-rc1", true, false),
		Entry("Expect v2.6.4-15-g0986c6cd to migrate", "v2.6.4-15-g0986c6cd", true, false),
		Entry("Expect v2.6.5 to migrate", "v2.6.5", true, false),
		Entry("Expect v2.6.5-rc1 to migrate", "v2.6.5-rc1", true, false),
		Entry("Expect v2.7.0 to migrate", "v2.7.0", true, false),
		Entry("Expect v2.7.0-rc1 to migrate", "v2.7.0-rc1", true, false),
		Entry("Expect v2.6.3 to not migrate", "v2.6.3", false, true),
		Entry("Expect v2.6.3-rc1 to not migrate", "v2.6.3-rc1", false, true),
		Entry("Expect v2.6.3-15-g0986c6cd to not migrate", "v2.6.3-15-g0986c6cd", false, true),
		Entry("Expect v2.6.x-deadbeef to not migrate", "v2.6.x-deadbeef", false, true),
		Entry("Expect v3.0 to not migrate", "v3.0", false, true),
		Entry("Expect v3.0.0 to not migrate", "v3.0.0", false, false),
		Entry("Expect v3.0.0-beta1 to not migrate", "v3.0.0-beta1", false, false),
		Entry("Expect v3.0.0-0 to not migrate", "v3.0.0-0", false, false),
		Entry("Expect v3.0.0-a to not migrate", "v3.0.0-a", false, false),
		Entry("Expect v3.0.0-beta1-128-g1caef47d to not migrate", "v3.0.0-beta1-128-g1caef47d", false, false),
		Entry("Expect master to not migrate", "master", false, true),
		Entry("Expect empty string to not migrate", "", false, true),
		Entry("Expect garbage to not migrate", "garbage", false, true),
		Entry("Expect 1.2.3.4.5 to not migrate", "1.2.3.4.5", false, true),
	)
})
