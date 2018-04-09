//+build windows

// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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

package windataplane_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/dataplane/windows"
)

var _ = Describe("Constructor test", func() {
	var configParams *config.Config
	var dpConfig windataplane.Config

	JustBeforeEach(func() {
		configParams = config.New()

		dpConfig = windataplane.Config{
			IPv6Enabled: configParams.Ipv6Support,
		}
	})

	It("should be constructable", func() {
		var dp = windataplane.NewWinDataplaneDriver(dpConfig)
		Expect(dp).ToNot(BeNil())
	})
})
