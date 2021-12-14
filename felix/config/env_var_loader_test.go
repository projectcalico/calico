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

package config_test

import (
	"github.com/projectcalico/calico/felix/config"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Environment parameter parsing",
	func(environ []string, expected map[string]string) {
		actual := config.LoadConfigFromEnvironment(environ)
		Expect(actual).To(Equal(expected))
	},
	Entry("Empty", []string{}, map[string]string{}),
	Entry("Malformed", []string{"foobar"}, map[string]string{}),
	Entry("Mainline",
		[]string{
			"FeLIX_LoGSEVERITYSCREEN=INFO",
			"FeLIX_FOO=bar=baz",
			"PATH=/usr/bin:/bin/sbin",
		},
		map[string]string{
			"logseverityscreen": "INFO",
			"foo":               "bar=baz",
		}),
)
