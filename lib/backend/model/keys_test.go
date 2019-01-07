// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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

package model_test

import (
	. "github.com/projectcalico/libcalico-go/lib/backend/model"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Describe("keys with region component", func() {

	It("should not parse workload endpoint status with wrong region", func() {
		Expect((WorkloadEndpointStatusListOptions{Region: "Asia"}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/workload/o1/w1/endpoint/e1")).To(BeNil())
	})

	It("should not parse active Felix status with wrong region", func() {
		Expect((ActiveStatusReportListOptions{Region: "Asia"}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/status")).To(BeNil())
	})

	It("should not parse last reported Felix status with wrong region", func() {
		Expect((LastStatusReportListOptions{Region: "Asia"}).KeyFromDefaultPath("/calico/felix/v2/region-Europe/host/h1/last_reported_status")).To(BeNil())
	})

	It("should generate correct path for a Felix status key with no region", func() {
		Expect(KeyToDefaultPath(ActiveStatusReportKey{Hostname: "h1"})).To(Equal("/calico/felix/v2/no-region/host/h1/status"))
	})

	It("should generate correct path for a workload status key with no region", func() {
		Expect(KeyToDefaultPath(WorkloadEndpointStatusKey{Hostname: "h1", EndpointID: "e1", WorkloadID: "w1", OrchestratorID: "o1"})).To(Equal("/calico/felix/v2/no-region/host/h1/workload/o1/w1/endpoint/e1"))
	})
})

var _ = DescribeTable(
	"key parsing",
	func(strKey string, expected Key, shouldFail bool) {
		key := KeyFromDefaultPath(strKey)
		if shouldFail {
			Expect(key).To(BeNil())
		} else {
			Expect(key).To(Equal(expected))
			serialized, err := KeyToDefaultPath(expected)
			Expect(err).ToNot(HaveOccurred())
			Expect(serialized).To(Equal(strKey))
		}
	},
	Entry(
		"profile rules with a /",
		"/calico/v1/policy/profile/foo%2fbar/rules",
		ProfileRulesKey{ProfileKey: ProfileKey{Name: "foo/bar"}},
		false,
	),
	Entry(
		"profile tags with a /",
		"/calico/v1/policy/profile/foo%2fbar/tags",
		ProfileTagsKey{ProfileKey: ProfileKey{Name: "foo/bar"}},
		false,
	),
	Entry(
		"profile labels with a /",
		"/calico/v1/policy/profile/foo%2fbar/labels",
		ProfileLabelsKey{ProfileKey: ProfileKey{Name: "foo/bar"}},
		false,
	),
	Entry(
		"policy with a /",
		"/calico/v1/policy/tier/default/policy/biff%2fbop",
		PolicyKey{Name: "biff/bop"},
		false,
	),
	Entry(
		"workload with a /",
		"/calico/v1/host/foobar/workload/open%2fstack/work%2fload/endpoint/end%2fpoint",
		WorkloadEndpointKey{
			Hostname:       "foobar",
			OrchestratorID: "open/stack",
			WorkloadID:     "work/load",
			EndpointID:     "end/point",
		},
		false,
	),
	Entry(
		"host endpoint with a /",
		"/calico/v1/host/foobar/endpoint/end%2fpoint",
		HostEndpointKey{
			Hostname:   "foobar",
			EndpointID: "end/point",
		},
		false,
	),
	Entry(
		"host IP",
		"/calico/v1/host/foobar/bird_ip",
		HostIPKey{Hostname: "foobar"},
		false,
	),
	Entry(
		"IP pool",
		"/calico/v1/ipam/v4/pool/10.0.0.0-8",
		IPPoolKey{CIDR: mustParseCIDR("10.0.0.0/8")},
		false,
	),
	Entry(
		"poorly formated IP pool",
		"/calico/v1/ipam/v4/pool/577559",
		nil,
		true,
	),
	Entry(
		"global felix config",
		"/calico/v1/config/foo",
		GlobalConfigKey{Name: "foo"},
		false,
	),
	Entry(
		"host config",
		"/calico/v1/host/hostname/config/foo",
		HostConfigKey{Hostname: "hostname", Name: "foo"},
		false,
	),
	Entry(
		"network set",
		"/calico/v1/netset/netsetname",
		NetworkSetKey{Name: "netsetname"},
		false,
	),
	Entry(
		"ready flag",
		"/calico/v1/Ready",
		ReadyFlagKey{},
		false,
	),
	Entry(
		"workload endpoint status",
		"/calico/felix/v2/region-Europe/host/h1/workload/o1/w1/endpoint/e1",
		WorkloadEndpointStatusKey{Hostname: "h1", EndpointID: "e1", Region: "Europe", WorkloadID: "w1", OrchestratorID: "o1"},
		false,
	),
	Entry(
		"Felix active status",
		"/calico/felix/v2/region-Europe/host/h1/status",
		ActiveStatusReportKey{Hostname: "h1", Region: "Europe"},
		false,
	),
	Entry(
		"Felix last reported status",
		"/calico/felix/v2/region-Europe/host/h1/last_reported_status",
		LastStatusReportKey{Hostname: "h1", Region: "Europe"},
		false,
	),
)

var _ = DescribeTable(
	"value parsing",
	func(key Key, rawVal string, expectedVal interface{}) {
		val, err := ParseValue(key, []byte(rawVal))
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal(expectedVal))
	},
	Entry(
		"Block affinity claims with confirmed state",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.64/26"),
			Host: "happyhost.io",
		},
		`{"state":"confirmed"}`,
		&BlockAffinity{State: StateConfirmed},
	),
	Entry(
		"Block affinity claims with pending state",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.0/26"),
			Host: "slightlyhappyhost.io",
		},
		`{"state":"pending"}`,
		&BlockAffinity{State: StatePending},
	),
	Entry(
		"Block affinity claims with pending-deletion state",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.192/26"),
			Host: "notsohappyhost.io",
		},
		`{"state":"pendingDeletion"}`,
		&BlockAffinity{State: StatePendingDeletion},
	),
	Entry(
		"Pre-3.0.7 style block affinity claims with no state i.e. empty string in value",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.128/26"),
			Host: "oldhost.io",
		},
		``,
		&BlockAffinity{},
	),
	Entry(
		"Block affinity claims with empty state {} in value",
		BlockAffinityKey{
			CIDR: mustParseCIDR("172.29.128.128/26"),
			Host: "oldhost.io",
		},
		`{}`,
		&BlockAffinity{},
	),
)

func mustParseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *ipNet
}
