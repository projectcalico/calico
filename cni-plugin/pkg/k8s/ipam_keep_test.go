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

package k8s

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
)

var _ = DescribeTable("listedAddresses",
	func(wep *internalapi.WorkloadEndpoint, want []string) {
		got := listedAddresses(wep)
		Expect(got.Len()).To(Equal(len(want)))
		for _, ip := range want {
			Expect(got.Contains(ip)).To(BeTrue(), "missing %s", ip)
		}
	},
	Entry("a nil endpoint lists nothing", nil, nil),
	Entry("an endpoint with no networks lists nothing", &internalapi.WorkloadEndpoint{}, nil),
	Entry("dual-stack networks give both bare IPs", wepWithNetworks("10.0.0.5/32", "fd00::5/128"), []string{"10.0.0.5", "fd00::5"}),
	Entry("an unparseable entry is skipped", wepWithNetworks("10.0.0.5/32", "garbage"), []string{"10.0.0.5"}),
)

var _ = DescribeTable("keepsListedAddresses",
	func(ipamType, pod, ipAddrsNoIpam string, want bool) {
		conf := types.NetConf{}
		conf.IPAM.Type = ipamType
		Expect(keepsListedAddresses(conf, utils.WEPIdentifiers{Pod: pod}, ipAddrsNoIpam)).To(Equal(want))
	},
	Entry("calico-ipam, ordinary pod", "calico-ipam", "web-0", "", true),
	Entry("another IPAM type", "host-local", "web-0", "", false),
	Entry("a virt-launcher pod", "calico-ipam", "virt-launcher-vm1-abcde", "", false),
	Entry("ipAddrsNoIpam is set", "calico-ipam", "web-0", `["10.0.0.1"]`, false),
)

func wepWithNetworks(nets ...string) *internalapi.WorkloadEndpoint {
	wep := internalapi.NewWorkloadEndpoint()
	wep.Spec.IPNetworks = nets
	return wep
}
