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

package converters

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

var poolTable = []TableEntry{
	Entry("fully populated IPv4 IPPool",
		&apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{
				CIDR: cnet.MustParseCIDR("10.0.0.1/24"),
			},
			Spec: apiv1.IPPoolSpec{
				IPIP: &apiv1.IPIPConfiguration{
					Enabled: true,
					Mode:    ipip.Undefined,
				},
				NATOutgoing: false,
				Disabled:    false,
			},
		},
		&model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("10.0.0.1/24"),
			},
			Value: &model.IPPool{
				CIDR:          cnet.MustParseCIDR("10.0.0.1/24"),
				IPIPInterface: "tunl0",
				IPIPMode:      ipip.Undefined,
				Masquerade:    false,
				Disabled:      false,
				IPAM:          true,
			},
		},
		apiv3.IPPool{
			ObjectMeta: v1.ObjectMeta{
				Name: "10-0-0-1-24",
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:        "10.0.0.1/24",
				IPIPMode:    apiv3.IPIPModeAlways,
				NATOutgoing: false,
				Disabled:    false,
				BlockSize:   26,
			},
		},
	),
	Entry("fully populated IPv6 IPPool",
		&apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{
				CIDR: cnet.MustParseCIDR("2001::/120"),
			},
			Spec: apiv1.IPPoolSpec{
				IPIP: &apiv1.IPIPConfiguration{
					Enabled: true,
					Mode:    ipip.Always,
				},
				NATOutgoing: false,
				Disabled:    true,
			},
		},
		&model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("2001::/120"),
			},
			Value: &model.IPPool{
				CIDR:          cnet.MustParseCIDR("2001::/120"),
				IPIPInterface: "tunl0",
				IPIPMode:      ipip.Always,
				Masquerade:    false,
				Disabled:      true,
				IPAM:          false,
			},
		},
		apiv3.IPPool{
			ObjectMeta: v1.ObjectMeta{
				Name: "2001---120",
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:        "2001::/120",
				IPIPMode:    apiv3.IPIPModeAlways,
				NATOutgoing: false,
				Disabled:    true,
				BlockSize:   122,
			},
		},
	),
	Entry("IPv4 IPPool with IPIPMode blank, should be converted to IPIPMode Always",
		&apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{
				CIDR: cnet.MustParseCIDR("5.5.5.5/25"),
			},
			Spec: apiv1.IPPoolSpec{
				IPIP: &apiv1.IPIPConfiguration{
					Enabled: false,
					Mode:    ipip.Undefined,
				},
				NATOutgoing: true,
				Disabled:    true,
			},
		},
		&model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("5.5.5.5/25"),
			},
			Value: &model.IPPool{
				CIDR:          cnet.MustParseCIDR("5.5.5.5/25"),
				IPIPInterface: "",
				IPIPMode:      "",
				Masquerade:    true,
				Disabled:      true,
				IPAM:          false,
			},
		},
		apiv3.IPPool{
			ObjectMeta: v1.ObjectMeta{
				Name: "5-5-5-5-25",
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:        "5.5.5.5/25",
				IPIPMode:    apiv3.IPIPModeNever,
				NATOutgoing: true,
				Disabled:    true,
				BlockSize:   26,
			},
		},
	),
	Entry("IPv4 IPPool with IPIPMode unspecified, should be converted to IPIPMode Always",
		&apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{
				CIDR: cnet.MustParseCIDR("6.6.6.6/26"),
			},
			Spec: apiv1.IPPoolSpec{
				IPIP: &apiv1.IPIPConfiguration{
					Enabled: false,
				},
				NATOutgoing: true,
				Disabled:    true,
			},
		},
		&model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("6.6.6.6/26"),
			},
			Value: &model.IPPool{
				CIDR:       cnet.MustParseCIDR("6.6.6.6/26"),
				Masquerade: true,
				Disabled:   true,
				IPAM:       false,
			},
		},
		apiv3.IPPool{
			ObjectMeta: v1.ObjectMeta{
				Name: "6-6-6-6-26",
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:        "6.6.6.6/26",
				IPIPMode:    apiv3.IPIPModeNever,
				NATOutgoing: true,
				Disabled:    true,
				BlockSize:   26,
			},
		},
	),
	Entry("partially populated IPv4 IPPool with IPIPMode set to cross-subnet",
		&apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{
				CIDR: cnet.MustParseCIDR("1.1.1.1/11"),
			},
			Spec: apiv1.IPPoolSpec{
				IPIP: &apiv1.IPIPConfiguration{
					Enabled: true,
					Mode:    ipip.CrossSubnet,
				},
				NATOutgoing: false,
				Disabled:    true,
			},
		},
		&model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("1.1.1.1/11"),
			},
			Value: &model.IPPool{
				CIDR:          cnet.MustParseCIDR("1.1.1.1/11"),
				Masquerade:    false,
				IPIPInterface: "tunl0",
				IPIPMode:      ipip.CrossSubnet,
				Disabled:      true,
				IPAM:          false,
			},
		},
		apiv3.IPPool{
			ObjectMeta: v1.ObjectMeta{
				Name: "1-1-1-1-11",
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:        "1.1.1.1/11",
				IPIPMode:    apiv3.IPIPModeCrossSubnet,
				NATOutgoing: false,
				Disabled:    true,
				BlockSize:   26,
			},
		},
	),
}

var _ = DescribeTable("v1->v3 IPPool conversion tests",
	func(v1API *apiv1.IPPool, v1KVP *model.KVPair, v3API apiv3.IPPool) {
		p := IPPool{}

		// Test and assert v1 API to v1 backend logic.
		v1KVPResult, err := p.APIV1ToBackendV1(v1API)
		Expect(err).NotTo(HaveOccurred())
		Expect(v1KVPResult.Key.(model.IPPoolKey).CIDR).To(Equal(v1KVP.Key.(model.IPPoolKey).CIDR))
		Expect(v1KVPResult.Value.(*model.IPPool)).To(Equal(v1KVP.Value))

		// Test and assert v1 backend to v3 API logic.
		v3APIResult, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(v3APIResult.(*apiv3.IPPool).Name).To(Equal(v3API.Name))
		Expect(v3APIResult.(*apiv3.IPPool).Spec).To(Equal(v3API.Spec))
	},

	poolTable...,
)
