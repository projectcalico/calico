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

package conversionv1v3

import (
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

var poolTable = []struct {
	description string
	inV1        *model.KVPair
	outV3       *model.KVPair
}{
	{
		description: "fully populated IPv4 IPPool",
		inV1: &model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("10.0.0.1/24"),
			},
			Value: model.IPPool{
				CIDR:          cnet.MustParseCIDR("10.0.0.1/24"),
				IPIPInterface: "tunl0",
				IPIPMode:      ipip.Undefined,
				Masquerade:    false,
				Disabled:      false,
				IPAM:          true,
			},
		},
		outV3: &model.KVPair{
			Key: model.ResourceKey{
				Name: "10-0-0-1-24",
				Kind: "ippool",
			},
			Value: apiv3.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "10-0-0-1-24",
				},
				Spec: apiv3.IPPoolSpec{
					CIDR:        "10.0.0.1/24",
					IPIPMode:    apiv3.IPIPModeAlways,
					NATOutgoing: false,
					Disabled:    false,
				},
			},
		},
	},
	{
		description: "fully populated IPv6 IPPool",
		inV1: &model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("2001::/120"),
			},
			Value: model.IPPool{
				CIDR:          cnet.MustParseCIDR("2001::/120"),
				IPIPInterface: "tunl0",
				IPIPMode:      ipip.Always,
				Masquerade:    false,
				Disabled:      true,
				IPAM:          false,
			},
		},
		outV3: &model.KVPair{
			Key: model.ResourceKey{
				Name: "2001---120",
				Kind: "ippool",
			},
			Value: apiv3.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "2001---120",
				},
				Spec: apiv3.IPPoolSpec{
					CIDR:        "2001::/120",
					IPIPMode:    apiv3.IPIPModeAlways,
					NATOutgoing: false,
					Disabled:    true,
				},
			},
		},
	},
	{
		description: "IPv4 IPPool with IPIPMode blank, should be converted to IPIPMode Always",
		inV1: &model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("5.5.5.5/25"),
			},
			Value: model.IPPool{
				CIDR:          cnet.MustParseCIDR("5.5.5.5/25"),
				IPIPInterface: "",
				IPIPMode:      "",
				Masquerade:    true,
				Disabled:      true,
				IPAM:          false,
			},
		},
		outV3: &model.KVPair{
			Key: model.ResourceKey{
				Name: "5-5-5-5-25",
				Kind: "ippool",
			},
			Value: apiv3.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "5-5-5-5-25",
				},
				Spec: apiv3.IPPoolSpec{
					CIDR:        "5.5.5.5/25",
					IPIPMode:    apiv3.IPIPModeNever,
					NATOutgoing: true,
					Disabled:    true,
				},
			},
		},
	},
	{
		description: "IPv4 IPPool with IPIPMode unspecified, should be converted to IPIPMode Always",
		inV1: &model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("6.6.6.6/26"),
			},
			Value: model.IPPool{
				CIDR:       cnet.MustParseCIDR("6.6.6.6/26"),
				Masquerade: true,
				Disabled:   true,
				IPAM:       false,
			},
		},
		outV3: &model.KVPair{
			Key: model.ResourceKey{
				Name: "6-6-6-6-26",
				Kind: "ippool",
			},
			Value: apiv3.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "6-6-6-6-26",
				},
				Spec: apiv3.IPPoolSpec{
					CIDR:        "6.6.6.6/26",
					IPIPMode:    apiv3.IPIPModeNever,
					NATOutgoing: true,
					Disabled:    true,
				},
			},
		},
	},
	{
		description: "partially populated IPv4 IPPool with IPIPMode set to cross-subnet",
		inV1: &model.KVPair{
			Key: model.IPPoolKey{
				CIDR: cnet.MustParseCIDR("1.1.1.1/11"),
			},
			Value: model.IPPool{
				CIDR:          cnet.MustParseCIDR("1.1.1.1/11"),
				Masquerade:    false,
				IPIPInterface: "tunl0",
				IPIPMode:      ipip.CrossSubnet,
				Disabled:      true,
				IPAM:          false,
			},
		},
		outV3: &model.KVPair{
			Key: model.ResourceKey{
				Name: "1-1-1-1-11",
				Kind: "ippool",
			},
			Value: apiv3.IPPool{
				ObjectMeta: v1.ObjectMeta{
					Name: "1-1-1-1-11",
				},
				Spec: apiv3.IPPoolSpec{
					CIDR:        "1.1.1.1/11",
					IPIPMode:    apiv3.IPIPModeCrossSubnet,
					NATOutgoing: false,
					Disabled:    true,
				},
			},
		},
	},
}

func TestCanConvertV1ToV3IPPool(t *testing.T) {
	RegisterTestingT(t)

	for _, entry := range poolTable {
		t.Run(entry.description, func(t *testing.T) {
			t.Parallel()

			result, err := ConvertIPPool(entry.inV1)

			Expect(err).NotTo(HaveOccurred(), entry.description)
			Expect(result.Key.(model.ResourceKey).Name).To(Equal(entry.outV3.Key.(model.ResourceKey).Name), entry.description)
			Expect(result.Value.(apiv3.IPPool).Spec).To(Equal(entry.outV3.Value.(apiv3.IPPool).Spec), entry.description)
		})
	}
}
