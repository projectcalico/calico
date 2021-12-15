// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// IPPool implements the Converter interface.
type IPPool struct{}

// APIV1ToBackendV1 converts v1 IPPool API to v1 IPPool KVPair.
func (_ IPPool) APIV1ToBackendV1(rIn unversioned.Resource) (*model.KVPair, error) {
	p := rIn.(*apiv1.IPPool)

	var ipipInterface string
	var ipipMode encap.Mode
	if p.Spec.IPIP != nil {
		if p.Spec.IPIP.Enabled {
			ipipInterface = "tunl0"
		} else {
			ipipInterface = ""
		}
		ipipMode = p.Spec.IPIP.Mode
	}

	d := model.KVPair{
		Key: model.IPPoolKey{
			CIDR: p.Metadata.CIDR,
		},
		Value: &model.IPPool{
			CIDR:          p.Metadata.CIDR,
			IPIPInterface: ipipInterface,
			IPIPMode:      ipipMode,
			Masquerade:    p.Spec.NATOutgoing,
			IPAM:          !p.Spec.Disabled,
			Disabled:      p.Spec.Disabled,
		},
	}

	return &d, nil
}

// BackendV1ToAPIV3 converts v1 IPPool KVPair to v3 API.
func (_ IPPool) BackendV1ToAPIV3(kvp *model.KVPair) (Resource, error) {
	pool, ok := kvp.Value.(*model.IPPool)
	if !ok {
		return nil, fmt.Errorf("value is not a valid IPPool resource Value")
	}

	ipp := apiv3.NewIPPool()
	ipp.Name = names.CIDRToName(pool.CIDR)
	ipp.Spec = apiv3.IPPoolSpec{
		CIDR:         pool.CIDR.String(),
		IPIPMode:     convertIPIPMode(pool.IPIPMode, pool.IPIPInterface),
		VXLANMode:    apiv3.VXLANModeNever,
		NATOutgoing:  pool.Masquerade,
		Disabled:     pool.Disabled,
		NodeSelector: "all()",
		AllowedUses: []apiv3.IPPoolAllowedUse{
			apiv3.IPPoolAllowedUseWorkload,
			apiv3.IPPoolAllowedUseTunnel,
		},
	}

	// Set the blocksize based on IP address family.
	if pool.CIDR.IP.To4() != nil {
		ipp.Spec.BlockSize = 26
	} else {
		ipp.Spec.BlockSize = 122
	}

	return ipp, nil
}

func convertIPIPMode(mode encap.Mode, ipipInterface string) apiv3.IPIPMode {
	ipipMode := strings.ToLower(string(mode))

	if ipipInterface == "" {
		return apiv3.IPIPModeNever
	} else if ipipMode == "cross-subnet" {
		return apiv3.IPIPModeCrossSubnet
	}
	return apiv3.IPIPModeAlways
}
