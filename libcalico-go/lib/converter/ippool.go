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

package converter

import (
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// IPPoolConverter implements a set of functions used for converting between
// API and backend representations of the IPPool resource.
type IPPoolConverter struct{}

// ConvertMetadataToKey converts an IPPoolMetadata to an IPPoolKey.
func (p IPPoolConverter) ConvertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	pm := m.(api.IPPoolMetadata)
	k := model.IPPoolKey{
		CIDR: pm.CIDR,
	}
	return k, nil
}

// ConvertAPIToKVPair converts an API Policy structure to a KVPair containing a
// backend IPPool and IPPoolKey.
func (p IPPoolConverter) ConvertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(api.IPPool)
	k, err := p.ConvertMetadataToKey(ap.Metadata)
	if err != nil {
		return nil, err
	}

	// Only valid interface for now is tunl0.
	var ipipInterface string
	var ipipMode encap.Mode
	if ap.Spec.IPIP != nil {
		if ap.Spec.IPIP.Enabled {
			ipipInterface = "tunl0"
		} else {
			ipipInterface = ""
		}
		ipipMode = ap.Spec.IPIP.Mode
	}

	d := model.KVPair{
		Key: k,
		Value: &model.IPPool{
			CIDR:          ap.Metadata.CIDR,
			IPIPInterface: ipipInterface,
			IPIPMode:      ipipMode,
			Masquerade:    ap.Spec.NATOutgoing,
			IPAM:          !ap.Spec.Disabled,
			Disabled:      ap.Spec.Disabled,
		},
	}

	return &d, nil
}

// ConvertKVPairToAPI converts a KVPair containing a backend IPPool and IPPoolKey
// to an API IPPool structure.
func (_ IPPoolConverter) ConvertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	backendPool := d.Value.(*model.IPPool)

	apiPool := api.NewIPPool()
	apiPool.Metadata.CIDR = backendPool.CIDR
	apiPool.Spec.NATOutgoing = backendPool.Masquerade
	apiPool.Spec.Disabled = backendPool.Disabled

	// If any IPIP configuration is present then include the IPIP spec..
	if backendPool.IPIPInterface != "" || backendPool.IPIPMode != encap.Undefined {
		apiPool.Spec.IPIP = &api.IPIPConfiguration{
			Enabled: backendPool.IPIPInterface != "",
			Mode:    backendPool.IPIPMode,
		}
	}

	return apiPool, nil
}
