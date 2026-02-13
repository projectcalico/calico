// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.

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

package resources

import (
	"fmt"
	"reflect"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	IPPoolResourceName = "IPPools"
)

func NewIPPoolClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:       r,
		resource:         IPPoolResourceName,
		k8sResourceType:  reflect.TypeOf(apiv3.IPPool{}),
		k8sListType:      reflect.TypeOf(apiv3.IPPoolList{}),
		kind:             apiv3.KindIPPool,
		versionconverter: IPPoolv1v3Converter{},
		apiGroup:         group,
	}
}

// IPPoolv1v3Converter implements VersionConverter interface.
type IPPoolv1v3Converter struct{}

// ConvertFromK8s converts v1 IPPool Resource to v3 IPPool resource
func (c IPPoolv1v3Converter) ConvertFromK8s(inRes Resource) (Resource, error) {
	ipp, ok := inRes.(*apiv3.IPPool)
	if !ok {
		return nil, fmt.Errorf("invalid type conversion")
	}
	return ipp, nil
}

func IPPoolV3ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	v3res := kvp.Value.(*apiv3.IPPool)
	_, cidr, err := cnet.ParseCIDR(v3res.Spec.CIDR)
	if err != nil {
		return nil, err
	}
	v1key := model.IPPoolKey{
		CIDR: *cidr,
	}
	var ipipInterface string
	var ipipMode encap.Mode
	switch v3res.Spec.IPIPMode {
	case apiv3.IPIPModeAlways:
		ipipInterface = "tunl0"
		ipipMode = encap.Always
	case apiv3.IPIPModeCrossSubnet:
		ipipInterface = "tunl0"
		ipipMode = encap.CrossSubnet
	default:
		ipipInterface = ""
		ipipMode = encap.Never
	}

	var vxlanMode encap.Mode
	switch v3res.Spec.VXLANMode {
	case apiv3.VXLANModeAlways:
		vxlanMode = encap.Always
	case apiv3.VXLANModeCrossSubnet:
		vxlanMode = encap.CrossSubnet
	default:
		vxlanMode = encap.Never
	}

	if v3res.Spec.AssignmentMode == nil {
		automatic := apiv3.Automatic
		v3res.Spec.AssignmentMode = &automatic
	}

	return &model.KVPair{
		Key: v1key,
		Value: &model.IPPool{
			CIDR:             *cidr,
			IPIPInterface:    ipipInterface,
			IPIPMode:         ipipMode,
			VXLANMode:        vxlanMode,
			Masquerade:       v3res.Spec.NATOutgoing,
			IPAM:             !v3res.Spec.Disabled,
			Disabled:         v3res.Spec.Disabled,
			DisableBGPExport: v3res.Spec.DisableBGPExport,
			AssignmentMode:   *v3res.Spec.AssignmentMode,
		},
		Revision: kvp.Revision,
	}, nil
}
