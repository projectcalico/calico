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

package resources

import (
	"fmt"
	"reflect"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	IPPoolResourceName = "IPPools"
	IPPoolCRDName      = "ippools.crd.projectcalico.org"
)

func NewIPPoolClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            IPPoolCRDName,
		resource:        IPPoolResourceName,
		description:     "Calico IP Pools",
		k8sResourceType: reflect.TypeOf(apiv3.IPPool{}),
		k8sResourceTypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindIPPool,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		k8sListType:      reflect.TypeOf(apiv3.IPPoolList{}),
		resourceKind:     apiv3.KindIPPool,
		versionconverter: IPPoolv1v3Converter{},
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

	// If IPIP field is not nil, then it means the resource has v1 IPIP data
	// and we must convert it to v3 equivalent data.
	if ipp.Spec.IPIP != nil {
		if !ipp.Spec.IPIP.Enabled {
			ipp.Spec.IPIPMode = apiv3.IPIPModeNever
		} else if ipp.Spec.IPIP.Mode == encap.CrossSubnet {
			ipp.Spec.IPIPMode = apiv3.IPIPModeCrossSubnet
		} else {
			ipp.Spec.IPIPMode = apiv3.IPIPModeAlways
		}

		// Set IPIP to nil since we've already converted v1 IPIP fields to v3.
		ipp.Spec.IPIP = nil
	}

	// Take a logical OR of the v1 NATOutgoing field with the v3 NATOutgoing.
	ipp.Spec.NATOutgoing = ipp.Spec.NATOutgoingV1 || ipp.Spec.NATOutgoing

	// Set v1 NatOutgoing to false since we've already converted it to v3 NatOutgoing.
	ipp.Spec.NATOutgoingV1 = false

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
		ipipMode = encap.Undefined
	}

	var vxlanMode encap.Mode
	switch v3res.Spec.VXLANMode {
	case apiv3.VXLANModeAlways:
		vxlanMode = encap.Always
	case apiv3.VXLANModeCrossSubnet:
		vxlanMode = encap.CrossSubnet
	default:
		vxlanMode = encap.Undefined
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
		},
		Revision: kvp.Revision,
	}, nil
}
