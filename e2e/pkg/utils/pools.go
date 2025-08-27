// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/sirupsen/logrus"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func GetEncapsulationFromPools(client ctrlclient.Client) (ipipEnabled, vxlanEnabled, vxlanEnabledV6 bool, err error) {
	pools := v3.IPPoolList{}
	if err := client.List(context.Background(), &pools); err != nil {
		return false, false, false, err
	}
	logrus.Debugf("Get IPIP and VXLAN encapsulation from all IP pools: %+v", pools)

	ipipEnabled, vxlanEnabled, vxlanEnabledV6 = false, false, false
	for _, p := range pools.Items {
		if p.Spec.IPIPMode == v3.IPIPModeAlways || p.Spec.IPIPMode == v3.IPIPModeCrossSubnet {
			ipipEnabled = true
		}
		if p.Spec.VXLANMode == v3.VXLANModeAlways || p.Spec.VXLANMode == v3.VXLANModeCrossSubnet {
			if cidr := cnet.MustParseCIDR(p.Spec.CIDR); cidr.IP.To4() != nil {
				vxlanEnabled = true
			} else {
				vxlanEnabledV6 = true
			}
		}
	}
	logrus.Infof("IPIP enabled: %v, IPv4 VXLAN enabled: %v, IPv6 VXLAN enabled: %v", ipipEnabled, vxlanEnabled, vxlanEnabledV6)
	return ipipEnabled, vxlanEnabled, vxlanEnabledV6, nil
}
