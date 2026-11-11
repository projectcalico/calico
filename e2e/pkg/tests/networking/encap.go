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

package networking

import (
	"context"
	"net"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils"
)

// detectEncapInterfaces returns the tunnel device each IP family's pools use:
// "tunl0" for IPIP (IPv4 only), "vxlan.calico" / "vxlan-v6.calico" for VXLAN.
// A family with no encapsulation, or no pools, is absent from the map.
func detectEncapInterfaces(cli ctrlclient.Client) map[utils.IPFamily]string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := map[utils.IPFamily]string{}
	pools := &v3.IPPoolList{}
	if err := cli.List(ctx, pools); err != nil {
		logrus.WithError(err).Warn("Could not list IPPools for encap detection, assuming no tunnel")
		return result
	}

	for _, pool := range pools.Items {
		_, cidr, err := net.ParseCIDR(pool.Spec.CIDR)
		if err != nil {
			logrus.WithError(err).Warnf("Skipping IPPool %s with unparseable CIDR %q", pool.Name, pool.Spec.CIDR)
			continue
		}
		fam := utils.IPv4
		if cidr.IP.To4() == nil {
			fam = utils.IPv6
		}

		var iface string
		switch {
		case fam == utils.IPv4 && (pool.Spec.IPIPMode == v3.IPIPModeAlways || pool.Spec.IPIPMode == v3.IPIPModeCrossSubnet):
			iface = "tunl0"
		case pool.Spec.VXLANMode == v3.VXLANModeAlways || pool.Spec.VXLANMode == v3.VXLANModeCrossSubnet:
			iface = "vxlan.calico"
			if fam == utils.IPv6 {
				iface = "vxlan-v6.calico"
			}
		default:
			continue
		}
		logrus.Infof("Detected %s encapsulation device %s from IPPool %s", fam, iface, pool.Name)
		if prev, ok := result[fam]; ok && prev != iface {
			logrus.Warnf("Mixed %s encapsulation: IPPool %s uses %s but another pool uses %s; using %s", fam, pool.Name, iface, prev, prev)
			continue
		}
		result[fam] = iface
	}

	if len(result) == 0 {
		logrus.Info("No encapsulation detected from IPPools")
	}
	return result
}
