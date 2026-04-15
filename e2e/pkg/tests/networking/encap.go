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
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// detectEncapInterface returns the name of the tunnel device used by the
// cluster's encapsulation mode. It inspects the IPPools to determine
// whether IPIP or VXLAN is in use:
//   - IPIP (Always or CrossSubnet) → "tunl0"
//   - VXLAN (Always or CrossSubnet) → "vxlan.calico"
//   - No encapsulation → ""
func detectEncapInterface(cli ctrlclient.Client) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pools := &v3.IPPoolList{}
	if err := cli.List(ctx, pools); err != nil {
		logrus.WithError(err).Warn("Could not list IPPools for encap detection, assuming no tunnel")
		return ""
	}

	var result string
	for _, pool := range pools.Items {
		switch {
		case pool.Spec.IPIPMode == v3.IPIPModeAlways || pool.Spec.IPIPMode == v3.IPIPModeCrossSubnet:
			logrus.Infof("Detected IPIP encapsulation from IPPool %s (mode=%s)", pool.Name, pool.Spec.IPIPMode)
			if result != "" && result != "tunl0" {
				logrus.Warnf("Mixed encapsulation detected: IPPool %s uses IPIP but another pool uses VXLAN; using %s", pool.Name, result)
				continue
			}
			result = "tunl0"
		case pool.Spec.VXLANMode == v3.VXLANModeAlways || pool.Spec.VXLANMode == v3.VXLANModeCrossSubnet:
			logrus.Infof("Detected VXLAN encapsulation from IPPool %s (mode=%s)", pool.Name, pool.Spec.VXLANMode)
			if result != "" && result != "vxlan.calico" {
				logrus.Warnf("Mixed encapsulation detected: IPPool %s uses VXLAN but another pool uses IPIP; using %s", pool.Name, result)
				continue
			}
			result = "vxlan.calico"
		}
	}

	if result != "" {
		return result
	}

	logrus.Info("No encapsulation detected from IPPools")
	return ""
}
