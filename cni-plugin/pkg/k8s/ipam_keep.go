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
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// listedAddresses returns the bare IP addresses a workload endpoint records in its
// IPNetworks. A nil endpoint lists none, and entries that do not parse are skipped.
func listedAddresses(wep *internalapi.WorkloadEndpoint) set.Set[string] {
	listed := set.New[string]()
	if wep == nil {
		return listed
	}
	for _, ipNetwork := range wep.Spec.IPNetworks {
		ip, _, err := net.ParseCIDR(ipNetwork)
		if err != nil {
			logrus.WithError(err).WithField("ipNetwork", ipNetwork).Warn("Endpoint records an address we cannot parse, ignoring it")
			continue
		}
		listed.Add(ip.String())
	}
	return listed
}

// releaseUnlisted releases the addresses on handleID that listed does not contain, and
// reports whether it kept any. A failed ADD uses it to free only the addresses that this
// sandbox allocated, since the endpoint still lists the rest and the next ADD claims them.
func releaseUnlisted(ctx context.Context, ipamClient ipam.Interface, handleID string, listed set.Set[string], logger *logrus.Entry) (bool, error) {
	ips, err := ipamClient.IPsByHandle(ctx, handleID)
	if err != nil {
		if errors.As(err, &cerrors.ErrorResourceDoesNotExist{}) {
			return false, nil
		}
		return false, fmt.Errorf("listing addresses on handle %s: %w", handleID, err)
	}

	var kept bool
	var errs []error
	for _, ip := range ips {
		if listed.Contains(ip.String()) {
			logger.WithField("ip", ip).Info("Keeping address the endpoint lists")
			kept = true
			continue
		}
		logger.WithField("ip", ip).Info("Releasing address the endpoint does not list")
		if _, _, err := ipamClient.ReleaseIPs(ctx, ipam.ReleaseOptions{Address: ip.String(), Handle: handleID}); err != nil {
			errs = append(errs, fmt.Errorf("releasing %s: %w", ip, err))
		}
	}
	return kept, errors.Join(errs...)
}

// keepsListedAddresses reports whether a failed ADD should leave the addresses its endpoint
// lists in place. It holds only for calico-ipam with ordinary pods, the same cases in which
// ADD reuses or moves addresses onto the new sandbox's handle.
func keepsListedAddresses(conf types.NetConf, epIDs utils.WEPIdentifiers, ipAddrsNoIPAM string) bool {
	return conf.IPAM.Type == "calico-ipam" &&
		!kubevirt.MaybeVirtLauncherPod(epIDs.Pod) &&
		ipAddrsNoIPAM == ""
}
