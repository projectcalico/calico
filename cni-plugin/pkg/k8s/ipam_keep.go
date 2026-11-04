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
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// ipamReleaseTimeout bounds the IPAM calls made under the host IPAM lock, matching calico-ipam.
const ipamReleaseTimeout = 90 * time.Second

// listedAddresses returns the bare IP addresses a workload endpoint records in its
// IPNetworks, as parsed by endpointIPs.
func listedAddresses(wep *internalapi.WorkloadEndpoint, logger *logrus.Entry) set.Set[string] {
	listed := set.New[string]()
	for _, ip := range endpointIPs(wep, logger) {
		listed.Add(ip.String())
	}
	return listed
}

// endpointIPs returns the addresses a workload endpoint records in its IPNetworks, in order.
// A nil endpoint records none. An entry that doesn't parse is logged and skipped, so one
// corrupt entry can't stop the others from being reused or kept.
func endpointIPs(wep *internalapi.WorkloadEndpoint, logger *logrus.Entry) []net.IP {
	if wep == nil {
		return nil
	}
	var ips []net.IP
	for _, ipNetwork := range wep.Spec.IPNetworks {
		ip, _, err := net.ParseCIDR(ipNetwork)
		if err != nil {
			logger.WithError(err).WithField("ipNetwork", ipNetwork).Warn("Endpoint records an address we cannot parse, ignoring it")
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}

// releaseSandboxAddresses releases this sandbox's IPAM allocations except keepAddresses, the
// addresses the pod's endpoint still lists. With nothing to keep, another IPAM type or a KubeVirt
// pod, it runs the IPAM plugin's DEL. Otherwise it releases only the other addresses on the
// sandbox's handle and never the whole handle, since an empty handle lookup skips unreadable blocks.
func releaseSandboxAddresses(
	ctx context.Context,
	ipamClient ipam.Interface,
	conf types.NetConf,
	args *skel.CmdArgs,
	epIDs utils.WEPIdentifiers,
	keepAddresses set.Set[string],
	logger *logrus.Entry,
) error {
	if keepAddresses.Len() == 0 || conf.IPAM.Type != "calico-ipam" || kubevirt.MaybeVirtLauncherPod(epIDs.Pod) {
		return utils.ReleaseIPAllocation(ctx, logger, conf, args)
	}
	handleID := utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	return releaseUnlisted(ctx, ipamClient, handleID, conf.IPAMLockFile, keepAddresses, logger)
}

// releaseUnlisted releases the addresses on handleID that keepAddresses does not contain. It
// holds the host IPAM lock at lockPath throughout, like calico-ipam's DEL, and finishes even if
// ctx is canceled.
func releaseUnlisted(ctx context.Context, ipamClient ipam.Interface, handleID, lockPath string, keepAddresses set.Set[string], logger *logrus.Entry) error {
	return underIPAMLock(ctx, lockPath, func(ctx context.Context) error {
		ips, err := ipamClient.IPsByHandle(ctx, handleID)
		if err != nil {
			if errors.As(err, &cerrors.ErrorResourceDoesNotExist{}) {
				return nil
			}
			return fmt.Errorf("listing addresses on handle %s: %w", handleID, err)
		}

		var errs []error
		for _, ip := range ips {
			if keepAddresses.Contains(ip.String()) {
				logger.WithField("ip", ip).Info("Keeping address the endpoint lists")
				continue
			}
			logger.WithField("ip", ip).Info("Releasing address the endpoint does not list")
			if _, _, err := ipamClient.ReleaseIPs(ctx, ipam.ReleaseOptions{Address: ip.String(), Handle: handleID}); err != nil {
				errs = append(errs, fmt.Errorf("releasing %s: %w", ip, err))
			}
		}
		return errors.Join(errs...)
	})
}

// underIPAMLock runs fn holding the host IPAM lock at lockPath, as calico-ipam's DEL does.
// fn's context ignores cancellation of ctx, so a release that has started finishes, and its
// timeout starts only once the lock is held.
func underIPAMLock(ctx context.Context, lockPath string, fn func(context.Context) error) error {
	unlock := utils.AcquireIPAMLockBestEffort(lockPath)
	defer unlock()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ipamReleaseTimeout)
	defer cancel()
	return fn(ctx)
}
