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
	"slices"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
)

// addressesFromEndpoint returns the bare IP addresses in a workload endpoint's IPNetworks, in
// the order the endpoint lists them. These are the addresses the pod is currently using, so
// they are the ones to reuse for a new sandbox and to protect from release. A nil endpoint
// has none. An entry that doesn't parse is logged and skipped, so one corrupt entry can't
// stop the others from being used.
func addressesFromEndpoint(wep *internalapi.WorkloadEndpoint, logger *logrus.Entry) []net.IP {
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

// failedAddCleanup returns the release a failed ADD runs for this sandbox. It copies prior,
// the endpoint as the ADD found it, because the ADD then rewrites the endpoint with this
// sandbox's container ID and addresses, and judging from those would release the pod's own.
func failedAddCleanup(
	ctx context.Context,
	ipamClient ipam.Interface,
	conf types.NetConf,
	args *skel.CmdArgs,
	epIDs utils.WEPIdentifiers,
	prior *internalapi.WorkloadEndpoint,
	logger *logrus.Entry,
) func() {
	prior = prior.DeepCopy()
	return func() {
		logger.Info("Releasing IPAM allocation(s) after failure")
		if err := releaseUnusedAddresses(ctx, ipamClient, conf, args, epIDs, prior, logger); err != nil {
			logger.WithError(err).Error("Failed to release IPAM allocation(s) after failure")
		}
	}
}

// releaseUnusedAddresses frees this sandbox's IPAM allocations but keeps the addresses wep
// lists when wep names another sandbox, since the endpoint still lists them. An empty container
// ID counts as another sandbox. When wep is nil or names this sandbox, the IPAM type isn't
// calico-ipam, the pod is a KubeVirt pod, or wep lists no parsable address, it runs the IPAM
// plugin's DEL. Otherwise it releases the handle's unlisted addresses one at a time, never the
// whole handle.
func releaseUnusedAddresses(
	ctx context.Context,
	ipamClient ipam.Interface,
	conf types.NetConf,
	args *skel.CmdArgs,
	epIDs utils.WEPIdentifiers,
	wep *internalapi.WorkloadEndpoint,
	logger *logrus.Entry,
) error {
	var keepAddresses []net.IP
	if wep != nil && wep.Spec.ContainerID != args.ContainerID {
		keepAddresses = addressesFromEndpoint(wep, logger)
	}
	if len(keepAddresses) == 0 || conf.IPAM.Type != "calico-ipam" || kubevirt.MaybeVirtLauncherPod(epIDs.Pod) {
		return utils.ReleaseIPAllocation(ctx, logger, conf, args)
	}
	handleID := utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	return releaseUnlisted(ctx, ipamClient, handleID, conf.IPAMLockFile, keepAddresses, logger)
}

// releaseUnlisted releases each address on handleID that is not in keepAddresses. It holds the
// host IPAM lock at lockPath and finishes even if ctx is canceled, so a release that has
// started is not abandoned. A handle that doesn't exist has nothing to release.
func releaseUnlisted(ctx context.Context, ipamClient ipam.Interface, handleID, lockPath string, keepAddresses []net.IP, logger *logrus.Entry) error {
	return utils.WithIPAMLock(context.WithoutCancel(ctx), lockPath, func(ctx context.Context) error {
		ips, err := ipamClient.IPsByHandle(ctx, handleID)
		if err != nil {
			if errors.As(err, &cerrors.ErrorResourceDoesNotExist{}) {
				return nil
			}
			return fmt.Errorf("listing addresses on handle %s: %w", handleID, err)
		}

		var errs []error
		for _, ip := range ips {
			if slices.ContainsFunc(keepAddresses, ip.Equal) {
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
