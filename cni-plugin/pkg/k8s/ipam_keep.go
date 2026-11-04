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
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
)

// ipamReleaseTimeout bounds the IPAM calls made under the host IPAM lock, matching calico-ipam.
const ipamReleaseTimeout = 90 * time.Second

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

// releaseSandboxAddresses frees the IPAM allocations held for one sandbox, except keepAddresses,
// which the pod's endpoint still uses and so must stay allocated. With nothing to keep, an IPAM
// type other than calico-ipam, or a KubeVirt pod, it runs the configured IPAM plugin's DEL.
// Otherwise it releases the sandbox's other addresses one at a time, because the kept ones
// share its handle and releasing the handle would free them too.
func releaseSandboxAddresses(
	ctx context.Context,
	ipamClient ipam.Interface,
	conf types.NetConf,
	args *skel.CmdArgs,
	epIDs utils.WEPIdentifiers,
	keepAddresses []net.IP,
	logger *logrus.Entry,
) error {
	if len(keepAddresses) == 0 || conf.IPAM.Type != "calico-ipam" || kubevirt.MaybeVirtLauncherPod(epIDs.Pod) {
		return utils.ReleaseIPAllocation(ctx, logger, conf, args)
	}
	handleID := utils.GetHandleID(conf.Name, args.ContainerID, epIDs.WEPName)
	return releaseUnlisted(ctx, ipamClient, handleID, conf.IPAMLockFile, keepAddresses, logger)
}

// releaseUnlisted releases each address on handleID that is not in keepAddresses, comparing
// by IP value so different textual forms of an IPv6 address still match. It holds the host
// IPAM lock at lockPath, like calico-ipam does, and finishes even if ctx is canceled, so a
// release that has started is not abandoned. A handle that doesn't exist has nothing to release.
func releaseUnlisted(ctx context.Context, ipamClient ipam.Interface, handleID, lockPath string, keepAddresses []net.IP, logger *logrus.Entry) error {
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
