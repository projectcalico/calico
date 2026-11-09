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
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
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
	calicoClient calicoclient.Interface,
	conf types.NetConf,
	args *skel.CmdArgs,
	prior *internalapi.WorkloadEndpoint,
	logger *logrus.Entry,
) func() {
	prior = prior.DeepCopy()
	return func() {
		logger.Info("Releasing IPAM allocation(s) after failure")
		if err := releaseUnusedAddresses(ctx, calicoClient, conf, args, prior, logger); err != nil {
			logger.WithError(err).Error("Failed to release IPAM allocation(s) after failure")
		}
	}
}

// releaseUnusedAddresses frees this sandbox's IPAM allocations but keeps the addresses wep
// lists when wep names another sandbox or none, since the endpoint still lists them. For
// calico-ipam it runs calico-ipam's release in this process with that keep set, finishing even
// if ctx is canceled. Any other IPAM type gets its plugin's DEL.
func releaseUnusedAddresses(
	ctx context.Context,
	calicoClient calicoclient.Interface,
	conf types.NetConf,
	args *skel.CmdArgs,
	wep *internalapi.WorkloadEndpoint,
	logger *logrus.Entry,
) error {
	if conf.IPAM.Type != "calico-ipam" {
		return utils.ReleaseIPAllocation(ctx, logger, conf, args)
	}
	var keepAddresses []net.IP

	// An empty container ID is an unknown sandbox, which keeps its addresses: freeing a live
	// address is worse than IPAM GC freeing it later. CmdDelK8s's endpoint delete deliberately
	// treats it as this sandbox instead.
	if wep != nil && wep.Spec.ContainerID != args.ContainerID {
		keepAddresses = addressesFromEndpoint(wep, logger)
	}
	return ipamplugin.ReleaseSandbox(context.WithoutCancel(ctx), calicoClient, conf, args, keepAddresses)
}
