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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
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

// releaseUnlisted releases the addresses on handleID that listed does not contain, and
// reports whether it kept any. A failed ADD uses it to free only the addresses that this
// sandbox allocated, since the endpoint still lists the rest and the next ADD claims them.
// It holds the host IPAM lock at lockPath throughout, like calico-ipam's DEL, and finishes
// even if ctx is canceled.
func releaseUnlisted(ctx context.Context, ipamClient ipam.Interface, handleID, lockPath string, listed set.Set[string], logger *logrus.Entry) (bool, error) {
	var kept bool
	err := underIPAMLock(ctx, lockPath, func(ctx context.Context) error {
		ips, err := ipamClient.IPsByHandle(ctx, handleID)
		if err != nil {
			if errors.As(err, &cerrors.ErrorResourceDoesNotExist{}) {
				return nil
			}
			return fmt.Errorf("listing addresses on handle %s: %w", handleID, err)
		}

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
		return errors.Join(errs...)
	})
	return kept, err
}

// releaseListedElsewhere releases each listed address that the owner pod holds on a sandbox
// handle on network. The pod's own DEL uses it once the endpoint is gone, so an address a
// failed sandbox kept for the endpoint doesn't outlive the pod. Releasing by handle leaves an
// address that moved meanwhile alone.
func releaseListedElsewhere(
	ctx context.Context,
	ipamClient ipam.Interface,
	network, lockPath string,
	owner ipam.AttributeOwner,
	listed set.Set[string],
	logger *logrus.Entry,
) error {
	return underIPAMLock(ctx, lockPath, func(ctx context.Context) error {
		var errs []error
		for addr := range listed.All() {
			attr, err := ipamClient.GetAssignmentAttributes(ctx, cnet.IP{IP: net.ParseIP(addr)})
			if errors.As(err, &cerrors.ErrorResourceDoesNotExist{}) || errors.As(err, &cerrors.ErrorIPInCooldown{}) {
				continue
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("reading the allocation of %s: %w", addr, err))
				continue
			}
			if attr == nil || attr.HandleID == nil {
				continue
			}
			handleID := *attr.HandleID
			if _, ok := ipam.ParsePodHandleID(handleID, network); !ok || !owner.Matches(attr.ActiveOwnerAttrs) {
				continue
			}

			logger.WithFields(logrus.Fields{"ip": addr, "handle": handleID}).Info("Releasing address the deleted endpoint listed")
			if _, _, err := ipamClient.ReleaseIPs(ctx, ipam.ReleaseOptions{Address: addr, Handle: handleID}); err != nil {
				errs = append(errs, fmt.Errorf("releasing %s: %w", addr, err))
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

// keepsListedAddresses reports whether a failed ADD should leave the addresses its endpoint
// lists in place. It holds only for calico-ipam with ordinary pods, the same cases in which
// ADD reuses or moves addresses onto the new sandbox's handle.
func keepsListedAddresses(conf types.NetConf, epIDs utils.WEPIdentifiers, ipAddrsNoIPAM string) bool {
	return conf.IPAM.Type == "calico-ipam" &&
		!kubevirt.MaybeVirtLauncherPod(epIDs.Pod) &&
		ipAddrsNoIPAM == ""
}
