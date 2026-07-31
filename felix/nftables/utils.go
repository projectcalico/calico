// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
package nftables

import (
	"context"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/environment"
)

// NewNftablesDataplaneFn is a function type that creates a new nftables dataplane interface.
type NewNftablesDataplaneFn func(knftables.Family, string, ...knftables.Option) (knftables.Interface, error)

// MinKernelVersionForNftables is the minimum kernel version required for the
// native nftables dataplane. Calico's documented nftables requirement is
// "Linux kernel version 5.13 or later with nft >= 1.0.1"
// (https://docs.tigera.io/calico/latest/getting-started/kubernetes/nftables),
// mirroring kube-proxy's nftables mode requirement
// (https://kubernetes.io/docs/reference/networking/virtual-ips/#proxy-mode-nftables).
// The nft half of the requirement is enforced by knftables itself, which
// refuses to drive an nft binary older than v1.0.1. Older kernels (e.g.
// RHEL 8's 4.18) cannot reliably run the nftables dataplane under churn.
var MinKernelVersionForNftables = environment.MustParseVersion("5.13")

// HostNftablesSupportedFn returns a function that reports whether this host
// meets the minimum requirements for the native nftables dataplane:
//
//   - a usable nft binary of a supported version (knftables enforces >= v1.0.1), and
//   - a kernel of at least MinKernelVersionForNftables.
//
// It is used to resolve NFTablesMode=Auto on hosts that run no kube-proxy,
// where the kube-proxy-based detection gives no signal.
// Both dependencies are injectable for testing; pass nil for the defaults.
func HostNftablesSupportedFn(newDataplane NewNftablesDataplaneFn, getKernelVersion func() (*environment.Version, error)) func() bool {
	if newDataplane == nil {
		newDataplane = knftables.New
	}
	if getKernelVersion == nil {
		getKernelVersion = func() (*environment.Version, error) {
			reader, err := environment.GetKernelVersionReader()
			if err != nil {
				return nil, err
			}
			if closer, ok := reader.(io.Closer); ok {
				defer closer.Close()
			}
			return environment.GetKernelVersion(reader)
		}
	}

	return func() bool {
		kernelVersion, err := getKernelVersion()
		if err != nil {
			log.WithError(err).Warn(
				"Failed to determine kernel version; assuming this host does not support the nftables dataplane.")
			return false
		}
		if kernelVersion.Compare(MinKernelVersionForNftables) < 0 {
			log.WithFields(log.Fields{
				"kernelVersion": kernelVersion,
				"minVersion":    MinKernelVersionForNftables,
			}).Info("Kernel is older than the minimum required for the nftables dataplane.")
			return false
		}
		if _, err := newDataplane(knftables.IPv4Family, "calico"); err != nil {
			// knftables validates that the nft binary is present and recent
			// enough for it to drive.
			log.WithError(err).Info("This host does not have a usable nft binary for the nftables dataplane.")
			return false
		}
		log.WithField("kernelVersion", kernelVersion).Info(
			"This host meets the minimum requirements for the nftables dataplane.")
		return true
	}
}

// KubeProxyNftablesEnabledFn returns a function that can be used to check if kube-proxy is running
// in nftables mode. It does this by checking for the presence of the nftables chains that
// kube-proxy creates when running in nftables mode.
func KubeProxyNftablesEnabledFn(newDataplane NewNftablesDataplaneFn) func() (bool, error) {
	if newDataplane == nil {
		newDataplane = knftables.New
	}

	// Create v4 and v6 nftables interfaces. If either succeeds, we can use it to check for
	// the presence of the kube-proxy nftables table.
	nft, err := newDataplane(knftables.IPv4Family, "kube-proxy")
	if err != nil {
		// Don't return an error here - some systems may not have nftables support. We handle
		// this case in the returned function.
		log.WithError(err).Warn("Failed to create nftables interface to check kube-proxy mode.")
	}
	nftv6, err := newDataplane(knftables.IPv6Family, "kube-proxy")
	if err != nil {
		// Don't return an error here - some systems may not have nftables support. We handle
		// this case in the returned function.
		log.WithError(err).Warn("Failed to create IPv6 nftables interface to check kube-proxy mode.")
	}

	// Common function to check for the presence of the kube-proxy nftables table for a given family.
	checkTable := func(nft knftables.Interface) (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		objs, err := nft.List(ctx, "chains")
		if err != nil {
			if knftables.IsNotFound(err) {
				// Table not found, kube-proxy is not in nftables mode.
				return false, nil
			}
			log.WithError(err).Warn("Failed to list nftables to check kube-proxy mode.")
			return false, err
		}

		// If there are any chains, kube-proxy is in nftables mode.
		return len(objs) > 0, nil
	}

	// Return a function that checks both IPv4 and IPv6 tables, depending on which are available.
	return func() (bool, error) {
		if nft != nil {
			ipv4Enabled, err := checkTable(nft)
			if err != nil {
				// Failed to check IPv4 table.
				return false, err
			} else if ipv4Enabled {
				// Kube-proxy is in nftables mode.
				return true, nil
			}
			// kube-proxy not in nftables mode for IPv4, maybe check IPv6.
		}
		if nftv6 != nil {
			// Check IPv6 table.
			return checkTable(nftv6)
		}

		// Neither IPv4 nor IPv6 nftables interfaces are available, kube-proxy must not be in nftables mode.
		return false, nil
	}
}
