//go:build linux

// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
package ipv4

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	FALLBACK_IPPOOL_TEMPLATE = "172.%d.0.0/16"
	FALLBACK_IPPOOL_MIN      = 16
	FALLBACK_IPPOOL_MAX      = 31
)

var hostIPAddressRetriever func(netlink.Link, int) ([]netlink.Addr, error) = netlink.AddrList

// GetDefaultIPv4Pool detects host interfaces and selects default IP pool without overlapping
func GetDefaultIPv4Pool(preferedPool *net.IPNet) (*net.IPNet, error) {
	log.Debug("Auto-detecting IPv4 interfaces to select default pool")

	hostAddrs, err := retrieveIPAddresses()
	if err != nil {
		log.Errorf("Unable to retrieve host network interfaces: '%s'", err.Error())
		return nil, err
	}

	return findAvailableCIDR(preferedPool, hostAddrs), nil
}

func retrieveIPAddresses() ([]net.IPNet, error) {
	linkAddresses, err := hostIPAddressRetriever(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to list addresses")
	}

	resp := make([]net.IPNet, len(linkAddresses))
	for _, addr := range linkAddresses {
		resp = append(resp, *addr.IPNet)
	}

	return resp, nil
}

func findAvailableCIDR(preferredPool *net.IPNet, hostAddrs []net.IPNet) *net.IPNet {
	if !doesPoolOverlap(preferredPool, hostAddrs) {
		return preferredPool
	}

	for i := FALLBACK_IPPOOL_MIN; i <= FALLBACK_IPPOOL_MAX; i++ {
		_, poolToTry, _ := net.ParseCIDR(fmt.Sprintf(FALLBACK_IPPOOL_TEMPLATE, i))
		if !doesPoolOverlap(poolToTry, hostAddrs) {
			return poolToTry
		}
	}

	// We couldn't find a pool. For compatibility reasons, return the preferred pool to match existing behavior.
	return preferredPool
}

func doesPoolOverlap(preferredPool *net.IPNet, hostAddrs []net.IPNet) bool {
	for _, addr := range hostAddrs {
		if preferredPool.Contains(addr.IP) {
			return true
		}
	}
	return false
}
