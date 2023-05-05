// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
package autodetection

import (
	"net"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Interface contains details about an interface on the host.
type Interface struct {
	Name  string
	Cidrs []cnet.IPNet
}

// GetInterfaces returns a list of all interfaces, skipping any interfaces whose
// name matches any of the exclusion list regexes, and including those on the
// inclusion list.
func GetInterfaces(getSystemInterfaces func() ([]net.Interface, error), includeRegexes []string, excludeRegexes []string, version int) ([]Interface, error) {
	netIfaces, err := getSystemInterfaces()
	if err != nil {
		log.WithError(err).Warnf("Failed to enumerate interfaces")
		return nil, err
	}

	var filteredIfaces []Interface
	var includeRegexp *regexp.Regexp
	var excludeRegexp *regexp.Regexp

	// Create single include and exclude regexes to perform the interface
	// check.
	if len(includeRegexes) > 0 {
		if includeRegexp, err = regexp.Compile("(" + strings.Join(includeRegexes, ")|(") + ")"); err != nil {
			log.WithError(err).Warnf("Invalid interface regex")
			return nil, err
		}
	}
	if len(excludeRegexes) > 0 {
		if excludeRegexp, err = regexp.Compile("(" + strings.Join(excludeRegexes, ")|(") + ")"); err != nil {
			log.WithError(err).Warnf("Invalid interface regex")
			return nil, err
		}
	}

	// Loop through interfaces filtering on the regexes.  Loop in reverse
	// order to maintain behavior with older versions.
	for idx := len(netIfaces) - 1; idx >= 0; idx-- {
		iface := netIfaces[idx]
		include := (includeRegexp == nil) || includeRegexp.MatchString(iface.Name)
		exclude := (excludeRegexp != nil) && excludeRegexp.MatchString(iface.Name)
		if include && !exclude {
			if i, err := convertInterface(&iface, version); err == nil {
				filteredIfaces = append(filteredIfaces, *i)
			}
		}
	}
	return filteredIfaces, nil
}

// convertInterface converts a net.Interface to our Interface type (which has
// converted address types).
func convertInterface(i *net.Interface, version int) (*Interface, error) {
	log.WithField("Interface", i.Name).Debug("Querying interface addresses")
	addrs, err := i.Addrs()
	if err != nil {
		log.Warnf("Cannot get interface address(es): %v", err)
		return nil, err
	}

	iface := &Interface{Name: i.Name}
	for _, addr := range addrs {
		addrStr := addr.String()
		ip, ipNet, err := cnet.ParseCIDR(addrStr)
		if err != nil {
			log.WithError(err).WithField("Address", addrStr).Warning("Failed to parse CIDR")
			continue
		}

		if ip.Version() == version {
			// Switch out the IP address in the network with the
			// interface IP to get the CIDR (IP + network).
			ipNet.IP = ip.IP
			log.WithField("CIDR", ipNet).Debug("Found valid IP address and network")
			iface.Cidrs = append(iface.Cidrs, *ipNet)
		}
	}

	return iface, nil
}
