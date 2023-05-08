// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	gonet "net"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// ReachDestination auto-detects the interface Network by setting up a UDP
// connection to a "reach" destination.
func ReachDestination(dest string, version int) (*net.IPNet, error) {
	log.Debugf("Auto-detecting IPv%d CIDR by reaching destination %s", version, dest)

	// Open a UDP connection to determine which external IP address is
	// used to access the supplied destination.
	protocol := fmt.Sprintf("udp%d", version)
	address := fmt.Sprintf("[%s]:80", dest)
	conn, err := gonet.Dial(protocol, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close() // nolint: errcheck

	// Get the local address as a golang IP and use that to find the matching
	// interface CIDR.
	addr := conn.LocalAddr()
	if addr == nil {
		return nil, fmt.Errorf("no address detected by connecting to %s", dest)
	}
	udpAddr := addr.(*gonet.UDPAddr)
	log.WithFields(log.Fields{"IP": udpAddr.IP, "Destination": dest}).Info("Auto-detected address by connecting to remote")

	// Get a full list of interface and IPs and find the CIDR matching the
	// found IP.
	ifaces, err := GetInterfaces(gonet.Interfaces, nil, nil, version)
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		log.WithField("Name", iface.Name).Debug("Checking interface CIDRs")
		for _, cidr := range iface.Cidrs {
			log.WithField("CIDR", cidr.String()).Debug("Checking CIDR")
			if cidr.IP.Equal(udpAddr.IP) {
				log.WithField("CIDR", cidr.String()).Debug("Found matching interface CIDR")
				return &cidr, nil
			}
		}
	}

	return nil, fmt.Errorf("autodetected IPv%d address does not match any addresses found on local interfaces: %s", version, udpAddr.IP.String())
}
